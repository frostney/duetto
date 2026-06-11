unit WS.Deflate;

// RFC 7692 permessage-deflate over paszlib (FPC's pure-Pascal zlib —
// no external libz, in keeping with lwpt's dependency-light stance).
// Raw deflate streams (negative windowBits), Z_SYNC_FLUSH framing, the
// 0x00 0x00 0xFF 0xFF tail stripped on send and re-appended on receive
// (§7.2.1), context takeover honored per negotiated flags.
//
// The inflater is streaming: the protocol layer feeds it fragment chunks
// as they arrive off the wire, output accumulates in an internal buffer
// with a hard cap — that cap is the compression-bomb guard.

{$I Shared.inc}

interface

uses
  SysUtils,

  zbase;

type
  TWSDeflater = class
  private
    FStrm: z_stream;
    FNoTakeover: Boolean;
    FLive: Boolean;
  public
    constructor Create(AWindowBits: Integer; ANoTakeover: Boolean;
      ALevel: Integer = 6);
    destructor Destroy; override;
    // Compress one whole message. Output has the 4-byte tail already
    // stripped and is never empty (an empty message becomes #$00, §7.2.3.6).
    function CompressMessage(P: PByte; ALen: NativeInt;
      out AOut: TBytes): Boolean;
  end;

  TWSInflater = class
  private
    FStrm: z_stream;
    FNoTakeover: Boolean;
    FLive: Boolean;
    FOut: TBytes;
    FOutSize: NativeInt;
    FMaxOut: NativeInt;
    function Pump(P: PByte; ALen: NativeInt): Boolean;
  public
    constructor Create(AWindowBits: Integer; ANoTakeover: Boolean;
      AMaxOut: NativeInt);
    destructor Destroy; override;
    procedure BeginMessage;
    // Feed one (already unmasked) fragment chunk. False = corrupt stream
    // or output cap exceeded.
    function Feed(P: PByte; ALen: NativeInt): Boolean;
    // Message complete: append the 0x00 0x00 0xFF 0xFF tail and flush.
    function Finish: Boolean;
    property OutData: TBytes read FOut;
    property OutSize: NativeInt read FOutSize;
  end;

implementation

uses
  zdeflate,
  zinflate;

const
  DeflateTail: array[0..3] of Byte = ($00, $00, $FF, $FF);

{ TWSDeflater }

constructor TWSDeflater.Create(AWindowBits: Integer; ANoTakeover: Boolean;
  ALevel: Integer);
begin
  inherited Create;
  FNoTakeover := ANoTakeover;
  FillChar(FStrm, SizeOf(FStrm), 0);
  FLive := deflateInit2(FStrm, ALevel, Z_DEFLATED, -AWindowBits, 8, 0) = Z_OK;
end;

destructor TWSDeflater.Destroy;
begin
  if FLive then deflateEnd(FStrm);
  inherited;
end;

function TWSDeflater.CompressMessage(P: PByte; ALen: NativeInt;
  out AOut: TBytes): Boolean;
var
  Cap, Have: NativeInt;
  R: Integer;
begin
  Result := False;
  if not FLive then Exit;

  // §7.2.3.6: emit the canonical single 0x00 (empty stored block header,
  // BFINAL=0) for an empty payload. paszlib would emit a two-byte empty
  // fixed-Huffman block (02 00) here; both are wire-valid, but 0x00 is
  // shorter and what the ecosystem (uWebSockets, Autobahn) produces.
  // Zero input cannot alter the deflate window, so stream state — and
  // therefore context takeover — is unaffected by skipping zlib.
  if ALen = 0 then
  begin
    SetLength(AOut, 1);
    AOut[0] := $00;
    Result := True;
    Exit;
  end;

  // deflateBound-ish: worst case for incompressible data plus flush tail.
  Cap := ALen + (ALen shr 8) + 64;
  SetLength(AOut, Cap);
  Have := 0;

  FStrm.next_in := P;
  FStrm.avail_in := ALen;
  repeat
    FStrm.next_out := @AOut[Have];
    FStrm.avail_out := Cap - Have;
    R := deflate(FStrm, Z_SYNC_FLUSH);
    if (R <> Z_OK) and (R <> Z_BUF_ERROR) then Exit;
    Have := Cap - FStrm.avail_out;
    if (FStrm.avail_in = 0) and (FStrm.avail_out > 0) then Break;
    if FStrm.avail_out = 0 then
    begin
      Cap := Cap * 2;
      SetLength(AOut, Cap);
    end;
  until False;

  // §7.2.1: a sync flush always terminates with an empty stored block —
  // 0x00 0x00 0xFF 0xFF — which the wire format strips.
  if (Have < 4) or not CompareMem(@AOut[Have - 4], @DeflateTail, 4) then
    Exit;
  Dec(Have, 4);

  if Have = 0 then
  begin
    // §7.2.3.6: an empty deflate block so the receiver's inflate has input.
    SetLength(AOut, 1);
    AOut[0] := $00;
  end
  else
    SetLength(AOut, Have);

  if FNoTakeover then
    if deflateReset(FStrm) <> Z_OK then Exit;

  Result := True;
end;

{ TWSInflater }

constructor TWSInflater.Create(AWindowBits: Integer; ANoTakeover: Boolean;
  AMaxOut: NativeInt);
begin
  inherited Create;
  FNoTakeover := ANoTakeover;
  FMaxOut := AMaxOut;
  FillChar(FStrm, SizeOf(FStrm), 0);
  FLive := inflateInit2(FStrm, -AWindowBits) = Z_OK;
  SetLength(FOut, 4096);
end;

destructor TWSInflater.Destroy;
begin
  if FLive then inflateEnd(FStrm);
  inherited;
end;

procedure TWSInflater.BeginMessage;
begin
  FOutSize := 0;
end;

function TWSInflater.Pump(P: PByte; ALen: NativeInt): Boolean;
var
  R: Integer;
begin
  Result := False;
  FStrm.next_in := P;
  FStrm.avail_in := ALen;
  repeat
    if FOutSize = Length(FOut) then
    begin
      if NativeInt(Length(FOut)) >= FMaxOut then Exit; // bomb guard
      if NativeInt(Length(FOut)) * 2 > FMaxOut then
        SetLength(FOut, FMaxOut)
      else
        SetLength(FOut, Length(FOut) * 2);
    end;
    FStrm.next_out := @FOut[FOutSize];
    FStrm.avail_out := Length(FOut) - FOutSize;
    R := inflate(FStrm, Z_SYNC_FLUSH);
    // Z_STREAM_END means the peer set BFINAL inside a permessage-deflate
    // stream — out of contract, treat as corrupt.
    if (R <> Z_OK) and (R <> Z_BUF_ERROR) then Exit;
    FOutSize := Length(FOut) - FStrm.avail_out;
    if FOutSize > FMaxOut then Exit;
    if FStrm.avail_in = 0 then Break;
    if (R = Z_BUF_ERROR) and (FStrm.avail_out > 0) then Exit; // no progress
  until False;
  Result := True;
end;

function TWSInflater.Feed(P: PByte; ALen: NativeInt): Boolean;
begin
  if not FLive then Exit(False);
  if ALen = 0 then Exit(True);
  Result := Pump(P, ALen);
end;

function TWSInflater.Finish: Boolean;
var
  Tail: array[0..3] of Byte;
begin
  if not FLive then Exit(False);
  Move(DeflateTail, Tail, 4);
  Result := Pump(@Tail[0], 4);
  if Result and FNoTakeover then
    Result := inflateReset(FStrm) = Z_OK;
end;

end.
