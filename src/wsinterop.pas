program wsinterop;

// Live-socket battery: lwws TWSClient against lwws TWSServer over real
// TCP (loopback), plus a raw-socket section that injects protocol
// violations a conforming client cannot produce and asserts the close
// codes RFC 6455 (and Autobahn cases 4.x/7.x) require.
//
// Exit 0 = every check passed.

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  SysUtils, Classes, BaseUnix, Sockets,
  WS.Server, WS.Client, WS.Frame, WS.Handshake;

type
  TEcho = class
    procedure OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
  end;

  TServerThread = class(TThread)
  public
    Srv: TWSServer;
    procedure Execute; override;
  end;

procedure TEcho.OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
begin
  if AText then AConn.SendText(P, Len) else AConn.SendBinary(P, Len);
end;

procedure TServerThread.Execute;
begin
  while not Terminated do
    Srv.Run(50);
end;

var
  Failures: Integer = 0;

procedure Check(ACond: Boolean; const AName: string);
begin
  if ACond then
    WriteLn('ok   - ', AName)
  else
  begin
    WriteLn('FAIL - ', AName);
    Inc(Failures);
  end;
end;

// ---------------------------------------------------------------------------
// Raw socket helpers for the violation section
// ---------------------------------------------------------------------------

function RawConnect(APort: Word): Tsocket;
var
  SA: TInetSockAddr;
  TV: TTimeVal;
begin
  Result := fpSocket(AF_INET, SOCK_STREAM, 0);
  TV.tv_sec := 5; TV.tv_usec := 0;
  fpSetSockOpt(Result, SOL_SOCKET, SO_RCVTIMEO, @TV, SizeOf(TV));
  FillChar(SA, SizeOf(SA), 0);
  SA.sin_family := AF_INET;
  SA.sin_port := htons(APort);
  SA.sin_addr.s_addr := htonl($7F000001); // 127.0.0.1
  if fpConnect(Result, @SA, SizeOf(SA)) <> 0 then
    raise Exception.Create('raw connect failed');
end;

// Speak the opening handshake on a raw socket; returns leftover bytes
// (frames pipelined behind the 101), if any.
function RawHandshake(AFd: Tsocket): TBytes;
var
  Req, Raw: RawByteString;
  Buf: array[0..4095] of Byte;
  Got, HdrEnd: Integer;
begin
  Result := nil;
  Req := ClientBuildRequest('127.0.0.1', '/', ClientGenerateKey, False);
  fpSend(AFd, @Req[1], Length(Req), 0);
  Raw := '';
  repeat
    Got := fpRecv(AFd, @Buf[0], SizeOf(Buf), 0);
    if Got <= 0 then raise Exception.Create('raw handshake: connection lost');
    SetLength(Raw, Length(Raw) + Got);
    Move(Buf[0], Raw[Length(Raw) - Got + 1], Got);
    HdrEnd := HandshakeFindEnd(Raw);
  until HdrEnd > 0;
  if Pos('101', Copy(Raw, 1, 16)) = 0 then
    raise Exception.Create('raw handshake: no 101');
  SetLength(Result, Length(Raw) - HdrEnd);
  if Length(Result) > 0 then
    Move(Raw[HdrEnd + 1], Result[0], Length(Result));
end;

// Read frames until a close frame arrives; return its status code
// (0 if the peer hung up without one).
function RawReadCloseCode(AFd: Tsocket; const ALeftover: TBytes): Word;
var
  Buf: TBytes;
  Len, Got, Used: NativeInt;
  H: TWSFrameHeader;
  R: TWSParseResult;
begin
  Result := 0;
  Buf := Copy(ALeftover);
  Len := Length(Buf);
  repeat
    R := ParseFrameHeader(PByte(Buf), Len, H);
    if R = wprOK then
    begin
      Used := H.HeaderLen;
      if Len - Used < H.PayloadLen then
        R := wprNeedMore // payload still in flight
      else if H.Opcode = WS_OP_CLOSE then
      begin
        if H.PayloadLen >= 2 then
          Exit((Buf[Used] shl 8) or Buf[Used + 1])
        else
          Exit(0);
      end
      else
      begin // skip non-close frame (e.g. an echo) and continue
        Delete(Buf, 0, Used + H.PayloadLen);
        Dec(Len, Used + H.PayloadLen);
        Continue;
      end;
    end;
    if R = wprProtocolError then Exit(0);
    SetLength(Buf, Len + 4096);
    Got := fpRecv(AFd, @Buf[Len], 4096, 0);
    if Got <= 0 then Exit(0); // EOF/timeout without close frame
    Len := Len + Got;
    SetLength(Buf, Len);
  until False;
end;

procedure RawSendFrame(AFd: Tsocket; AOpcode: Byte; const APayload: RawByteString;
  AMasked: Boolean);
var
  Hdr: array[0..WS_MAX_HEADER - 1] of Byte;
  HLen: Integer;
  Key: UInt32;
  Body: TBytes;
begin
  Key := $A1B2C3D4;
  HLen := WriteFrameHeader(@Hdr[0], True, False, AOpcode, AMasked, Key,
    Length(APayload));
  fpSend(AFd, @Hdr[0], HLen, 0);
  if APayload = '' then Exit;
  SetLength(Body, Length(APayload));
  Move(APayload[1], Body[0], Length(APayload));
  if AMasked then
    ApplyMask(PByte(Body), Length(Body), Key, 0);
  fpSend(AFd, @Body[0], Length(Body), 0);
end;

// ---------------------------------------------------------------------------

const
  PipelinedMsgs: array[0..2] of RawByteString = ('one', 'two', 'three');

var
  Echo: TEcho;
  SrvT: TServerThread;
  Port: Word;
  Url: string;
  Cli: TWSClient;
  IsText: Boolean;
  Data: TBytes;
  Big: TBytes;
  S: RawByteString;
  I: Integer;
  Ok: Boolean;
  Fd: Tsocket;
  Left: TBytes;
  Code: Word;
begin
  Echo := TEcho.Create;
  SrvT := TServerThread.Create(True);
  SrvT.Srv := TWSServer.Create(0, True); // port 0 = kernel-assigned
  SrvT.Srv.OnMessage := Echo.OnMsg;
  Port := SrvT.Srv.Port;
  Url := Format('ws://127.0.0.1:%d/', [Port]);
  SrvT.Start;
  WriteLn('server on ', Port);

  // --- lwws client vs lwws server ---------------------------------------
  Cli := TWSClient.Create;
  Cli.Connect(Url);
  Cli.SendText('hello lwws');
  Check(Cli.ReadMessage(IsText, Data) and IsText and
    (Length(Data) = 10) and CompareMem(@Data[0], PAnsiChar('hello lwws'), 10),
    'text echo round-trip');

  SetLength(Big, 1024 * 1024);
  for I := 0 to High(Big) do
    Big[I] := Byte((I * 31 + 7) and $FF);
  Cli.SendBinary(@Big[0], Length(Big));
  Check(Cli.ReadMessage(IsText, Data) and (not IsText) and
    (Length(Data) = Length(Big)) and CompareMem(@Data[0], @Big[0], Length(Big)),
    'binary echo 1 MiB');

  Cli.SendText('one');
  Cli.SendText('two');
  Cli.SendText('three');
  Ok := True;
  for I := 0 to 2 do
  begin
    S := PipelinedMsgs[I];
    Ok := Ok and Cli.ReadMessage(IsText, Data) and IsText and
      (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S));
  end;
  Check(Ok, 'three pipelined messages, in order');

  Cli.Ping('beat');
  Cli.SendText('after ping');
  Check(Cli.ReadMessage(IsText, Data) and (Length(Data) = 10),
    'ping auto-ponged, data stream undisturbed');

  Cli.Close(1000, 'done');
  Check(Cli.CloseCode = 1000, 'clean close echoes 1000');
  Cli.Free;

  // --- permessage-deflate over the wire ----------------------------------
  Cli := TWSClient.Create;
  Cli.Connect(Url, True);
  Check(Cli.Deflate.Enabled, 'deflate negotiated when offered');
  S := '';
  for I := 1 to 8192 do
    S := S + 'compressible payload line ' + IntToStr(I and 7) + #10;
  Cli.SendText(S);
  Check(Cli.ReadMessage(IsText, Data) and IsText and
    (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S)),
    'deflate echo ~200 KiB content-identical');
  Cli.Close;
  Cli.Free;

  // --- raw-socket violations ---------------------------------------------
  // A client frame without a mask: MUST fail the connection, 1002 (§5.1).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_TEXT, 'naughty', False);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'unmasked client frame -> close 1002');

  // Close frame carrying reserved code 999: protocol error, 1002 (§7.4).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_CLOSE, Chr(999 shr 8) + Chr(999 and $FF), True);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'close with invalid code 999 -> close 1002');

  // Fragmented control frame (FIN=0 ping): 1002 (§5.5).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  S := #$09#$80; // FIN=0, opcode=9, masked, len 0
  S := S + #0#0#0#0; // mask key
  fpSend(Fd, @S[1], Length(S), 0);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1002, 'fragmented ping -> close 1002');

  // Text frame with invalid UTF-8: 1007 (§8.1).
  Fd := RawConnect(Port);
  Left := RawHandshake(Fd);
  RawSendFrame(Fd, WS_OP_TEXT, #$FF#$FE'broken', True);
  Code := RawReadCloseCode(Fd, Left);
  CloseSocket(Fd);
  Check(Code = 1007, 'invalid UTF-8 text -> close 1007');

  SrvT.Terminate;
  SrvT.Srv.Stop;
  SrvT.WaitFor;
  SrvT.Srv.Free;
  SrvT.Free;
  Echo.Free;

  WriteLn;
  if Failures = 0 then
    WriteLn('interop: ALL CHECKS PASSED')
  else
    WriteLn('interop: ', Failures, ' FAILURE(S)');
  Halt(Ord(Failures > 0));
end.
