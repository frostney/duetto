unit WS.Transport.TlsServer;

// Per-connection server TLS over lwpt's TransportSecurity accept API,
// factored out of the fd-owning transports (epoll on Linux, IOCP on
// Windows) so both drive one implementation of the flow-control
// contract and stay pure byte movers. Nothing here touches a socket,
// an epoll set or a completion port; nothing here knows an RFC 6455
// rule either — this unit sits exactly between the two, on the
// ciphertext/plaintext boundary.
//
// The macOS Network.framework transport does NOT use this unit: it
// terminates TLS inside the platform stack (ADR-0002) and never sees a
// memory BIO.
//
// What the transport owns and what this unit owns
// -----------------------------------------------
// The transport owns every syscall. It hands this unit the ciphertext
// it read (Ingest) and the plaintext the session layer wants to send
// (Encrypt), and supplies two callbacks:
//
//   OnPlaintext  — decrypted application bytes, ready for the
//                  transport's normal OnData delivery. Returning False
//                  stops the pump: the delivery tore this connection
//                  down and neither the session object nor the
//                  connection may be touched again.
//   OnCiphertext — hand bytes to the socket. > 0 = accepted (a short
//                  accept is fine and expected), 0 = would block (the
//                  transport arms its writability notification), < 0 =
//                  the socket is dead.
//
// NEITHER CALLBACK MAY RAISE. An exception unwinds out of the middle of
// a pump, leaving the lwpt session half-driven (ciphertext produced but
// not consumed, a write retry outstanding, the carry buffer holding
// bytes nobody will re-offer) with no way for this unit to reconcile
// it. The transports treat a raising handler as fatal to Run, which is
// exactly the convention WS.Transport already publishes for OnData: a
// handler that can fail must catch its own failure and tear the
// connection down deliberately.
//
// This unit owns the exact accounting on both sides: it re-offers what
// lwpt would not accept (the carry buffer below), consumes exactly what
// the socket took (TransportSecurityConsumeCiphertext), and never
// reorders a byte — all ciphertext, handshake records and application
// records alike, leaves through the single lwpt output queue in the
// order lwpt produced it.
//
// Flow control (lwpt#85)
// ----------------------
// Inbound: TransportSecurityFeedCiphertext accepts a PREFIX. The tail
// goes into the carry buffer and is re-offered, ahead of anything new,
// on every later pump. A short accept means the encrypted-input buffer
// hit its high watermark, so Ingest reports wtiPaused and the transport
// stops reading the socket; MayResume reports lwpt's own low-water
// hysteresis (it is deliberately not re-derived here), so intake
// restarts only once the backlog has actually drained.
//
// Outbound: Encrypt is bounded by TransportSecurityServerOutputFlow's
// RemainingBytes, so a large send is absorbed in capacity-sized bites
// and the rest is re-offered through the transport's OnSendReady — the
// same partial-accept contract WS.Transport already publishes, which is
// why the session layer above needs no changes for TLS.
//
// One lwpt subtlety drives the FWriteRetry state:
// TransportSecurityServerWrite copies the WHOLE offer into an internal
// retry buffer before encrypting, and demands that an incomplete write
// be resumed with a nil/zero-length buffer. So a short encrypt still
// means the full offer was accepted (lwpt owns the tail), and a read
// must not be attempted until the retry has drained — lwpt raises if it
// is.
//
// Guards
// ------
// Two reactor-owned bounds turn a slow or hostile peer into a bounded
// cost: a monotonic handshake deadline (the clock axis) and an inbound
// pre-handshake ciphertext budget (the volume axis). The transport
// checks DeadlineExpired from its event loop; the budget is enforced
// inside Ingest.

{$I Shared.inc}

interface

uses
  SysUtils,

  TransportSecurity,
  WS.Transport;

const
  // Wall-clock budget from accept to an activated TLS session.
  WSTlsDefaultHandshakeDeadlineMs = 10000;
  // Ciphertext one connection may push before its handshake completes.
  // A ClientHello plus a full certificate flight is a few KiB; this is
  // an order of magnitude of headroom and still a hard ceiling.
  WSTlsDefaultInboundHandshakeBudget = 64 * 1024;
  // One decrypted TLS record is at most 16384 bytes, so a read larger
  // than this can never come back fuller.
  WSTlsPlaintextBufferSize = 16 * 1024;

type
  EWSTlsServer = class(Exception);

  // Resolved and validated flow-control / guard policy: every 0 in the
  // TWSTransportTls record replaced by its default, every value checked
  // against lwpt's limits. Both fd-owning transports resolve once, at
  // construction, so a bad configuration fails the listener rather than
  // the first connection.
  TWSTlsPolicy = record
    InputHighWater: Integer;
    InputLowWater: Integer;
    OutputCapacity: Integer;
    HandshakeDeadlineMs: Integer;
    InboundHandshakeBudget: Integer;
  end;

  // FIFO for ciphertext lwpt would not accept yet. Bounded in practice
  // by one socket read: a short accept sets Backpressured, the
  // transport drops its read interest, and nothing new arrives until
  // this has drained.
  //
  // The head only moves forward, so Append compacts before it grows —
  // otherwise a long-lived backpressured connection would keep
  // extending the buffer past dead space.
  TWSTlsCarry = record
  private
    FBuf: TBytes;
    FHead: NativeInt;
    FTail: NativeInt;
  public
    procedure Reset;
    procedure Append(P: PByte; ALen: NativeInt);
    procedure Consume(ALen: NativeInt);
    // Oldest unaccepted byte, or nil when empty; valid until the next
    // Append.
    function Head: PByte;
    function Len: NativeInt;
    // Allocated bytes — bookkeeping visibility for the tests, not a
    // contract.
    function Allocated: NativeInt;
  end;

  // Decrypted application bytes. The pointer is session-owned and valid
  // only for the duration of the call. False = the delivery dropped
  // this connection; the pump stops immediately and nothing here may be
  // touched again. MUST NOT RAISE — an exception leaves the session
  // mid-pump with no way to reconcile it (see the unit header).
  TWSTlsPlaintextEvent = function(P: PByte; ALen: NativeInt): Boolean of object;

  // Hand ciphertext to the socket. Returns bytes taken (a short take is
  // normal — the transport arms its writability notification and the
  // remainder rides the next pump), or -1 when the socket is dead.
  // MUST NOT RAISE, for the same reason as TWSTlsPlaintextEvent.
  TWSTlsCiphertextEvent = function(P: PByte; ALen: NativeInt): NativeInt of object;

  TWSTlsIngestResult = (
    wtiOk,        // digested; keep reading the socket
    wtiPaused,    // encrypted input is at its high watermark; stop reading
    wtiFailed     // the connection is dead (protocol error, guard, or peer)
  );

  TWSTlsServerSession = class
  private
    FConn: TTransportSecurityConnection;
    FPolicy: TWSTlsPolicy;
    FCarry: TWSTlsCarry;
    FPlain: TBytes;
    FDeadline: QWord;
    FInboundPreHandshake: Int64;
    FOnPlaintext: TWSTlsPlaintextEvent;
    FOnCiphertext: TWSTlsCiphertextEvent;
    FHandshakeDone: Boolean;
    FWriteRetry: Boolean;
    FCloseNotifyQueued: Boolean;
    FDead: Boolean;
    FPeerClosed: Boolean;
    FDetached: Boolean;
    procedure Fail;
    function FeedChunk(P: PByte; ALen: NativeInt): NativeInt;
    function FlushEgress: Boolean;
    function ResumeWrite: Boolean;
    function DriveHandshake: Boolean;
    function ReadPlaintext: Boolean;
    function Outcome: TWSTlsIngestResult;
  public
    // Begins a TLS session against the transport's shared context. Both
    // callbacks are required. Raises on a context lwpt refuses.
    constructor Create(const AContext: TTransportSecurityServerContext;
      const APolicy: TWSTlsPolicy; AOnPlaintext: TWSTlsPlaintextEvent;
      AOnCiphertext: TWSTlsCiphertextEvent);
    destructor Destroy; override;

    // Feed ciphertext straight off the socket. Drives the handshake
    // while one is pending, then decrypts and delivers plaintext
    // through OnPlaintext. P may be nil with ALen = 0 to pump without
    // new input (a writability event, or a resumed read after the
    // backlog drained).
    function Ingest(P: PByte; ALen: NativeInt): TWSTlsIngestResult;

    // Encrypt plaintext for the wire, bounded by the remaining output
    // capacity. Returns bytes accepted (short = the caller re-offers the
    // tail after OnSendReady, exactly as on a plaintext transport), or
    // -1 when the connection is dead.
    function Encrypt(P: PByte; ALen: NativeInt): NativeInt;

    // Graceful teardown: drain whatever is still queued, then
    // close_notify. True = nothing is left to write and the transport
    // may send FIN; False = call again on the next writability event.
    function DrainClose: Boolean;

    // Abortive teardown: release the lwpt session with no close_notify.
    procedure Abort;

    // True once the handshake deadline has passed with no activation.
    function DeadlineExpired: Boolean;

    // Intake may restart: lwpt's low-water hysteresis has cleared and
    // nothing is waiting to be re-offered.
    function MayResume: Boolean;

    // The engine owes the wire something — queued ciphertext, or a
    // write lwpt could not finish. The transport keeps its writability
    // notification armed exactly while this holds; when it is False
    // with a short Encrypt behind it, the limit was output CAPACITY
    // rather than the socket and the transport arms anyway to
    // manufacture the OnSendReady the caller is owed.
    function NeedsWritable: Boolean;

    // Ciphertext lwpt has produced that the socket has not taken yet.
    // A completion-port transport reads it to tell "a write is already
    // on its way back to me" — its completion will re-drive the pump —
    // from "nothing will ever complete on this connection again", which
    // is the state a short Encrypt with an empty output queue leaves
    // behind and the one that needs a self-posted carrier.
    function PendingCiphertext: NativeInt;

    property HandshakeDone: Boolean read FHandshakeDone;
    property Dead: Boolean read FDead;
    // The peer sent close_notify; the lwpt session is gone.
    property PeerClosed: Boolean read FPeerClosed;
    // A plaintext delivery tore the connection down mid-pump.
    property Detached: Boolean read FDetached;
  end;

// Resolve zeros to defaults and validate against lwpt's limits. Raises
// EWSTlsServer naming the offending TWSTransportTls field.
function WSTlsResolvePolicy(const ATls: TWSTransportTls): TWSTlsPolicy;

// The one context a transport builds for its whole lifetime; every
// accepted connection begins against it.
function WSTlsCreateServerContext(const ATls: TWSTransportTls;
  const APolicy: TWSTlsPolicy): TTransportSecurityServerContext;

implementation

{ TWSTlsCarry }

procedure TWSTlsCarry.Reset;
begin
  FBuf := nil;
  FHead := 0;
  FTail := 0;
end;

procedure TWSTlsCarry.Append(P: PByte; ALen: NativeInt);
begin
  if (ALen <= 0) or (P = nil) then Exit;
  if FHead > 0 then
  begin
    if FTail > FHead then
      Move(FBuf[FHead], FBuf[0], FTail - FHead);
    Dec(FTail, FHead);
    FHead := 0;
  end;
  if FTail + ALen > Length(FBuf) then
    SetLength(FBuf, FTail + ALen);
  Move(P^, FBuf[FTail], ALen);
  Inc(FTail, ALen);
end;

procedure TWSTlsCarry.Consume(ALen: NativeInt);
begin
  if ALen <= 0 then Exit;
  Inc(FHead, ALen);
  if FHead >= FTail then
  begin
    FHead := 0;
    FTail := 0;
  end;
end;

function TWSTlsCarry.Head: PByte;
begin
  if FTail > FHead then
    Result := @FBuf[FHead]
  else
    Result := nil;
end;

function TWSTlsCarry.Len: NativeInt;
begin
  Result := FTail - FHead;
end;

function TWSTlsCarry.Allocated: NativeInt;
begin
  Result := Length(FBuf);
end;

{ policy }

function WSTlsResolvePolicy(const ATls: TWSTransportTls): TWSTlsPolicy;
begin
  Result.InputHighWater := ATls.InputHighWater;
  if Result.InputHighWater = 0 then
    Result.InputHighWater := TLS_SERVER_DEFAULT_INPUT_CAPACITY;
  if (Result.InputHighWater < TLS_SERVER_MIN_INPUT_CAPACITY) or
    (Result.InputHighWater > TLS_SERVER_MAX_INPUT_CAPACITY) then
    raise EWSTlsServer.CreateFmt('TWSTransportTls.InputHighWater must be ' +
      '0 (default %d) or between %d and %d bytes; got %d',
      [TLS_SERVER_DEFAULT_INPUT_CAPACITY, TLS_SERVER_MIN_INPUT_CAPACITY,
      TLS_SERVER_MAX_INPUT_CAPACITY, ATls.InputHighWater]);

  // 0 means "half the high watermark" here, so a literal zero low
  // watermark (which lwpt would accept, and which disables the
  // hysteresis) is deliberately not expressible through this record.
  Result.InputLowWater := ATls.InputLowWater;
  if Result.InputLowWater = 0 then
    Result.InputLowWater := Result.InputHighWater div 2;
  if (Result.InputLowWater < 0) or
    (Result.InputLowWater >= Result.InputHighWater) then
    raise EWSTlsServer.CreateFmt('TWSTransportTls.InputLowWater must be 0 ' +
      '(default: half of InputHighWater) or below InputHighWater (%d); ' +
      'got %d', [Result.InputHighWater, ATls.InputLowWater]);

  Result.OutputCapacity := ATls.OutputCapacity;
  if Result.OutputCapacity = 0 then
    Result.OutputCapacity := TLS_SERVER_DEFAULT_OUTPUT_CAPACITY;
  if (Result.OutputCapacity < TLS_SERVER_MIN_OUTPUT_CAPACITY) or
    (Result.OutputCapacity > TLS_SERVER_MAX_OUTPUT_CAPACITY) then
    raise EWSTlsServer.CreateFmt('TWSTransportTls.OutputCapacity must be ' +
      '0 (default %d) or between %d and %d bytes; got %d',
      [TLS_SERVER_DEFAULT_OUTPUT_CAPACITY, TLS_SERVER_MIN_OUTPUT_CAPACITY,
      TLS_SERVER_MAX_OUTPUT_CAPACITY, ATls.OutputCapacity]);

  Result.HandshakeDeadlineMs := ATls.HandshakeDeadlineMs;
  if Result.HandshakeDeadlineMs = 0 then
    Result.HandshakeDeadlineMs := WSTlsDefaultHandshakeDeadlineMs;
  if Result.HandshakeDeadlineMs < 0 then
    raise EWSTlsServer.CreateFmt('TWSTransportTls.HandshakeDeadlineMs must ' +
      'be 0 (default %d) or positive; got %d',
      [WSTlsDefaultHandshakeDeadlineMs, ATls.HandshakeDeadlineMs]);

  Result.InboundHandshakeBudget := ATls.InboundHandshakeBudget;
  // The default never sits below the input high watermark: a listener
  // that widened its encrypted-input buffer must not have handshakes
  // rejected at a volume that buffer was sized to hold.
  if Result.InboundHandshakeBudget = 0 then
    if Result.InputHighWater > WSTlsDefaultInboundHandshakeBudget then
      Result.InboundHandshakeBudget := Result.InputHighWater
    else
      Result.InboundHandshakeBudget := WSTlsDefaultInboundHandshakeBudget;
  // Same floor, enforced rather than applied, for an explicit value.
  // Both numbers in the message are the RESOLVED ones actually compared:
  // InputHighWater may itself have come from a default, and reporting
  // the raw 0 the caller wrote would name a value nothing was checked
  // against.
  if Result.InboundHandshakeBudget < Result.InputHighWater then
    raise EWSTlsServer.CreateFmt('TWSTransportTls.InboundHandshakeBudget ' +
      'must be 0 (default %d) or at least the resolved InputHighWater ' +
      '(%d); got a resolved %d',
      [WSTlsDefaultInboundHandshakeBudget, Result.InputHighWater,
      Result.InboundHandshakeBudget]);
end;

function WSTlsCreateServerContext(const ATls: TWSTransportTls;
  const APolicy: TWSTlsPolicy): TTransportSecurityServerContext;
begin
  if not ATls.Enabled then
    raise EWSTlsServer.Create(
      'WSTlsCreateServerContext called with TLS disabled');
  if ATls.Pkcs12Path = '' then
    raise EWSTlsServer.Create(
      'TWSTransportTls.Enabled needs a PKCS#12 identity in Pkcs12Path');
  try
    Result := TTransportSecurityServerContext.Create(ATls.Pkcs12Path,
      UnicodeString(ATls.Pkcs12Passphrase), APolicy.InputHighWater,
      APolicy.InputLowWater, APolicy.OutputCapacity);
  except
    // lwpt's message names the OpenSSL/PKCS#12 cause; the prefix names
    // the duetto surface that produced the configuration, so a bad
    // identity does not read as an internal error.
    on E: Exception do
      raise EWSTlsServer.CreateFmt('server TLS identity %s: %s',
        [ATls.Pkcs12Path, E.Message]);
  end;
end;

{ TWSTlsServerSession }

constructor TWSTlsServerSession.Create(
  const AContext: TTransportSecurityServerContext;
  const APolicy: TWSTlsPolicy; AOnPlaintext: TWSTlsPlaintextEvent;
  AOnCiphertext: TWSTlsCiphertextEvent);
begin
  inherited Create;
  if not Assigned(AOnPlaintext) or not Assigned(AOnCiphertext) then
    raise EWSTlsServer.Create(
      'TWSTlsServerSession needs both delivery callbacks');
  FPolicy := APolicy;
  FOnPlaintext := AOnPlaintext;
  FOnCiphertext := AOnCiphertext;
  SetLength(FPlain, WSTlsPlaintextBufferSize);
  FDeadline := GetTickCount64 + QWord(APolicy.HandshakeDeadlineMs);
  BeginTransportSecurityServer(FConn, AContext);
end;

destructor TWSTlsServerSession.Destroy;
begin
  Abort;
  inherited;
end;

procedure TWSTlsServerSession.Fail;
begin
  if FDead then Exit;
  FDead := True;
  // Idempotent against lwpt's own poisoning: an operation that returned
  // tssError already released the backend state, and Abort then finds
  // nothing to free.
  AbortTransportSecurityServer(FConn);
  FCarry.Reset;
end;

procedure TWSTlsServerSession.Abort;
begin
  Fail;
end;

function TWSTlsServerSession.DeadlineExpired: Boolean;
begin
  Result := (not FHandshakeDone) and (not FDead) and
    (GetTickCount64 >= FDeadline);
end;

function TWSTlsServerSession.MayResume: Boolean;
begin
  // lwpt's Backpressured flag IS the hysteresis (it clears only once
  // buffered input has fallen back to the low watermark), so it is read
  // rather than re-derived from BufferedBytes here. A non-empty carry
  // means bytes are still owed to lwpt, which outranks the flag.
  Result := (not FDead) and (FCarry.Len = 0) and
    (not TransportSecurityServerInputFlow(FConn).Backpressured);
end;

function TWSTlsServerSession.NeedsWritable: Boolean;
begin
  Result := (not FDead) and (FWriteRetry or
    (TransportSecurityPendingCiphertext(FConn) > 0));
end;

function TWSTlsServerSession.PendingCiphertext: NativeInt;
begin
  // A failed session has already had its backend state released; asking
  // lwpt about it would be a question about nothing.
  if FDead then Exit(0);
  Result := TransportSecurityPendingCiphertext(FConn);
end;

// Hand the socket everything lwpt has produced, consuming exactly what
// it took. True = still alive (not necessarily drained — callers test
// TransportSecurityPendingCiphertext for that).
function TWSTlsServerSession.FlushEgress: Boolean;
var
  Buf: Pointer;
  Avail: Integer;
  Taken: NativeInt;
begin
  if FDead then Exit(False);
  repeat
    Avail := TransportSecurityGetCiphertext(FConn, Buf);
    if Avail <= 0 then Exit(True);
    Taken := FOnCiphertext(PByte(Buf), Avail);
    if Taken < 0 then
    begin
      Fail;
      Exit(False);
    end;
    if Taken = 0 then Exit(True); // socket full; the transport armed EPOLLOUT
    TransportSecurityConsumeCiphertext(FConn, Taken);
  until False;
end;

// Resume a write lwpt could not finish. Must run to completion before
// any read: lwpt raises on a read with a retry outstanding.
function TWSTlsServerSession.ResumeWrite: Boolean;
var
  R: TTransportSecurityIOResult;
begin
  Result := True;
  while FWriteRetry and (not FDead) do
  begin
    if not FlushEgress then Exit(False);
    if TransportSecurityPendingCiphertext(FConn) > 0 then Exit;
    R := TransportSecurityServerWrite(FConn, nil, 0);
    if R.State = tssError then
    begin
      Fail;
      Exit(False);
    end;
    if R.State = tssDone then
    begin
      FWriteRetry := False;
      Exit;
    end;
    // tssWantRead (a renegotiation read) or a round that neither
    // consumed plaintext nor produced ciphertext: no way forward now.
    if (R.State = tssWantRead) or ((R.BytesProcessed = 0) and
      (TransportSecurityPendingCiphertext(FConn) = 0)) then Exit;
  end;
end;

// True when the handshake advanced (state change or ciphertext
// produced) — the pump uses that to decide whether another round is
// worth taking.
function TWSTlsServerSession.DriveHandshake: Boolean;
var
  St: TTransportSecurityState;
begin
  Result := False;
  while not FDead do
  begin
    if not FlushEgress then Exit;
    // Handshake records still on the socket's back: lwpt refuses to
    // advance until its output queue is empty, and so must we — this is
    // what keeps handshake and application ciphertext in one order.
    if TransportSecurityPendingCiphertext(FConn) > 0 then Exit;
    St := TransportSecurityServerHandshake(FConn);
    case St of
      tssDone:
        begin
          FHandshakeDone := True;
          Exit(True);
        end;
      tssWantWrite:
        Result := True; // records produced; flush them and come back
      tssWantRead:
        Exit;
    else
      Fail;
      Exit;
    end;
  end;
end;

// True when plaintext was delivered.
function TWSTlsServerSession.ReadPlaintext: Boolean;
var
  R: TTransportSecurityIOResult;
begin
  Result := False;
  while (not FDead) and (not FDetached) do
  begin
    if FWriteRetry then
    begin
      if not ResumeWrite then Exit;
      if FWriteRetry then Exit; // still owed; reading would raise
    end;
    if not FlushEgress then Exit;
    if TransportSecurityPendingCiphertext(FConn) > 0 then Exit;
    R := TransportSecurityServerRead(FConn, FPlain, Length(FPlain));
    if R.State = tssError then
    begin
      Fail;
      Exit;
    end;
    if R.BytesProcessed > 0 then
    begin
      Result := True;
      if not FOnPlaintext(@FPlain[0], R.BytesProcessed) then
      begin
        FDetached := True;
        Exit;
      end;
      Continue;
    end;
    if R.State = tssPeerClosed then
    begin
      // close_notify: lwpt has already released the session, so no
      // further TLS work is possible on this connection.
      FPeerClosed := True;
      FDead := True;
      FCarry.Reset;
      Exit;
    end;
    if R.State = tssWantWrite then Continue; // flush at the loop top
    Exit;                                    // tssWantRead: drained
  end;
end;

// Offer one span to lwpt; returns the accepted prefix length, or -1.
function TWSTlsServerSession.FeedChunk(P: PByte; ALen: NativeInt): NativeInt;
var
  N: Integer;
begin
  if FDead or (ALen <= 0) then Exit(0);
  // lwpt takes an Integer length. Only worth clamping where NativeInt is
  // actually wider — on a 32-bit target the two are the same type and
  // the compare is a tautology the compiler warns about.
  {$ifdef CPU64}
  if ALen > High(Integer) then ALen := High(Integer);
  {$endif}
  N := TransportSecurityFeedCiphertext(FConn, P, Integer(ALen));
  if N < 0 then
  begin
    Fail;
    Exit(-1);
  end;
  Result := N;
end;

function TWSTlsServerSession.Outcome: TWSTlsIngestResult;
begin
  if FDead then
    Result := wtiFailed
  else if (FCarry.Len > 0) or
    TransportSecurityServerInputFlow(FConn).Backpressured then
    Result := wtiPaused
  else
    Result := wtiOk;
end;

function TWSTlsServerSession.Ingest(P: PByte;
  ALen: NativeInt): TWSTlsIngestResult;
var
  N: NativeInt;
  Progressed: Boolean;
begin
  if FDead then Exit(wtiFailed);

  if (ALen > 0) and (not FHandshakeDone) then
  begin
    Inc(FInboundPreHandshake, ALen);
    if FInboundPreHandshake > Int64(FPolicy.InboundHandshakeBudget) then
    begin
      // Volume guard: more ciphertext than any handshake needs, with no
      // activation to show for it.
      Fail;
      Exit(wtiFailed);
    end;
  end;

  // Wire order first: whatever lwpt refused last time outranks anything
  // new, and new bytes queue behind it rather than overtaking it.
  if FCarry.Len > 0 then
  begin
    N := FeedChunk(FCarry.Head, FCarry.Len);
    if N < 0 then Exit(wtiFailed);
    FCarry.Consume(N);
    if (FCarry.Len > 0) and (ALen > 0) then
    begin
      FCarry.Append(P, ALen);
      ALen := 0;
    end;
  end;
  if ALen > 0 then
  begin
    N := FeedChunk(P, ALen);
    if N < 0 then Exit(wtiFailed);
    if N < ALen then FCarry.Append(P + N, ALen - N);
  end;

  // Drain: every round re-offers the carry (decryption frees input
  // space), drives the handshake while one is pending, then reads
  // plaintext. Stops as soon as a round changes nothing.
  repeat
    Progressed := False;
    if (FCarry.Len > 0) and (not FDead) then
    begin
      N := FeedChunk(FCarry.Head, FCarry.Len);
      if N < 0 then Break;
      if N > 0 then
      begin
        FCarry.Consume(N);
        Progressed := True;
      end;
    end;
    if FDead or FDetached then Break;
    if FHandshakeDone then
    begin
      if ReadPlaintext then Progressed := True;
    end
    else if DriveHandshake then
      Progressed := True;
  until (not Progressed) or FDead or FDetached;

  Result := Outcome;
end;

function TWSTlsServerSession.Encrypt(P: PByte; ALen: NativeInt): NativeInt;
var
  Flow: TTransportSecurityOutputFlow;
  R: TTransportSecurityIOResult;
  N: Integer;
begin
  if FDead then Exit(-1);
  if (ALen <= 0) or (P = nil) then Exit(0);
  if not FHandshakeDone then Exit(0); // nothing rides before activation

  if FWriteRetry then
  begin
    if not ResumeWrite then Exit(-1);
    if FWriteRetry then Exit(0);
  end;
  if not FlushEgress then Exit(-1);
  if TransportSecurityPendingCiphertext(FConn) > 0 then Exit(0);

  Flow := TransportSecurityServerOutputFlow(FConn);
  if Flow.RemainingBytes <= 0 then Exit(0);
  if ALen > Flow.RemainingBytes then
    N := Flow.RemainingBytes
  else
    N := Integer(ALen);

  R := TransportSecurityServerWrite(FConn, P, N);
  if R.State = tssError then
  begin
    Fail;
    Exit(-1);
  end;
  // lwpt copied all N bytes before encrypting and owns whatever it could
  // not consume, so the whole offer is accepted even on a short encrypt;
  // re-offering the tail here would duplicate it on the wire.
  FWriteRetry := R.BytesProcessed < N;
  if not FlushEgress then Exit(-1);
  Result := N;
end;

function TWSTlsServerSession.DrainClose: Boolean;
var
  St: TTransportSecurityState;
begin
  if FDead then Exit(True);
  if not FHandshakeDone then
  begin
    // No session to shut down gracefully; lwpt would poison it anyway.
    Fail;
    Exit(True);
  end;
  if FWriteRetry then
  begin
    if not ResumeWrite then Exit(True);
    if FWriteRetry then Exit(False);
  end;
  if not FlushEgress then Exit(True);
  if TransportSecurityPendingCiphertext(FConn) > 0 then Exit(False);
  if not FCloseNotifyQueued then
  begin
    St := CloseTransportSecurityServerGracefully(FConn);
    if St = tssError then
    begin
      Fail;
      Exit(True);
    end;
    // Queued or already on the wire. We do not wait for the peer's
    // close_notify (tssWantRead): the contract here is that OUR alert
    // reaches the socket before FIN, which is what turns an abrupt
    // reset into an orderly shutdown for the peer.
    FCloseNotifyQueued := True;
  end;
  if not FlushEgress then Exit(True);
  Result := TransportSecurityPendingCiphertext(FConn) = 0;
end;

end.
