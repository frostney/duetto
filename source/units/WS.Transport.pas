unit WS.Transport;

// The completion-shaped transport contract (ADR-0001, ADR-0003). A
// transport owns listening, connection lifecycle, and byte movement for
// one platform; the session layer (WS.Server) owns handshakes, protocol
// wiring, and flush policy. Nothing in a transport may know an RFC 6455
// rule.
//
// Execution context (ADR-0003): every completion fires on the
// transport's execution context — the Run thread for the epoll
// transport, per-connection serial dispatch queues for the
// Network.framework transport. Per-connection completions are always
// serialized; completions for DIFFERENT connections may run
// concurrently. Connection methods (SubmitSend, SubmitClose) are
// callable only from that connection's callback context. The two
// cross-thread entry points are Stop and SubmitPost — the latter is
// the scheduling hook that hands work to a connection's context from
// any thread.
//
// Buffer rules: the pointer handed to OnData is transport-owned and
// valid only for the duration of the callback. SubmitSend accepts up to
// ALen bytes immediately and returns the count taken (-1 = connection
// is dead; caller must SubmitClose); when it returns short, the
// transport fires OnSendReady once it can take more — the caller then
// re-offers its current pending output. OnSendReady may also fire after
// a send that took everything; a re-offer with nothing pending is a
// harmless no-op.
//
// Accept and receive are transport-armed rather than submitted — a
// narrower surface than ADR-0001 sketches, completion-shaped all the
// same; a completion-port transport hosts it by arming its own receives
// internally.
//
// Ownership: transport connection objects are created by the transport
// (surfaced via OnAccept) and freed by the transport. After SubmitClose
// (caller-initiated teardown) the caller must drop every reference and
// receives no further completions; the actual free may be deferred
// internally (the Network.framework transport frees on the cancelled
// state, the last event on the connection's queue). After OnClosed
// returns (remote close / transport error) the same applies. Neither
// the connection object nor the OnData buffer may be touched afterwards.

{$I Shared.inc}

interface

type
  TWSTransportConn = class
  private
    FId: NativeUInt;
  public
    // The session layer's per-connection object; opaque to the transport.
    UserData: Pointer;

    // Accept up to ALen bytes for delivery now; returns bytes taken, or
    // -1 when the connection is dead. Short return arms OnSendReady.
    function SubmitSend(P: PByte; ALen: NativeInt): NativeInt; virtual; abstract;

    // Teardown. The caller must drop every reference before calling and
    // receives no further completions; OnClosed does not fire. The
    // transport frees this object (possibly deferred — see the
    // ownership rules above).
    procedure SubmitClose; virtual; abstract;

    // Transport-neutral monotonic connection identifier.
    property Id: NativeUInt read FId write FId;
  end;

  TWSTransportAcceptEvent = procedure(AConn: TWSTransportConn) of object;
  TWSTransportDataEvent = procedure(AConn: TWSTransportConn; P: PByte;
    ALen: NativeInt) of object;
  TWSTransportReadyEvent = procedure(AConn: TWSTransportConn) of object;
  TWSTransportClosedEvent = procedure(AConn: TWSTransportConn) of object;
  // SubmitPost delivery. AConn <> nil: the target connection, on its
  // execution context. AConn = nil: the post was dropped (connection
  // gone or transport stopping) and fires on whichever context noticed,
  // which is any one of:
  //   - the POSTING thread — SubmitPost itself found the connection
  //     gone, or found the queue already stopped;
  //   - the RUN / completion thread — the drop was noticed while
  //     delivering a queued batch;
  //   - the SHUTDOWN thread — Shutdown reclaimed what was still
  //     pending;
  //   - (Network.framework only) the target CONNECTION'S dispatch
  //     queue — the post was dispatched, then the connection went away
  //     before the block ran.
  // A dropped delivery may therefore only reclaim AData; nothing in the
  // handler may assume a particular thread.
  //
  // OnPost is consequently NOT serialized against itself: an inline
  // drop on a posting thread can run concurrently with a delivery on
  // the Run thread, and an inline drop can overtake an earlier post
  // from the SAME caller that is still queued. Per-caller FIFO is a
  // guarantee of the delivered path only (AConn <> nil, on that
  // connection's execution context); drops carry no ordering at all.
  TWSTransportPostEvent = procedure(AConn: TWSTransportConn;
    AData: Pointer) of object;

  // Server-side TLS configuration. Identity arrives as a PKCS#12 file —
  // the one file-based input Apple's Security framework imports cleanly,
  // and the shape lwpt's TransportSecurity server context takes too.
  //
  // Two families of backend consume this record:
  //
  //   - Network.framework (macOS) terminates TLS inside the platform
  //     stack. It reads Enabled/Pkcs12Path/Pkcs12Passphrase and IGNORES
  //     every field below them: the flow-control watermarks, the
  //     handshake deadline and the inbound budget are properties of the
  //     OpenSSL memory-BIO pipeline that only the fd-owning transports
  //     drive. nw_connection does its own buffering and its own
  //     handshake timeout.
  //   - epoll (Linux) and IOCP (Windows) terminate TLS themselves over
  //     lwpt's TransportSecurity server API (WS.Transport.TlsServer).
  //     Every field here applies.
  //
  // All the tuning fields take 0 to mean "the default" so
  // WSTransportNoTls — and any zero-initialized record — is a valid
  // configuration.
  TWSTransportTls = record
    Enabled: Boolean;
    Pkcs12Path: string;
    Pkcs12Passphrase: string;

    // Encrypted-input high watermark, in bytes: how much ciphertext one
    // connection may hold undigested before the transport stops reading
    // its socket. 0 = lwpt's default (64 KiB). Must sit within lwpt's
    // TLS_SERVER_MIN/MAX_INPUT_CAPACITY (17 KiB … 256 KiB) — the floor
    // is one maximum-size TLS record, so a connection can always make
    // progress. OpenSSL backends only.
    //
    // It is also the PER-ROUND SOCKET READ BOUND on a TLS connection.
    // lwpt accepts at most this much per feed and the transport carries
    // the remainder in a per-connection buffer, so reading a whole
    // transport-sized buffer (256 KiB on epoll, 64 KiB on IOCP) would
    // let a flooding peer pin [read size − watermark] bytes per
    // connection on top of the bound configured here — and pin a
    // different amount on each backend. Clamping the read to the
    // watermark makes this one number the whole per-connection inbound
    // bound, identically on both.
    InputHighWater: Integer;

    // Encrypted-input low watermark, in bytes: intake resumes only once
    // buffered ciphertext has fallen back to this. The hysteresis that
    // keeps a busy connection from toggling EPOLLIN on every record.
    // 0 = half the resolved high watermark. Must be below it.
    // OpenSSL backends only.
    InputLowWater: Integer;

    // Encrypted-output capacity, in bytes: the ceiling on ciphertext
    // produced but not yet handed to the socket. Bounds how much
    // plaintext one SubmitSend can absorb (the rest is re-offered
    // through OnSendReady). 0 = lwpt's default (64 KiB); range is
    // TLS_SERVER_MIN/MAX_OUTPUT_CAPACITY (17 KiB … 256 KiB).
    // Independent of the input capacities. OpenSSL backends only.
    OutputCapacity: Integer;

    // Reactor-owned monotonic budget, in milliseconds, from accept until
    // the TLS handshake completes. A connection that has not finished by
    // then is aborted. 0 = WSTlsDefaultHandshakeDeadlineMs (10 s).
    // The slow-loris guard on the clock axis. OpenSSL backends only.
    //
    // The graceful-close drain REUSES this budget as its own deadline:
    // pushing close_notify out and waiting for the peer's FIN is the
    // same "a peer that went quiet must not pin an fd forever" problem
    // on the same time scale, and a second knob for it would be a
    // configuration surface with no distinct decision behind it.
    HandshakeDeadlineMs: Integer;

    // Total ciphertext, in bytes, one connection may push at the server
    // BEFORE its handshake completes; exceeding it aborts the
    // connection. 0 = the LARGER of WSTlsDefaultInboundHandshakeBudget
    // (64 KiB — an order of magnitude above any real
    // ClientHello/certificate flight) and the resolved InputHighWater,
    // so a listener that widened its encrypted-input buffer never has a
    // handshake rejected at a volume that buffer was sized to hold. Must
    // resolve to at least InputHighWater; a smaller explicit value is a
    // configuration error. The slow-loris guard on the volume axis: it
    // stops a peer from
    // trickling well-formed-looking records forever, which the deadline
    // alone would only catch after the full timeout, and stops a
    // garbage flood from being re-offered indefinitely.
    // OpenSSL backends only.
    InboundHandshakeBudget: Integer;
  end;

  // A parsed listener bind address (see WSParseBindAddress). wbfAny is
  // the empty string — every interface, exactly as before the option
  // existed. The other two carry the literal's bytes in network order:
  // 4 significant for wbfInet4, 16 for wbfInet6.
  TWSBindFamily = (wbfAny, wbfInet4, wbfInet6);
  TWSBindAddress = record
    Family: TWSBindFamily;
    Text: string;                 // the literal as given ('' for wbfAny)
    Bytes: array[0..15] of Byte;
  end;

  TWSTransport = class
  private
    FPort: Word;
    FOnAccept: TWSTransportAcceptEvent;
    FOnData: TWSTransportDataEvent;
    FOnSendReady: TWSTransportReadyEvent;
    FOnClosed: TWSTransportClosedEvent;
    FOnPost: TWSTransportPostEvent;
  protected
    procedure SetPort(AValue: Word);
  public
    // Blocks until Stop; with ATimeoutMs >= 0 returns after at most that
    // long (the epoll transport additionally completes at most one
    // readiness round per call; queue-driven transports do their work on
    // their own queues and simply wait here).
    //
    // "At most" is literal, and server TLS makes it observable: while
    // any connection carries a TLS deadline (a handshake pending, a
    // close_notify draining) the fd-owning transports bound their park
    // so the deadline can be swept. A bounded Run(N) may therefore
    // return EARLY — never later — and a host that treats the call as a
    // fixed-length tick must re-check its own clock rather than count
    // Run returns.
    procedure Run(ATimeoutMs: Integer = -1); virtual; abstract;

    // Thread-safe. Unblocks Run and stops accepting new connections.
    // Connection teardown belongs to Shutdown/destruction.
    procedure Stop; virtual; abstract;

    // Constructors bind and resolve Port but deliver no completions;
    // connections arriving before Open are refused. Wire the four
    // events, then Open — closes the window where an accept could fire
    // with no session attached.
    procedure Open; virtual;

    // Thread-safe scheduling hook: deliver OnPost exactly once per
    // call — with the live connection whose Id is AConnId, on that
    // connection's execution context, serialized with its completions
    // and in per-caller FIFO order (delivered posts only — a dropped
    // one carries no ordering); or with AConn = nil when the connection
    // is already gone or the transport is stopping (see
    // TWSTransportPostEvent for the dropped-delivery contexts). AData is
    // opaque to the transport and is always handed back through OnPost,
    // so the caller can reclaim it — with OnPost unassigned the
    // envelope is silently dropped, so wire OnPost before the first
    // SubmitPost (the session does, before Open). Pure scheduling: no
    // bytes, no protocol.
    procedure SubmitPost(AConnId: NativeUInt; AData: Pointer); virtual; abstract;

    // Quiesce: cancel every connection and block until no completion
    // can ever fire again. Must be called (with Run returned) before
    // the session frees its per-connection state; the transport frees
    // its connection objects during the drain. Pending posts are
    // dropped (delivered once with AConn = nil), never leaked.
    //
    // Network.framework diverges on one point: a post already
    // dispatched onto a still-live connection's queue when Shutdown
    // begins may be DELIVERED (AConn <> nil) rather than dropped —
    // "pending" there means "queued in the transport", and a dispatched
    // post has left that queue. The drain guarantees every such post
    // has run to completion before Shutdown returns, so the exactly-once
    // and no-leak guarantees hold either way.
    procedure Shutdown; virtual; abstract;

    // The bound port (kernel-assigned when the transport was created
    // with port 0); valid as soon as the constructor returns.
    property Port: Word read FPort;

    property OnAccept: TWSTransportAcceptEvent read FOnAccept write FOnAccept;
    property OnData: TWSTransportDataEvent read FOnData write FOnData;
    property OnSendReady: TWSTransportReadyEvent read FOnSendReady write FOnSendReady;
    property OnClosed: TWSTransportClosedEvent read FOnClosed write FOnClosed;
    property OnPost: TWSTransportPostEvent read FOnPost write FOnPost;
  end;

function WSTransportNoTls: TWSTransportTls;

// Accepts '' (all interfaces), an IPv4 dotted-quad ('127.0.0.1') or an
// IPv6 literal without brackets ('::1', '2001:db8::1', '::ffff:1.2.3.4').
// Anything else — a hostname, brackets, a zone id, garbage — raises an
// Exception naming the input. Never resolves names: a listener's bind
// address is a policy decision and DNS must not get a vote in it.
// Pure string work shared by every transport so the three platforms
// agree byte for byte on what is and is not a literal.
function WSParseBindAddress(const AText: string): TWSBindAddress;

implementation

uses
  SysUtils;

function WSTransportNoTls: TWSTransportTls;
begin
  Result.Enabled := False;
  Result.Pkcs12Path := '';
  Result.Pkcs12Passphrase := '';
  Result.InputHighWater := 0;
  Result.InputLowWater := 0;
  Result.OutputCapacity := 0;
  Result.HandshakeDeadlineMs := 0;
  Result.InboundHandshakeBudget := 0;
end;

// --- bind-address literals -------------------------------------------------

// Strict dotted-quad: exactly four decimal fields of 1..3 digits, each
// 0..255. No octal, no hex, no shorthand ('127.1'), no whitespace.
function TryParseInet4(const S: string; P: PByte): Boolean;
var
  I, Field, Value, Digits: Integer;
begin
  Result := False;
  Field := 0;
  Value := 0;
  Digits := 0;
  for I := 1 to Length(S) do
    case S[I] of
      '0'..'9':
        begin
          Value := Value * 10 + (Ord(S[I]) - Ord('0'));
          Inc(Digits);
          if (Digits > 3) or (Value > 255) then Exit;
        end;
      '.':
        begin
          if (Digits = 0) or (Field = 3) then Exit;
          P[Field] := Value;
          Inc(Field);
          Value := 0;
          Digits := 0;
        end;
    else
      Exit;
    end;
  if (Field <> 3) or (Digits = 0) then Exit;
  P[3] := Value;
  Result := True;
end;

// One colon-separated run of IPv6 groups into P (2 bytes per group);
// the last group may be an embedded dotted-quad (two groups' worth).
// AGroups returns how many 16-bit groups were consumed.
function ParseInet6Run(const S: string; P: PByte; out AGroups: Integer): Boolean;
var
  Rest, Item: string;
  Colon, I, Value: Integer;
begin
  Result := False;
  AGroups := 0;
  if S = '' then Exit(True);
  Rest := S;
  repeat
    Colon := Pos(':', Rest);
    if Colon = 0 then
    begin
      Item := Rest;
      Rest := '';
    end
    else
    begin
      Item := Copy(Rest, 1, Colon - 1);
      Rest := Copy(Rest, Colon + 1, MaxInt);
      if Rest = '' then Exit; // trailing single colon
    end;
    if Item = '' then Exit;
    if AGroups > 7 then Exit;
    if (Pos('.', Item) > 0) then
    begin
      // Embedded IPv4 is legal only as the final two groups.
      if (Rest <> '') or (AGroups > 6) then Exit;
      if not TryParseInet4(Item, P + AGroups * 2) then Exit;
      Inc(AGroups, 2);
      Exit(True);
    end;
    if Length(Item) > 4 then Exit;
    Value := 0;
    for I := 1 to Length(Item) do
      case Item[I] of
        '0'..'9': Value := Value * 16 + (Ord(Item[I]) - Ord('0'));
        'a'..'f': Value := Value * 16 + (Ord(Item[I]) - Ord('a') + 10);
        'A'..'F': Value := Value * 16 + (Ord(Item[I]) - Ord('A') + 10);
      else
        Exit;
      end;
    P[AGroups * 2] := Value shr 8;
    P[AGroups * 2 + 1] := Value and $FF;
    Inc(AGroups);
  until Rest = '';
  Result := True;
end;

// RFC 4291 §2.2 text forms: eight hex groups, at most one '::' standing
// in for a run of zero groups, an optional trailing dotted-quad. Brackets
// and zone ids ('%en0') are rejected — a listener address is a plain
// literal, not a URL host component.
function TryParseInet6(const S: string; P: PByte): Boolean;
var
  Gap: Integer;
  Head, Tail: string;
  HeadBytes, TailBytes: array[0..15] of Byte;
  HeadGroups, TailGroups: Integer;
begin
  Result := False;
  if Pos(':', S) = 0 then Exit;
  FillChar(HeadBytes, SizeOf(HeadBytes), 0);
  FillChar(TailBytes, SizeOf(TailBytes), 0);
  Gap := Pos('::', S);
  if Gap = 0 then
  begin
    if not ParseInet6Run(S, @HeadBytes[0], HeadGroups) then Exit;
    if HeadGroups <> 8 then Exit;
    Move(HeadBytes[0], P^, 16);
    Exit(True);
  end;
  Head := Copy(S, 1, Gap - 1);
  Tail := Copy(S, Gap + 2, MaxInt);
  if Pos('::', Tail) > 0 then Exit; // a second '::' is ambiguous
  if not ParseInet6Run(Head, @HeadBytes[0], HeadGroups) then Exit;
  if not ParseInet6Run(Tail, @TailBytes[0], TailGroups) then Exit;
  if HeadGroups + TailGroups > 7 then Exit; // '::' must cover >= 1 group
  FillChar(P^, 16, 0);
  Move(HeadBytes[0], P^, HeadGroups * 2);
  Move(TailBytes[0], (P + 16 - TailGroups * 2)^, TailGroups * 2);
  Result := True;
end;

function WSParseBindAddress(const AText: string): TWSBindAddress;
begin
  Result.Family := wbfAny;
  Result.Text := AText;
  FillChar(Result.Bytes, SizeOf(Result.Bytes), 0);
  if AText = '' then Exit;
  if TryParseInet4(AText, @Result.Bytes[0]) then
    Result.Family := wbfInet4
  else if TryParseInet6(AText, @Result.Bytes[0]) then
    Result.Family := wbfInet6
  else
    raise Exception.CreateFmt(
      'bind address ''%s'' is not an IPv4 or IPv6 literal (hostnames are ' +
      'never resolved)', [AText]);
end;

procedure TWSTransport.Open;
begin
  // Readiness-driven transports accept only inside Run; nothing to arm.
end;

procedure TWSTransport.SetPort(AValue: Word);
begin
  FPort := AValue;
end;

end.
