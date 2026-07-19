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
// callable only from that connection's callback context.
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

  // Server-side TLS for transports whose platform stack carries it
  // natively (Network.framework). Identity arrives as a PKCS#12 file —
  // the one file-based input Apple's Security framework imports cleanly.
  TWSTransportTls = record
    Enabled: Boolean;
    Pkcs12Path: string;
    Pkcs12Passphrase: string;
  end;

  TWSTransport = class
  private
    FPort: Word;
    FOnAccept: TWSTransportAcceptEvent;
    FOnData: TWSTransportDataEvent;
    FOnSendReady: TWSTransportReadyEvent;
    FOnClosed: TWSTransportClosedEvent;
  protected
    procedure SetPort(AValue: Word);
  public
    // Blocks until Stop; with ATimeoutMs >= 0 returns after at most that
    // long (the epoll transport additionally completes at most one
    // readiness round per call; queue-driven transports do their work on
    // their own queues and simply wait here).
    procedure Run(ATimeoutMs: Integer = -1); virtual; abstract;

    // Thread-safe. Unblocks Run and stops accepting new connections.
    // Connection teardown belongs to Shutdown/destruction.
    procedure Stop; virtual; abstract;

    // Constructors bind and resolve Port but deliver no completions;
    // connections arriving before Open are refused. Wire the four
    // events, then Open — closes the window where an accept could fire
    // with no session attached.
    procedure Open; virtual;

    // Quiesce: cancel every connection and block until no completion
    // can ever fire again. Must be called (with Run returned) before
    // the session frees its per-connection state; the transport frees
    // its connection objects during the drain.
    procedure Shutdown; virtual; abstract;

    // The bound port (kernel-assigned when the transport was created
    // with port 0); valid as soon as the constructor returns.
    property Port: Word read FPort;

    property OnAccept: TWSTransportAcceptEvent read FOnAccept write FOnAccept;
    property OnData: TWSTransportDataEvent read FOnData write FOnData;
    property OnSendReady: TWSTransportReadyEvent read FOnSendReady write FOnSendReady;
    property OnClosed: TWSTransportClosedEvent read FOnClosed write FOnClosed;
  end;

function WSTransportNoTls: TWSTransportTls;

implementation

function WSTransportNoTls: TWSTransportTls;
begin
  Result.Enabled := False;
  Result.Pkcs12Path := '';
  Result.Pkcs12Passphrase := '';
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
