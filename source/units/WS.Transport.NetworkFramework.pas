unit WS.Transport.NetworkFramework;

// macOS transport: Network.framework via its C API (ADR-0002),
// implementing the WS.Transport completion contract natively —
// nw_listener/nw_connection are completion-shaped, so submits map
// straight onto sends/receives with completion blocks.
//
// Concurrency (ADR-0003): one serial dispatch queue per connection;
// listener events on their own serial queue. Per-connection completions
// are serialized by the queue; different connections run concurrently.
//
// FPC 3.2.2 has no C-blocks support, so this unit hand-rolls the stable
// blocks ABI (clang BlockImplementation.txt): a block literal is
// {isa, flags, reserved, invoke, descriptor, captures...}; the runtime
// may Block_copy it (byte copy — we set no copy/dispose helpers and
// capture only plain pointers whose lifetime we control).
//
// Lifecycle: nw callbacks can still be queued when the session lets go
// of a connection, so SubmitClose defers the actual free to the
// nw_connection cancelled state — the final event on the connection's
// queue, after which no callback can fire. Server TLS arrives natively:
// sec_protocol_options + a SecIdentity imported from PKCS#12.

{$I Shared.inc}

interface

{$ifdef DARWIN}

uses
  syncobjs,
  SysUtils,

  WS.Transport;

type
  // Hand-rolled C-blocks ABI (see the unit comment). Interface-visible
  // only so connection/transport objects can embed block storage.
  PWSBlockDescriptor = ^TWSBlockDescriptor;
  TWSBlockDescriptor = record
    Reserved: NativeUInt;
    Size: NativeUInt;
  end;

  PWSBlock = ^TWSBlock;
  TWSBlock = record
    Isa: Pointer;
    Flags: Int32;
    Reserved: Int32;
    Invoke: CodePointer;
    Descriptor: PWSBlockDescriptor;
    Ctx: Pointer;              // single plain-pointer capture
  end;

  TWSNetworkFrameworkTransport = class;

  TWSNwConn = class(TWSTransportConn)
  private
    FTransport: TWSNetworkFrameworkTransport;
    FNw: Pointer;              // nw_connection_t (+1)
    FQueue: Pointer;           // serial dispatch queue (+1)
    FStateBlock: TWSBlock;
    FRecvBlock: TWSBlock;
    FSendBlock: TWSBlock;
    FInFlight: Boolean;        // one outstanding send caps memory
    FDead: Boolean;            // SubmitClose called; drop everything
    FClosedNotified: Boolean;  // OnClosed fired (or suppressed)
    procedure ArmReceive;
    procedure RemoteClosed;
  public
    function SubmitSend(P: PByte; ALen: NativeInt): NativeInt; override;
    procedure SubmitClose; override;
  end;

  TWSNetworkFrameworkTransport = class(TWSTransport)
  private
    FListener: Pointer;        // nw_listener_t
    FParams: Pointer;          // nw_parameters_t
    FListenerQueue: Pointer;
    FStopSem: Pointer;
    FReadySem: Pointer;
    FDrainSem: Pointer;
    FListenerDoneSem: Pointer;
    FTlsIdentity: Pointer;     // sec_identity_t
    FTempKeychain: Pointer;    // private import keychain (see LoadIdentity)
    FListenerState: Integer;
    FActive: LongInt;          // live nw connections (finalize pending)
    FNextId: NativeUInt;       // listener-queue confined
    FStopping: Boolean;
    FOpen: Boolean;            // accepts refused until the session wires up
    FShutdownDone: Boolean;
    FLive: array of TWSNwConn; // for Shutdown's cancel sweep
    FLiveCount: Integer;
    FLiveLock: TCriticalSection;
    FListenerStateBlock: TWSBlock;
    FNewConnBlock: TWSBlock;
    FTlsBlock: TWSBlock;
    FTcpBlock: TWSBlock;
    procedure LoadIdentity(const APath, APassphrase: string);
    procedure LiveTrack(AConn: TWSNwConn);
    procedure LiveUntrack(AConn: TWSNwConn);
    procedure ConnFinalized(AConn: TWSNwConn);
  public
    constructor Create(APort: Word; const ATls: TWSTransportTls);
    destructor Destroy; override;
    procedure Run(ATimeoutMs: Integer = -1); override;
    procedure Stop; override;
    procedure Open; override;
    procedure Shutdown; override;
  end;

{$endif}

implementation

{$ifdef DARWIN}

uses
  Classes;

{$linkframework Network}
{$linkframework Security}
{$linkframework CoreFoundation}

// ---------------------------------------------------------------------------
// C bindings: libdispatch, Network.framework, Security, CoreFoundation
// ---------------------------------------------------------------------------

type
  PNatUInt = ^NativeUInt;

const
  DISPATCH_TIME_FOREVER = UInt64($FFFFFFFFFFFFFFFF);
  NsPerMs = Int64(1000000);
  NsPerSecond = Int64(1000000000);
  ListenerReadyTimeoutSeconds = 10;
  DrainPollMs = 100;
  LiveTableGrowth = 64;
  CF_STRING_ENCODING_UTF8 = $08000100;

  NW_LISTENER_STATE_READY = 2;
  NW_LISTENER_STATE_FAILED = 3;
  NW_LISTENER_STATE_CANCELLED = 4;

  NW_CONNECTION_STATE_READY = 3;
  NW_CONNECTION_STATE_FAILED = 4;
  NW_CONNECTION_STATE_CANCELLED = 5;

function Dispatch_queue_create(ALabel: PAnsiChar; AAttr: Pointer): Pointer; cdecl; external name 'dispatch_queue_create';
procedure Dispatch_release(AObj: Pointer); cdecl; external name 'dispatch_release';
function Dispatch_semaphore_create(AValue: NativeInt): Pointer; cdecl; external name 'dispatch_semaphore_create';
function Dispatch_semaphore_wait(ASem: Pointer; ATimeout: UInt64): NativeInt; cdecl; external name 'dispatch_semaphore_wait';
function Dispatch_semaphore_signal(ASem: Pointer): NativeInt; cdecl; external name 'dispatch_semaphore_signal';
function Dispatch_time(AWhen: UInt64; ADeltaNs: Int64): UInt64; cdecl; external name 'dispatch_time';
function Dispatch_data_create(ABuffer: Pointer; ASize: NativeUInt;
  AQueue: Pointer; ADestructor: Pointer): Pointer; cdecl; external name 'dispatch_data_create';
function Dispatch_data_create_map(AData: Pointer; ABuffer: PPointer;
  ASize: PNatUInt): Pointer; cdecl; external name 'dispatch_data_create_map';
function Dispatch_data_get_size(AData: Pointer): NativeUInt; cdecl; external name 'dispatch_data_get_size';

procedure Nw_retain(AObj: Pointer); cdecl; external name 'nw_retain';
procedure Nw_release(AObj: Pointer); cdecl; external name 'nw_release';

function Nw_parameters_create_secure_tcp(ATls, ATcp: Pointer): Pointer; cdecl; external name 'nw_parameters_create_secure_tcp';
procedure Nw_parameters_set_reuse_local_address(AParams: Pointer;
  AReuse: ByteBool); cdecl; external name 'nw_parameters_set_reuse_local_address';
function Nw_tls_copy_sec_protocol_options(AOptions: Pointer): Pointer; cdecl; external name 'nw_tls_copy_sec_protocol_options';
procedure Sec_protocol_options_set_local_identity(AOptions: Pointer;
  AIdentity: Pointer); cdecl; external name 'sec_protocol_options_set_local_identity';
procedure Nw_tcp_options_set_no_delay(AOptions: Pointer;
  ANoDelay: ByteBool); cdecl; external name 'nw_tcp_options_set_no_delay';

function Nw_listener_create_with_port(APort: PAnsiChar;
  AParams: Pointer): Pointer; cdecl; external name 'nw_listener_create_with_port';
procedure Nw_listener_set_queue(AListener, AQueue: Pointer); cdecl; external name 'nw_listener_set_queue';
procedure Nw_listener_set_state_changed_handler(AListener,
  ABlock: Pointer); cdecl; external name 'nw_listener_set_state_changed_handler';
procedure Nw_listener_set_new_connection_handler(AListener,
  ABlock: Pointer); cdecl; external name 'nw_listener_set_new_connection_handler';
procedure Nw_listener_start(AListener: Pointer); cdecl; external name 'nw_listener_start';
procedure Nw_listener_cancel(AListener: Pointer); cdecl; external name 'nw_listener_cancel';
function Nw_listener_get_port(AListener: Pointer): Word; cdecl; external name 'nw_listener_get_port';

procedure Nw_connection_set_queue(AConn, AQueue: Pointer); cdecl; external name 'nw_connection_set_queue';
procedure Nw_connection_set_state_changed_handler(AConn,
  ABlock: Pointer); cdecl; external name 'nw_connection_set_state_changed_handler';
procedure Nw_connection_start(AConn: Pointer); cdecl; external name 'nw_connection_start';
procedure Nw_connection_cancel(AConn: Pointer); cdecl; external name 'nw_connection_cancel';
procedure Nw_connection_receive(AConn: Pointer; AMin, AMax: UInt32;
  ABlock: Pointer); cdecl; external name 'nw_connection_receive';
procedure Nw_connection_send(AConn, AData, AContext: Pointer;
  AComplete: ByteBool; ABlock: Pointer); cdecl; external name 'nw_connection_send';

// Data symbols (extern variables) resolved at runtime via dlsym — FPC
// 3.2.2's Delphi mode has no external-variable syntax. dlsym takes the
// C-level name (dyld strips the assembler underscore itself).
function Dlsym(AHandle: Pointer; AName: PAnsiChar): Pointer; cdecl; external name 'dlsym';

const
  RTLD_DEFAULT = Pointer(-2);

var
  CtxDefaultMessage: Pointer;    // nw content context: default message
  CtxDefaultStream: Pointer;     // nw content context: default stream
  CfgDisableProtocol: Pointer;   // configure block: disable protocol
  BlockIsaStack: Pointer;        // &_NSConcreteStackBlock
  KeyImportPassphrase: Pointer;  // kSecImportExportPassphrase
  KeyImportItemIdentity: Pointer; // kSecImportItemIdentity
  KeyImportKeychain: Pointer;    // kSecImportExportKeychain
  DictKeyCallbacks: Pointer;     // &kCFTypeDictionaryKeyCallBacks
  DictValueCallbacks: Pointer;   // &kCFTypeDictionaryValueCallBacks

function CFDataCreate(AAlloc, ABytes: Pointer;
  ALen: NativeInt): Pointer; cdecl; external name 'CFDataCreate';
function CFStringCreateWithCString(AAlloc: Pointer; AStr: PAnsiChar;
  AEncoding: UInt32): Pointer; cdecl; external name 'CFStringCreateWithCString';
function CFDictionaryCreate(AAlloc: Pointer; AKeys, AValues: PPointer;
  ANum: NativeInt; AKeyCB, AValueCB: Pointer): Pointer; cdecl; external name 'CFDictionaryCreate';
function CFArrayGetCount(AArray: Pointer): NativeInt; cdecl; external name 'CFArrayGetCount';
function CFArrayGetValueAtIndex(AArray: Pointer;
  AIndex: NativeInt): Pointer; cdecl; external name 'CFArrayGetValueAtIndex';
function CFDictionaryGetValue(ADict, AKey: Pointer): Pointer; cdecl; external name 'CFDictionaryGetValue';
function CFRetain(AObj: Pointer): Pointer; cdecl; external name 'CFRetain';
procedure CFRelease(AObj: Pointer); cdecl; external name 'CFRelease';
function SecPKCS12Import(AData, AOptions: Pointer;
  AItems: PPointer): Int32; cdecl; external name 'SecPKCS12Import';
function Sec_identity_create(AIdentity: Pointer): Pointer; cdecl; external name 'sec_identity_create';
function SecKeychainCreate(APath: PAnsiChar; APassLen: UInt32;
  APass: Pointer; APromptUser: ByteBool; AInitialAccess: Pointer;
  out AKeychain: Pointer): Int32; cdecl; external name 'SecKeychainCreate';
function SecKeychainDelete(AKeychain: Pointer): Int32; cdecl; external name 'SecKeychainDelete';

procedure ResolveDataSymbols;
begin
  CtxDefaultMessage :=
    PPointer(Dlsym(RTLD_DEFAULT, '_nw_content_context_default_message'))^;
  CtxDefaultStream :=
    PPointer(Dlsym(RTLD_DEFAULT, '_nw_content_context_default_stream'))^;
  CfgDisableProtocol := PPointer(Dlsym(RTLD_DEFAULT,
    '_nw_parameters_configure_protocol_disable'))^;
  BlockIsaStack := Dlsym(RTLD_DEFAULT, '_NSConcreteStackBlock');
  KeyImportPassphrase :=
    PPointer(Dlsym(RTLD_DEFAULT, 'kSecImportExportPassphrase'))^;
  KeyImportItemIdentity :=
    PPointer(Dlsym(RTLD_DEFAULT, 'kSecImportItemIdentity'))^;
  KeyImportKeychain :=
    PPointer(Dlsym(RTLD_DEFAULT, 'kSecImportExportKeychain'))^;
  DictKeyCallbacks := Dlsym(RTLD_DEFAULT, 'kCFTypeDictionaryKeyCallBacks');
  DictValueCallbacks := Dlsym(RTLD_DEFAULT, 'kCFTypeDictionaryValueCallBacks');
end;

// FPC RTL adoption for GCD threads. Dispatch callbacks arrive on
// threads FPC did not create: threadvars are allocated lazily (zeroed)
// by cthreads, but the std Text files and the ansistring
// codepage-conversion state are never initialized, so WriteLn and
// string conversions in Pascal callbacks would fail. Every trampoline
// adopts its thread on first entry. (ErrOutput binds to stdout on
// adopted threads — the ''-assign idiom has no stderr variant.)
threadvar
  GcdThreadInited: Boolean;

procedure EnsureThreadInit;
begin
  if GcdThreadInited then Exit;
  GcdThreadInited := True;
  Assign(Output, ''); Rewrite(Output);
  Assign(ErrOutput, ''); Rewrite(ErrOutput);
  Assign(Input, ''); Reset(Input);
end;

// ---------------------------------------------------------------------------
// Blocks ABI
// ---------------------------------------------------------------------------

const
  BlockDescriptor: TWSBlockDescriptor =
    (Reserved: 0; Size: SizeOf(TWSBlock));

// Lays a block literal out in caller-owned storage and returns it as
// the block pointer (the runtime copies it when it retains handlers).
function MakeBlock(var ABlock: TWSBlock; AInvoke: CodePointer;
  ACtx: Pointer): Pointer;
var
  B: PWSBlock;
begin
  B := @ABlock;
  B^.Isa := BlockIsaStack;
  B^.Flags := 0;
  B^.Reserved := 0;
  B^.Invoke := AInvoke;
  B^.Descriptor := @BlockDescriptor;
  B^.Ctx := ACtx;
  Result := B;
end;

// ---------------------------------------------------------------------------
// Block invoke trampolines (cdecl; first argument is the block itself)
// ---------------------------------------------------------------------------

procedure TlsConfigInvoke(ABlock: PWSBlock; AOptions: Pointer); cdecl;
var
  T: TWSNetworkFrameworkTransport;
  SecOpts: Pointer;
begin
  EnsureThreadInit;
  T := TWSNetworkFrameworkTransport(ABlock^.Ctx);
  SecOpts := Nw_tls_copy_sec_protocol_options(AOptions);
  Sec_protocol_options_set_local_identity(SecOpts, T.FTlsIdentity);
  Nw_release(SecOpts);
end;

procedure TcpConfigInvoke(ABlock: PWSBlock; AOptions: Pointer); cdecl;
begin
  Nw_tcp_options_set_no_delay(AOptions, True);
end;

procedure ListenerStateInvoke(ABlock: PWSBlock; AState: Int32;
  AError: Pointer); cdecl;
var
  T: TWSNetworkFrameworkTransport;
begin
  EnsureThreadInit;
  T := TWSNetworkFrameworkTransport(ABlock^.Ctx);
  T.FListenerState := AState;
  case AState of
    NW_LISTENER_STATE_READY:
      begin
        T.SetPort(Nw_listener_get_port(T.FListener));
        Dispatch_semaphore_signal(T.FReadySem);
      end;
    NW_LISTENER_STATE_FAILED:
      Dispatch_semaphore_signal(T.FReadySem);
    NW_LISTENER_STATE_CANCELLED:
      Dispatch_semaphore_signal(T.FListenerDoneSem);
  end;
end;

procedure ConnStateInvoke(ABlock: PWSBlock; AState: Int32;
  AError: Pointer); cdecl;
var
  C: TWSNwConn;
begin
  EnsureThreadInit;
  C := TWSNwConn(ABlock^.Ctx);
  case AState of
    NW_CONNECTION_STATE_READY:
      C.ArmReceive;
    NW_CONNECTION_STATE_FAILED:
      C.RemoteClosed;
    NW_CONNECTION_STATE_CANCELLED:
      C.FTransport.ConnFinalized(C);
  end;
end;

procedure RecvInvoke(ABlock: PWSBlock; AContent, AContext: Pointer;
  AComplete: ByteBool; AError: Pointer); cdecl;
var
  C: TWSNwConn;
  Map, Buf: Pointer;
  Size: NativeUInt;
  T: TWSNetworkFrameworkTransport;
begin
  EnsureThreadInit;
  C := TWSNwConn(ABlock^.Ctx);
  if C.FDead then Exit;
  T := C.FTransport;
  if AContent <> nil then
  begin
    Map := Dispatch_data_create_map(AContent, @Buf, @Size);
    if (Size > 0) and Assigned(T.OnData) then
      T.OnData(C, Buf, Size);
    Dispatch_release(Map);
    if C.FDead then Exit; // the session tore it down inside OnData
  end;
  if (AError <> nil) or AComplete then
    C.RemoteClosed
  else
    C.ArmReceive;
end;

procedure SendInvoke(ABlock: PWSBlock; AError: Pointer); cdecl;
var
  C: TWSNwConn;
begin
  EnsureThreadInit;
  C := TWSNwConn(ABlock^.Ctx);
  C.FInFlight := False;
  if C.FDead then
  begin
    // Deferred SubmitClose: the final send has landed (or was aborted).
    Nw_connection_cancel(C.FNw);
    Exit;
  end;
  if AError <> nil then
    C.RemoteClosed
  else if Assigned(C.FTransport.OnSendReady) then
    C.FTransport.OnSendReady(C);
end;

procedure NewConnInvoke(ABlock: PWSBlock; ANwConn: Pointer); cdecl;
var
  T: TWSNetworkFrameworkTransport;
  C: TWSNwConn;
begin
  EnsureThreadInit;
  T := TWSNetworkFrameworkTransport(ABlock^.Ctx);
  // Refuse connections while stopping — or before Open, when no session
  // events are wired and an accepted connection could never progress.
  if T.FStopping or (not T.FOpen) then
  begin
    Nw_connection_cancel(ANwConn);
    Exit;
  end;
  Nw_retain(ANwConn);
  C := TWSNwConn.Create;
  C.FTransport := T;
  C.FNw := ANwConn;
  C.FQueue := Dispatch_queue_create('org.duetto.conn', nil);
  Inc(T.FNextId);
  C.Id := T.FNextId;
  InterLockedIncrement(T.FActive);
  T.LiveTrack(C);
  if Assigned(T.OnAccept) then T.OnAccept(C);
  Nw_connection_set_queue(ANwConn, C.FQueue);
  Nw_connection_set_state_changed_handler(ANwConn,
    MakeBlock(C.FStateBlock, @ConnStateInvoke, C));
  Nw_connection_start(ANwConn);
end;

// ---------------------------------------------------------------------------
// TWSNwConn
// ---------------------------------------------------------------------------

procedure TWSNwConn.ArmReceive;
begin
  Nw_connection_receive(FNw, 1, High(UInt32),
    MakeBlock(FRecvBlock, @RecvInvoke, Self));
end;

procedure TWSNwConn.RemoteClosed;
begin
  if FClosedNotified or FDead then Exit;
  FClosedNotified := True;
  if Assigned(FTransport.OnClosed) then FTransport.OnClosed(Self);
  // The session has dropped its references; tear the nw side down. The
  // cancelled state is the final callback and frees this object.
  // A send still in flight performs the cancel from its completion
  // instead (no need to abort the final bytes; cancel is idempotent).
  FDead := True;
  if not FInFlight then Nw_connection_cancel(FNw);
end;

function TWSNwConn.SubmitSend(P: PByte; ALen: NativeInt): NativeInt;
var
  Data: Pointer;
begin
  if FDead or FClosedNotified then Exit(-1);
  if FInFlight then Exit(0); // backpressure: OnSendReady re-offers
  // Default destructor copies the buffer — the protocol's out queue may
  // move under an async send. Zero-copy here is a measured follow-up.
  Data := Dispatch_data_create(P, ALen, nil, nil);
  FInFlight := True;
  Nw_connection_send(FNw, Data, CtxDefaultStream, False,
    MakeBlock(FSendBlock, @SendInvoke, Self));
  Dispatch_release(Data);
  Result := ALen;
end;

procedure TWSNwConn.SubmitClose;
begin
  if FDead then Exit;
  FDead := True;
  // A send still in flight carries the final bytes (typically the close
  // frame) — the send completion performs the deferred cancel.
  if FInFlight then Exit;
  Nw_connection_cancel(FNw);
  // Freed in ConnFinalized once the cancelled state lands — callbacks
  // may still be queued behind us on this connection's queue.
end;

// ---------------------------------------------------------------------------
// TWSNetworkFrameworkTransport
// ---------------------------------------------------------------------------

constructor TWSNetworkFrameworkTransport.Create(APort: Word;
  const ATls: TWSTransportTls);
var
  TlsBlock: Pointer;
  PortStr: AnsiString;
begin
  inherited Create;
  // GCD callbacks allocate on their own threads; the heap must already
  // be in thread-safe mode before the first one can fire.
  IsMultiThread := True;
  FStopSem := Dispatch_semaphore_create(0);
  FReadySem := Dispatch_semaphore_create(0);
  FDrainSem := Dispatch_semaphore_create(0);
  FListenerDoneSem := Dispatch_semaphore_create(0);
  FLiveLock := TCriticalSection.Create;
  FListenerQueue := Dispatch_queue_create('org.duetto.listener', nil);

  if ATls.Enabled then
  begin
    LoadIdentity(ATls.Pkcs12Path, ATls.Pkcs12Passphrase);
    TlsBlock := MakeBlock(FTlsBlock, @TlsConfigInvoke, Self);
  end
  else
    TlsBlock := CfgDisableProtocol;

  FParams := Nw_parameters_create_secure_tcp(TlsBlock,
    MakeBlock(FTcpBlock, @TcpConfigInvoke, Self));
  Nw_parameters_set_reuse_local_address(FParams, True);

  PortStr := AnsiString(IntToStr(APort));
  FListener := Nw_listener_create_with_port(PAnsiChar(PortStr), FParams);
  if FListener = nil then
    raise Exception.Create('nw_listener_create_with_port failed');
  Nw_listener_set_queue(FListener, FListenerQueue);
  Nw_listener_set_state_changed_handler(FListener,
    MakeBlock(FListenerStateBlock, @ListenerStateInvoke, Self));
  Nw_listener_set_new_connection_handler(FListener,
    MakeBlock(FNewConnBlock, @NewConnInvoke, Self));
  Nw_listener_start(FListener);

  Dispatch_semaphore_wait(FReadySem,
    Dispatch_time(0, ListenerReadyTimeoutSeconds * NsPerSecond));
  if FListenerState <> NW_LISTENER_STATE_READY then
    raise Exception.CreateFmt('listener failed to bind port %d', [APort]);
end;

destructor TWSNetworkFrameworkTransport.Destroy;
begin
  Shutdown;
  if FListener <> nil then Nw_release(FListener);
  if FParams <> nil then Nw_release(FParams);
  if FTlsIdentity <> nil then Nw_release(FTlsIdentity);
  if FTempKeychain <> nil then
  begin
    SecKeychainDelete(FTempKeychain);
    CFRelease(FTempKeychain);
  end;
  if FListenerQueue <> nil then Dispatch_release(FListenerQueue);
  Dispatch_release(FStopSem);
  Dispatch_release(FReadySem);
  Dispatch_release(FDrainSem);
  Dispatch_release(FListenerDoneSem);
  FLiveLock.Free;
  inherited;
end;

// Quiesce (idempotent): stop accepting, hard-cancel every live
// connection — aborting in-flight sends, which is what makes the drain
// bounded — then wait until every cancelled state has landed. After
// this returns no completion can ever fire again, so the session may
// free its per-connection state (nw connection objects are freed by
// their own cancelled handlers during the drain).
procedure TWSNetworkFrameworkTransport.Shutdown;
var
  Doomed: array of TWSNwConn;
  I: Integer;
begin
  if FShutdownDone then Exit;
  FShutdownDone := True;
  FStopping := True;
  if FListener <> nil then
  begin
    Nw_listener_cancel(FListener);
    // Wait until the cancelled state has actually landed: returning
    // early would let a late listener callback touch freed state.
    // nw guarantees delivery of the cancelled state after cancel.
    while FListenerState <> NW_LISTENER_STATE_CANCELLED do
      Dispatch_semaphore_wait(FListenerDoneSem,
        Dispatch_time(0, DrainPollMs * NsPerMs));
  end;
  FLiveLock.Acquire;
  try
    SetLength(Doomed, FLiveCount);
    for I := 0 to FLiveCount - 1 do
      Doomed[I] := FLive[I];
  finally
    FLiveLock.Release;
  end;
  // nw_connection_cancel is thread-safe and idempotent.
  for I := 0 to High(Doomed) do
    Nw_connection_cancel(Doomed[I].FNw);
  while InterLockedExchangeAdd(FActive, 0) > 0 do
    Dispatch_semaphore_wait(FDrainSem,
      Dispatch_time(0, DrainPollMs * NsPerMs));
end;

procedure TWSNetworkFrameworkTransport.ConnFinalized(AConn: TWSNwConn);
begin
  LiveUntrack(AConn);
  Nw_release(AConn.FNw);
  Dispatch_release(AConn.FQueue);
  AConn.Free;
  InterLockedDecrement(FActive);
  Dispatch_semaphore_signal(FDrainSem);
end;

procedure TWSNetworkFrameworkTransport.LiveTrack(AConn: TWSNwConn);
begin
  FLiveLock.Acquire;
  try
    if FLiveCount = Length(FLive) then
      SetLength(FLive, FLiveCount + LiveTableGrowth);
    FLive[FLiveCount] := AConn;
    Inc(FLiveCount);
  finally
    FLiveLock.Release;
  end;
end;

procedure TWSNetworkFrameworkTransport.LiveUntrack(AConn: TWSNwConn);
var
  I: Integer;
begin
  FLiveLock.Acquire;
  try
    for I := 0 to FLiveCount - 1 do
      if FLive[I] = AConn then
      begin
        FLive[I] := FLive[FLiveCount - 1];
        FLive[FLiveCount - 1] := nil;
        Dec(FLiveCount);
        Break;
      end;
  finally
    FLiveLock.Release;
  end;
end;

procedure TWSNetworkFrameworkTransport.LoadIdentity(const APath,
  APassphrase: string);
var
  FS: TFileStream;
  Bytes: TBytes;
  CfData, CfPass, CfOpts, Items, Item0, IdentRef: Pointer;
  Keys, Values: array[0..1] of Pointer;
  Status: Int32;
  KcPath: AnsiString;
  KcPass: AnsiString;
begin
  FS := TFileStream.Create(APath, fmOpenRead);
  try
    SetLength(Bytes, FS.Size);
    if FS.Size > 0 then FS.ReadBuffer(Bytes[0], FS.Size);
  finally
    FS.Free;
  end;

  // Import into a private throwaway keychain owned by this transport.
  // SecPKCS12Import otherwise lands the key in the login keychain with
  // an ACL bound to the importing binary: the next build of the same
  // server would block forever inside the TLS handshake waiting for an
  // authorization prompt no headless process can answer. The keychain
  // file is deleted in Destroy.
  KcPath := AnsiString(GetTempFileName(GetTempDir, 'duetto-tls-'));
  KcPass := 'duetto-transient';
  Status := SecKeychainCreate(PAnsiChar(KcPath), Length(KcPass),
    PAnsiChar(KcPass), False, nil, FTempKeychain);
  if Status <> 0 then
    raise Exception.CreateFmt('temporary keychain creation failed (%d)',
      [Status]);

  CfData := CFDataCreate(nil, @Bytes[0], Length(Bytes));
  CfPass := CFStringCreateWithCString(nil,
    PAnsiChar(AnsiString(APassphrase)), CF_STRING_ENCODING_UTF8);
  Keys[0] := KeyImportPassphrase;
  Values[0] := CfPass;
  Keys[1] := KeyImportKeychain;
  Values[1] := FTempKeychain;
  CfOpts := CFDictionaryCreate(nil, @Keys[0], @Values[0], 2,
    DictKeyCallbacks, DictValueCallbacks);
  Items := nil;
  Status := SecPKCS12Import(CfData, CfOpts, @Items);
  CFRelease(CfOpts);
  CFRelease(CfPass);
  CFRelease(CfData);

  if (Status <> 0) or (Items = nil) or (CFArrayGetCount(Items) = 0) then
  begin
    if Items <> nil then CFRelease(Items);
    raise Exception.CreateFmt('PKCS#12 import failed for %s (status %d)',
      [APath, Status]);
  end;
  Item0 := CFArrayGetValueAtIndex(Items, 0);
  IdentRef := CFDictionaryGetValue(Item0, KeyImportItemIdentity);
  if IdentRef = nil then
  begin
    CFRelease(Items);
    raise Exception.CreateFmt('no identity in %s', [APath]);
  end;
  CFRetain(IdentRef);
  CFRelease(Items);
  FTlsIdentity := Sec_identity_create(IdentRef);
  CFRelease(IdentRef);
  if FTlsIdentity = nil then
    raise Exception.Create('sec_identity_create failed');
end;

procedure TWSNetworkFrameworkTransport.Open;
begin
  FOpen := True;
end;

procedure TWSNetworkFrameworkTransport.Run(ATimeoutMs: Integer);
begin
  if ATimeoutMs < 0 then
    Dispatch_semaphore_wait(FStopSem, DISPATCH_TIME_FOREVER)
  else
    Dispatch_semaphore_wait(FStopSem,
      Dispatch_time(0, Int64(ATimeoutMs) * NsPerMs));
end;

procedure TWSNetworkFrameworkTransport.Stop;
begin
  FStopping := True;
  Dispatch_semaphore_signal(FStopSem);
end;

initialization
  ResolveDataSymbols;
{$endif}

end.
