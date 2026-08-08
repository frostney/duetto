unit WS.Transport.PostQueue;

// Thread-safe FIFO behind the reactor transports' SubmitPost (epoll,
// IOCP): producers on any thread push {connection id, payload} nodes;
// the transport's single execution context detaches the whole chain
// with Drain and walks it in order. The Network.framework transport
// needs no queue of its own — GCD's per-connection serial queues
// already are one.
//
// Stop is the shutdown rendezvous: it atomically rejects every future
// Push and hands the caller whatever was pending, so posts racing
// Shutdown are either in the returned chain (dropped by the caller) or
// refused at Push (dropped by the poster). Nodes are owned by whoever
// detaches them: walk the chain, deliver or drop each Data, and
// Dispose each node.

{$I Shared.inc}

interface

uses
  syncobjs;

type
  PWSPostNode = ^TWSPostNode;
  TWSPostNode = record
    ConnId: NativeUInt;
    Data: Pointer;
    Next: PWSPostNode;
  end;

  TWSPostQueue = class
  private
    FLock: TCriticalSection;
    FHead: PWSPostNode;
    FTail: PWSPostNode;
    FStopped: Boolean;
    function Detach: PWSPostNode;
  public
    constructor Create;
    destructor Destroy; override;

    // Callable from any thread. True = queued (FIFO); False = the queue
    // is stopped and nothing was taken — the caller still owns AData.
    function Push(AConnId: NativeUInt; AData: Pointer): Boolean;

    // Detach and return the pending chain in FIFO order (nil = empty);
    // the caller walks it and Disposes each node.
    function Drain: PWSPostNode;

    // Reject every future Push and detach what was pending (same
    // ownership rules as Drain). Idempotent.
    function Stop: PWSPostNode;
  end;

implementation

constructor TWSPostQueue.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
end;

destructor TWSPostQueue.Destroy;
var
  Node, Next: PWSPostNode;
begin
  // By contract the owner has stopped and drained already; reclaim any
  // straggler nodes defensively (their Data is the owner's leak).
  Node := Detach;
  while Node <> nil do
  begin
    Next := Node^.Next;
    Dispose(Node);
    Node := Next;
  end;
  FLock.Free;
  inherited;
end;

function TWSPostQueue.Detach: PWSPostNode;
begin
  FLock.Acquire;
  try
    Result := FHead;
    FHead := nil;
    FTail := nil;
  finally
    FLock.Release;
  end;
end;

function TWSPostQueue.Push(AConnId: NativeUInt; AData: Pointer): Boolean;
var
  Node: PWSPostNode;
begin
  New(Node);
  Node^.ConnId := AConnId;
  Node^.Data := AData;
  Node^.Next := nil;
  FLock.Acquire;
  try
    Result := not FStopped;
    if Result then
    begin
      if FTail = nil then
        FHead := Node
      else
        FTail^.Next := Node;
      FTail := Node;
    end;
  finally
    FLock.Release;
  end;
  if not Result then Dispose(Node);
end;

function TWSPostQueue.Drain: PWSPostNode;
begin
  Result := Detach;
end;

function TWSPostQueue.Stop: PWSPostNode;
begin
  FLock.Acquire;
  try
    FStopped := True;
    Result := FHead;
    FHead := nil;
    FTail := nil;
  finally
    FLock.Release;
  end;
end;

end.
