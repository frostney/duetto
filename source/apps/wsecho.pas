program wsecho;

// RFC 6455 echo server on lwws — the standard benchmark/conformance
// target shape (same contract as the Autobahn fuzzingclient peer and the
// uWebSockets load_test server: echo every data message verbatim).
//
//   wsecho [--port=9001] [--no-deflate] [--quiet]
//
// Prints "listening on <port>" once ready so harnesses can wait for it.

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  SysUtils, WS.Server;

type
  TEcho = class
  public
    Quiet: Boolean;
    procedure OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
    procedure OnOpen(AConn: TWSConnection);
  end;

procedure TEcho.OnMsg(AConn: TWSConnection; AText: Boolean; P: PByte; Len: NativeInt);
begin
  if AText then
    AConn.SendText(P, Len)
  else
    AConn.SendBinary(P, Len);
end;

procedure TEcho.OnOpen(AConn: TWSConnection);
begin
  if not Quiet then
    WriteLn('open fd=', AConn.Fd);
end;

var
  Srv: TWSServer;
  Echo: TEcho;
  Port: Word;
  Deflate, Quiet: Boolean;
  I: Integer;
  A: string;
begin
  Port := 9001;
  Deflate := True;
  Quiet := False;
  for I := 1 to ParamCount do
  begin
    A := ParamStr(I);
    if Copy(A, 1, 7) = '--port=' then
      Port := StrToInt(Copy(A, 8, MaxInt))
    else if A = '--no-deflate' then
      Deflate := False
    else if A = '--quiet' then
      Quiet := True
    else
    begin
      WriteLn('usage: wsecho [--port=N] [--no-deflate] [--quiet]');
      Halt(2);
    end;
  end;

  Echo := TEcho.Create;
  Echo.Quiet := Quiet;
  Srv := TWSServer.Create(Port, Deflate);
  try
    Srv.OnMessage := Echo.OnMsg;
    if not Quiet then
      Srv.OnOpen := Echo.OnOpen;
    WriteLn('listening on ', Srv.Port);
    Flush(Output);
    Srv.Run;
  finally
    Srv.Free;
    Echo.Free;
  end;
end.
