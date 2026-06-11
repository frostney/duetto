program wsecho;

// RFC 6455 echo server on lwws — the standard benchmark/conformance
// target shape (same contract as the Autobahn fuzzingclient peer and the
// uWebSockets load_test server: echo every data message verbatim).
//
//   wsecho [--port=9001] [--no-deflate] [--quiet]
//
// Prints "listening on <port>" once ready so harnesses can wait for it
// (--port=0 binds an ephemeral port and reports the real one).

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  Classes, SysUtils,

  CLI.Help, CLI.Options, CLI.Parser,

  WS.Server;

const
  UsageLine = '[--port=N] [--no-deflate] [--quiet]';

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
  PortOpt: TIntegerOption;
  NoDeflateOpt, QuietOpt, HelpOpt: TFlagOption;
  Options: TOptionArray;
  Positionals: TStringList;
  Srv: TWSServer;
  Echo: TEcho;
  I: Integer;
begin
  PortOpt := TIntegerOption.Create('port',
    'Listen port; 0 binds an ephemeral port (default 9001)');
  NoDeflateOpt := TFlagOption.Create('no-deflate',
    'Refuse permessage-deflate during negotiation');
  QuietOpt := TFlagOption.Create('quiet',
    'Suppress per-connection logging');
  HelpOpt := TFlagOption.Create('help', 'Show this help and exit');
  Options := TOptionArray.Create(PortOpt, NoDeflateOpt, QuietOpt, HelpOpt);

  Positionals := nil;
  try
    try
      Positionals := ParseCommandLine(Options);
      if HelpOpt.Present then
      begin
        Write(GenerateHelpText('wsecho', UsageLine, Options));
        Halt(0);
      end;
      if Positionals.Count > 0 then
        raise TParseError.CreateFmt('unexpected argument: %s',
          [Positionals[0]]);
    except
      on E: TParseError do
      begin
        WriteLn('wsecho: ', E.Message);
        Write(GenerateHelpText('wsecho', UsageLine, Options));
        Halt(2);
      end;
    end;

    Echo := TEcho.Create;
    Echo.Quiet := QuietOpt.Present;
    Srv := TWSServer.Create(PortOpt.ValueOr(9001), not NoDeflateOpt.Present);
    try
      Srv.OnMessage := Echo.OnMsg;
      if not QuietOpt.Present then
        Srv.OnOpen := Echo.OnOpen;
      WriteLn('listening on ', Srv.Port);
      Flush(Output);
      Srv.Run;
    finally
      Srv.Free;
      Echo.Free;
    end;
  finally
    Positionals.Free;
    for I := 0 to High(Options) do
      Options[I].Free;
  end;
end.
