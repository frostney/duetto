program wsecho;

// RFC 6455 echo server on duetto — the standard benchmark/conformance
// target shape (same contract as the Autobahn fuzzingclient peer and the
// uWebSockets load_test server: echo every data message verbatim).
//
//   wsecho [--port=9001] [--no-deflate] [--quiet]
//          [--pkcs12=FILE --pkcs12-pass=SECRET]
//
// Prints "listening on <port>" once ready so harnesses can wait for it
// (--port=0 binds an ephemeral port and reports the real one).
// --pkcs12 serves wss:// with the identity in FILE — native TLS on
// macOS (Network.framework); the Linux transport rejects it until
// accept-side TransportSecurity lands (lwpt#70).

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  Classes, SysUtils,

  CLI.Help, CLI.Options, CLI.Parser,

  WS.Server, WS.Transport;

const
  UsageLine = '[--port=N] [--no-deflate] [--quiet] ' +
    '[--pkcs12=FILE --pkcs12-pass=SECRET]';

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
    WriteLn('open id=', AConn.Id);
end;

var
  PortOpt: TIntegerOption;
  Pkcs12Opt, Pkcs12PassOpt: TStringOption;
  NoDeflateOpt, QuietOpt, HelpOpt: TFlagOption;
  Options: TOptionArray;
  Positionals: TStringList;
  Srv: TWSServer;
  Echo: TEcho;
  Tls: TWSTransportTls;
  I: Integer;
begin
  PortOpt := TIntegerOption.Create('port',
    'Listen port; 0 binds an ephemeral port (default 9001)');
  NoDeflateOpt := TFlagOption.Create('no-deflate',
    'Refuse permessage-deflate during negotiation');
  QuietOpt := TFlagOption.Create('quiet',
    'Suppress per-connection logging');
  Pkcs12Opt := TStringOption.Create('pkcs12',
    'Serve wss:// with the PKCS#12 identity in FILE');
  Pkcs12PassOpt := TStringOption.Create('pkcs12-pass',
    'Passphrase for --pkcs12');
  HelpOpt := TFlagOption.Create('help', 'Show this help and exit');
  Options := TOptionArray.Create(PortOpt, NoDeflateOpt, QuietOpt,
    Pkcs12Opt, Pkcs12PassOpt, HelpOpt);

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
      if (Pkcs12PassOpt.ValueOr('') <> '') and (Pkcs12Opt.ValueOr('') = '') then
        raise TParseError.Create(
          '--pkcs12-pass requires --pkcs12 (refusing to serve plaintext)');
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
    Tls := WSTransportNoTls;
    if Pkcs12Opt.ValueOr('') <> '' then
    begin
      Tls.Enabled := True;
      Tls.Pkcs12Path := Pkcs12Opt.ValueOr('');
      Tls.Pkcs12Passphrase := Pkcs12PassOpt.ValueOr('');
    end;
    Srv := TWSServer.Create(PortOpt.ValueOr(9001), Tls,
      not NoDeflateOpt.Present);
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
