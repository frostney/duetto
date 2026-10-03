program wsecho;

// RFC 6455 echo server on duetto — the standard benchmark/conformance
// target shape (same contract as the Autobahn fuzzingclient peer and the
// uWebSockets load_test server: echo every data message verbatim).
//
//   wsecho [--port=9001] [--bind=ADDRESS] [--no-deflate] [--quiet]
//          [--pkcs12=FILE [--pkcs12-pass-file=PATH]]
//   WSECHO_PKCS12_PASS=SECRET wsecho --pkcs12=FILE
//   wsecho --pkcs12=FILE --pkcs12-pass=SECRET   (insecure, see below)
//
// Prints "listening on <port>" once ready so harnesses can wait for it
// (--port=0 binds an ephemeral port and reports the real one).
// --bind listens on one IPv4 or IPv6 literal ('127.0.0.1', '::1')
// instead of every interface; it goes straight to TWSServer, which
// rejects anything else (hostnames are never resolved).
// --pkcs12 serves wss:// with the identity in FILE, natively on every
// platform (duetto#22): macOS terminates TLS inside Network.framework,
// while the epoll (Linux) and IOCP (Windows) transports terminate it
// themselves over lwpt's memory-BIO accept API — OpenSSL on Linux
// (libssl/libcrypto 3 loadable at runtime), SChannel on Windows (x64
// and win32, nothing to ship beside the executable).
//
// The PKCS#12 passphrase has three sources. --pkcs12-pass-file reads
// it from a file (one trailing newline stripped, so `echo secret >
// file` works) and WSECHO_PKCS12_PASS from the environment; neither
// lands in the argument list `ps` shows every local user, nor in shell
// history. --pkcs12-pass=SECRET still works
// but is the insecure form: every local user can read it in `ps`.
// The two flags are mutually exclusive; either one overrides the
// environment variable, and an empty variable counts as unset. Each
// source names TLS intent, so without --pkcs12 every one of them is
// refused rather than silently serving plaintext. The resolved source
// (not just the value read at startup) is kept for the whole run, so a
// certificate reload (#82) can read it again.
//
// There are deliberately no knobs for the TLS flow-control policy: the
// program serves with every TWSTransportTls tuning field left at 0, so
// each falls back to its default. The flow-control watermarks are lwpt's
// defaults — a 64 KiB encrypted-input watermark (also the per-round
// socket read bound) with a 32 KiB resume watermark and 64 KiB of
// encrypted-output capacity — while the handshake-liveness guards are
// duetto's own (WS.Transport.TlsServer): a 10 s handshake deadline and a
// 64 KiB pre-handshake inbound budget. Squeezing those is a
// listener-tuning decision an echo/conformance target has no opinion
// about; wsinterop is where the extremes are exercised.

{$I Shared.inc}

uses
  {$ifdef UNIX} cthreads, {$endif}
  Classes, SysUtils,

  CLI.Help, CLI.Options, CLI.Parser,

  WS.Server, WS.Transport;

const
  UsageLine = '[--port=N] [--bind=ADDRESS] [--no-deflate] [--quiet] ' +
    '[--pkcs12=FILE [--pkcs12-pass-file=PATH | --pkcs12-pass=SECRET]]';
  PassphraseEnvironmentName = 'WSECHO_PKCS12_PASS';
  // TWSServer's own default, restated because --bind is the argument
  // after it.
  MaxMessageBytes = 16 * 1024 * 1024;

type
  // Where the PKCS#12 passphrase comes from. Location is the file path
  // (psFile) or the environment variable name (psEnvironment); Literal
  // holds the value only for the command-line form, which has nothing
  // else to re-read.
  TPassphraseKind = (psNone, psCommandLine, psFile, psEnvironment);
  TPassphraseSource = record
    Kind: TPassphraseKind;
    Location: string;
    Literal: string;
  end;

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

// Reads a passphrase file whole and strips exactly one trailing newline
// (LF or CRLF) — the one `echo` or an editor appends. Anything else,
// including further newlines or spaces, is part of the passphrase.
function ReadPassphraseFile(const APath: string): string;
var
  Stream: TFileStream;
  Len: Integer;
begin
  if DirectoryExists(APath) then
    raise Exception.CreateFmt('--pkcs12-pass-file %s is a directory',
      [APath]);
  try
    Stream := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
    try
      SetLength(Result, Stream.Size);
      if Length(Result) > 0 then
        Stream.ReadBuffer(Result[1], Length(Result));
    finally
      Stream.Free;
    end;
  except
    on E: Exception do
      raise Exception.CreateFmt('cannot read --pkcs12-pass-file: %s',
        [E.Message]);
  end;
  Len := Length(Result);
  if (Len > 0) and (Result[Len] = #10) then
  begin
    Dec(Len);
    if (Len > 0) and (Result[Len] = #13) then
      Dec(Len);
    SetLength(Result, Len);
  end;
end;

// Reads the passphrase from its source. Called once at startup today;
// re-reading the same source is what a reload (#82) needs.
function ReadPassphrase(const ASource: TPassphraseSource): string;
begin
  case ASource.Kind of
    psCommandLine: Result := ASource.Literal;
    psFile: Result := ReadPassphraseFile(ASource.Location);
    psEnvironment: Result := GetEnvironmentVariable(ASource.Location);
  else
    Result := '';
  end;
end;

// Names a source in an error message — never its value.
function PassphraseSourceName(const ASource: TPassphraseSource): string;
begin
  case ASource.Kind of
    psCommandLine: Result := '--pkcs12-pass';
    psFile: Result := '--pkcs12-pass-file';
    psEnvironment: Result := ASource.Location;
  else
    Result := 'no passphrase source';
  end;
end;

// Picks the passphrase source from the parsed flags and the environment
// (precedence in the header comment). Raises TParseError on a conflict.
function ResolvePassphraseSource(APkcs12, APassOpt,
  APassFileOpt: TStringOption): TPassphraseSource;
begin
  Result.Kind := psNone;
  Result.Location := '';
  Result.Literal := '';
  if APassOpt.Present and APassFileOpt.Present then
    raise TParseError.Create(
      '--pkcs12-pass and --pkcs12-pass-file are mutually exclusive');
  if APassOpt.Present then
  begin
    Result.Kind := psCommandLine;
    Result.Literal := APassOpt.ValueOr('');
  end
  else if APassFileOpt.Present then
  begin
    if APassFileOpt.ValueOr('') = '' then
      raise TParseError.Create('--pkcs12-pass-file needs a file path');
    Result.Kind := psFile;
    Result.Location := APassFileOpt.ValueOr('');
  end
  else if GetEnvironmentVariable(PassphraseEnvironmentName) <> '' then
  begin
    Result.Kind := psEnvironment;
    Result.Location := PassphraseEnvironmentName;
  end;
  if (Result.Kind <> psNone) and (not APkcs12.Present) then
    raise TParseError.CreateFmt(
      '%s requires --pkcs12 (refusing to serve plaintext)',
      [PassphraseSourceName(Result)]);
end;

var
  PortOpt: TIntegerOption;
  BindOpt, Pkcs12Opt, Pkcs12PassOpt, Pkcs12PassFileOpt: TStringOption;
  NoDeflateOpt, QuietOpt, HelpOpt: TFlagOption;
  Options: TOptionArray;
  Positionals: TStringList;
  Srv: TWSServer;
  Echo: TEcho;
  Tls: TWSTransportTls;
  // Lives for the whole run so a reload (#82) can re-read the source.
  PassphraseSource: TPassphraseSource;
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
  BindOpt := TStringOption.Create('bind',
    'Listen on one IPv4 or IPv6 literal (default: every interface)');
  Pkcs12PassFileOpt := TStringOption.Create('pkcs12-pass-file',
    'Read the --pkcs12 passphrase from this file, minus one trailing ' +
    'newline (alternative: ' + PassphraseEnvironmentName +
    ' in the environment)');
  Pkcs12PassOpt := TStringOption.Create('pkcs12-pass',
    'Passphrase for --pkcs12 on the command line (insecure: visible ' +
    'in ps and shell history)');
  HelpOpt := TFlagOption.Create('help', 'Show this help and exit');
  Options := TOptionArray.Create(PortOpt, BindOpt, NoDeflateOpt, QuietOpt,
    Pkcs12Opt, Pkcs12PassFileOpt, Pkcs12PassOpt, HelpOpt);

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
      if BindOpt.Present and (BindOpt.ValueOr('') = '') then
        raise TParseError.Create('--bind needs an address');
      PassphraseSource := ResolvePassphraseSource(Pkcs12Opt, Pkcs12PassOpt,
        Pkcs12PassFileOpt);
      if Pkcs12Opt.Present and (Pkcs12Opt.ValueOr('') = '') then
        raise TParseError.Create(
          '--pkcs12 needs a file path (refusing to serve plaintext)');
    except
      on E: TParseError do
      begin
        WriteLn('wsecho: ', E.Message);
        Write(GenerateHelpText('wsecho', UsageLine, Options));
        Halt(2);
      end;
    end;

    // Runtime failures (an unreadable passphrase file, a bind literal
    // TWSServer rejects, a port in use, a bad identity) exit 1 with the
    // reason instead of an unhandled-exception dump.
    try
      Tls := WSTransportNoTls;
      if Pkcs12Opt.Present then
      begin
        Tls.Enabled := True;
        Tls.Pkcs12Path := Pkcs12Opt.ValueOr('');
        Tls.Pkcs12Passphrase := ReadPassphrase(PassphraseSource);
      end;
      Srv := TWSServer.Create(PortOpt.ValueOr(9001), Tls,
        not NoDeflateOpt.Present, MaxMessageBytes, BindOpt.ValueOr(''));
    except
      on E: Exception do
      begin
        WriteLn('wsecho: ', E.Message);
        Halt(1);
      end;
    end;
    Echo := TEcho.Create;
    Echo.Quiet := QuietOpt.Present;
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
