program wsprobe;

// Point the duetto client at any echo endpoint and verify the essentials:
//
//   wsprobe ws://host:port/ [--deflate]
//
// Sends text / unicode / binary / large messages, expects byte-identical
// echoes, then performs a clean close. Exit 0 on success — handy both as
// a smoke tool against third-party servers and as the client half of
// cross-implementation checks.

{$I Shared.inc}

uses
  Classes, SysUtils,

  CLI.Help, CLI.Options, CLI.Parser,

  WS.Client;

const
  UsageLine = 'ws://host:port/ [--deflate]';

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
  Flush(Output);
end;

var
  DeflateOpt, HelpOpt: TFlagOption;
  Options: TOptionArray;
  Positionals: TStringList;
  Cli: TWSClient;
  Url: string;
  Deflate: Boolean;
  IsText: Boolean;
  Data, Big: TBytes;
  S: RawByteString;
  I: Integer;
begin
  DeflateOpt := TFlagOption.Create('deflate',
    'Offer permessage-deflate in the opening handshake');
  HelpOpt := TFlagOption.Create('help', 'Show this help and exit');
  Options := TOptionArray.Create(DeflateOpt, HelpOpt);

  Positionals := nil;
  try
    Positionals := ParseCommandLine(Options);
    if HelpOpt.Present then
    begin
      Write(GenerateHelpText('wsprobe', UsageLine, Options));
      Halt(0);
    end;
    if Positionals.Count <> 1 then
      raise TParseError.Create('expected exactly one ws:// or wss:// URL');
    Url := Positionals[0];
  except
    on E: TParseError do
    begin
      WriteLn('wsprobe: ', E.Message);
      Write(GenerateHelpText('wsprobe', UsageLine, Options));
      Halt(2);
    end;
  end;
  Deflate := DeflateOpt.Present;
  Positionals.Free;
  for I := 0 to High(Options) do
    Options[I].Free;

  Cli := TWSClient.Create;
  try
    Cli.Connect(Url, Deflate);
    WriteLn('connected; deflate=', Cli.Deflate.Enabled);
    Flush(Output);

    S := 'probe says hi';
    Cli.SendText(S);
    Check(Cli.ReadMessage(IsText, Data) and IsText and
      (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S)),
      'ascii text echo');

    S := 'grüße aus london — 中文 — 🚀';
    Cli.SendText(S);
    Check(Cli.ReadMessage(IsText, Data) and IsText and
      (Length(Data) = Length(S)) and CompareMem(@Data[0], @S[1], Length(S)),
      'multibyte utf-8 echo');

    SetLength(Big, 257 * 1024); // forces 64-bit length encoding
    for I := 0 to High(Big) do Big[I] := Byte(I xor (I shr 8));
    Cli.SendBinary(@Big[0], Length(Big));
    Check(Cli.ReadMessage(IsText, Data) and (not IsText) and
      (Length(Data) = Length(Big)) and CompareMem(@Data[0], @Big[0], Length(Big)),
      'binary 257 KiB echo (64-bit length)');

    Cli.Ping('probe');
    Cli.SendText('post-ping');
    Check(Cli.ReadMessage(IsText, Data) and (Length(Data) = 9),
      'ping tolerated mid-stream');

    Cli.Close(1000, 'probe done');
    Check(Cli.CloseCode = 1000, 'close echoed 1000');
  except
    on E: Exception do
    begin
      WriteLn('FAIL - ', E.Message);
      Inc(Failures);
    end;
  end;
  Cli.Free;

  if Failures = 0 then
    WriteLn('probe: ALL CHECKS PASSED')
  else
    WriteLn('probe: ', Failures, ' FAILURE(S)');
  Halt(Ord(Failures > 0));
end.
