program wsautobahn;

// Autobahn testsuite client driver — the peer for `wstest -m fuzzingserver`.
//
//   wsautobahn [--server=ws://127.0.0.1:9001] [--agent=lwws] [--deflate]
//
// Speaks the fuzzingserver control protocol: fetch the case count from
// /getCaseCount, run every case via /runCase?case=N&agent=A (echo each
// data message verbatim until the server ends the connection), then ask
// the server to write its report via /updateReports?agent=A.
//
// Exit 0 means the run completed; pass/fail per case is judged from the
// generated report by tools/autobahn-check.py, not here — a protocol
// failure mid-case (1002/1007/1009 from our own machine) is the correct
// behaviour for many cases.

{$I Shared.inc}

uses
  SysUtils, WS.Client;

const
  // Autobahn's largest payloads (cases 9.x) are 16 MiB; leave headroom so
  // our own 1009 cap never fires before the case intends it to.
  MaxCaseMessage = 64 * 1024 * 1024;

function BytesToRaw(const AData: TBytes): RawByteString;
begin
  SetLength(Result, Length(AData));
  if Length(AData) > 0 then
    Move(AData[0], Result[1], Length(AData));
end;

// Opening-handshake failures against the suite are environmental, not
// case behaviour: wstest accepts every connection before any case logic
// runs, but Docker's port proxy answers before wstest listens, and an
// emulated container can hiccup between two of the ~1000 connections of
// a full run. Retry with a fresh client per attempt — a failed Connect
// leaves the instance unusable.
function ConnectRetry(const AUrl: string; AOfferDeflate: Boolean;
  AMaxMessage: NativeInt; AAttempts: Integer): TWSClient;
var
  Attempt: Integer;
begin
  for Attempt := 1 to AAttempts do
  begin
    Result := TWSClient.Create;
    try
      Result.Connect(AUrl, AOfferDeflate, AMaxMessage);
      Exit;
    except
      on EWSClient do
      begin
        FreeAndNil(Result);
        if Attempt = AAttempts then
          raise;
        Sleep(1000);
      end;
    end;
  end;
  Result := nil; // unreachable; silences the compiler
end;

function FetchCaseCount(const AServer: string): Integer;
var
  Cli: TWSClient;
  IsText: Boolean;
  Data: TBytes;
begin
  Result := 0;
  Cli := ConnectRetry(AServer + '/getCaseCount', False, MaxCaseMessage, 60);
  try
    if Cli.ReadMessage(IsText, Data) and IsText then
      Result := StrToIntDef(string(BytesToRaw(Data)), 0);
    if Cli.Open then
      Cli.Close(1000);
  finally
    Cli.Free;
  end;
end;

procedure RunCase(const AServer, AAgent: string; ACase: Integer;
  ADeflate: Boolean);
var
  Cli: TWSClient;
  IsText: Boolean;
  Data: TBytes;
begin
  Cli := ConnectRetry(Format('%s/runCase?case=%d&agent=%s', [AServer, ACase,
    AAgent]), ADeflate, MaxCaseMessage, 15);
  try
    try
      while Cli.ReadMessage(IsText, Data) do
        if IsText then
          Cli.SendText(BytesToRaw(Data))
        else if Length(Data) > 0 then
          Cli.SendBinary(@Data[0], Length(Data))
        else
          Cli.SendBinary(nil, 0);
      if Cli.Open then
        Cli.Close(1000);
    except
      // A dropped connection mid-case is a case result, not a driver
      // failure; the report records what the server observed.
      on E: Exception do
        WriteLn('  case ', ACase, ': ', E.ClassName, ': ', E.Message);
    end;
  finally
    Cli.Free;
  end;
end;

procedure UpdateReports(const AServer, AAgent: string);
var
  Cli: TWSClient;
  IsText: Boolean;
  Data: TBytes;
begin
  // Report generation for ~500 cases can take wstest a while; be patient
  // here — losing this connection loses the whole run's results.
  Cli := ConnectRetry(AServer + '/updateReports?agent=' + AAgent, False,
    MaxCaseMessage, 30);
  try
    while Cli.ReadMessage(IsText, Data) do
      { drain until the server closes };
    if Cli.Open then
      Cli.Close(1000);
  finally
    Cli.Free;
  end;
end;

var
  Server, Agent, A: string;
  Deflate: Boolean;
  CaseCount, I: Integer;
begin
  Server := 'ws://127.0.0.1:9001';
  Agent := 'lwws';
  Deflate := False;
  for I := 1 to ParamCount do
  begin
    A := ParamStr(I);
    if Copy(A, 1, 9) = '--server=' then
      Server := Copy(A, 10, MaxInt)
    else if Copy(A, 1, 8) = '--agent=' then
      Agent := Copy(A, 9, MaxInt)
    else if A = '--deflate' then
      Deflate := True
    else
    begin
      WriteLn('usage: wsautobahn [--server=ws://host:port] [--agent=name] [--deflate]');
      Halt(2);
    end;
  end;

  CaseCount := FetchCaseCount(Server);
  if CaseCount <= 0 then
  begin
    WriteLn('could not fetch case count from ', Server);
    Halt(1);
  end;
  WriteLn('agent=', Agent, ' deflate=', Deflate, ' cases=', CaseCount);
  Flush(Output);

  for I := 1 to CaseCount do
  begin
    if (I = 1) or (I mod 25 = 0) or (I = CaseCount) then
    begin
      WriteLn('case ', I, '/', CaseCount);
      Flush(Output);
    end;
    RunCase(Server, Agent, I, Deflate);
  end;

  UpdateReports(Server, Agent);
  WriteLn('done; reports updated for agent ', Agent);
end.
