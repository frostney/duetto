{ WS.Transport.Test — the bind-address literal parser every transport
  shares (WSParseBindAddress): '' is every interface, strict dotted-quad
  IPv4, RFC 4291 IPv6 text forms (full, '::' compression, embedded IPv4),
  and the rejection matrix (hostnames, brackets, zone ids, bad octets,
  wrong group counts, double '::', stray colons) — every one of which
  raises naming the input rather than falling through to a resolver. }

program WS.Transport.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Transport;

type
  TBindLiterals = class(TTestSuite)
  public
    procedure SetupTests; override;
    procedure TestEmptyIsAny;
    procedure TestInet4;
    procedure TestInet6Full;
    procedure TestInet6Compressed;
    procedure TestInet6EmbeddedInet4;
    procedure TestRejections;
  end;

function HexOf(const A: TWSBindAddress; ACount: Integer): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to ACount - 1 do
    Result := Result + IntToHex(A.Bytes[I], 2);
end;

// True when the parser raised — and the message named the input, so
// the operator sees which flag value was wrong.
function Rejects(const AText: string): Boolean;
begin
  Result := False;
  try
    WSParseBindAddress(AText);
  except
    on E: Exception do
      Result := Pos('''' + AText + '''', E.Message) > 0;
  end;
end;

procedure TBindLiterals.TestEmptyIsAny;
var
  A: TWSBindAddress;
begin
  A := WSParseBindAddress('');
  Expect<Integer>(Ord(A.Family)).ToBe(Ord(wbfAny));
  Expect<string>(A.Text).ToBe('');
  Expect<string>(HexOf(A, 16)).ToBe('00000000000000000000000000000000');
end;

procedure TBindLiterals.TestInet4;
var
  A: TWSBindAddress;
begin
  A := WSParseBindAddress('127.0.0.1');
  Expect<Integer>(Ord(A.Family)).ToBe(Ord(wbfInet4));
  Expect<string>(A.Text).ToBe('127.0.0.1');
  Expect<string>(HexOf(A, 4)).ToBe('7F000001');
  A := WSParseBindAddress('0.0.0.0');
  Expect<Integer>(Ord(A.Family)).ToBe(Ord(wbfInet4));
  Expect<string>(HexOf(A, 4)).ToBe('00000000');
  A := WSParseBindAddress('255.255.255.255');
  Expect<string>(HexOf(A, 4)).ToBe('FFFFFFFF');
end;

procedure TBindLiterals.TestInet6Full;
var
  A: TWSBindAddress;
begin
  A := WSParseBindAddress('2001:0db8:0000:0000:0000:ff00:0042:8329');
  Expect<Integer>(Ord(A.Family)).ToBe(Ord(wbfInet6));
  Expect<string>(HexOf(A, 16)).ToBe('20010DB8000000000000FF0000428329');
  A := WSParseBindAddress('1:2:3:4:5:6:7:8');
  Expect<string>(HexOf(A, 16)).ToBe('00010002000300040005000600070008');
  A := WSParseBindAddress('ABCD:ef01::');
  Expect<string>(HexOf(A, 16)).ToBe('ABCDEF01000000000000000000000000');
end;

procedure TBindLiterals.TestInet6Compressed;
var
  A: TWSBindAddress;
begin
  A := WSParseBindAddress('::1');
  Expect<Integer>(Ord(A.Family)).ToBe(Ord(wbfInet6));
  Expect<string>(A.Text).ToBe('::1');
  Expect<string>(HexOf(A, 16)).ToBe('00000000000000000000000000000001');
  A := WSParseBindAddress('::');
  Expect<string>(HexOf(A, 16)).ToBe('00000000000000000000000000000000');
  A := WSParseBindAddress('2001:db8::1');
  Expect<string>(HexOf(A, 16)).ToBe('20010DB8000000000000000000000001');
  A := WSParseBindAddress('fe80::');
  Expect<string>(HexOf(A, 16)).ToBe('FE800000000000000000000000000000');
  A := WSParseBindAddress('1:2:3:4:5:6:7::');
  Expect<string>(HexOf(A, 16)).ToBe('00010002000300040005000600070000');
  A := WSParseBindAddress('::2:3:4:5:6:7:8');
  Expect<string>(HexOf(A, 16)).ToBe('00000002000300040005000600070008');
end;

procedure TBindLiterals.TestInet6EmbeddedInet4;
var
  A: TWSBindAddress;
begin
  A := WSParseBindAddress('::ffff:127.0.0.1');
  Expect<Integer>(Ord(A.Family)).ToBe(Ord(wbfInet6));
  Expect<string>(HexOf(A, 16)).ToBe('00000000000000000000FFFF7F000001');
  A := WSParseBindAddress('64:ff9b::192.0.2.33');
  Expect<string>(HexOf(A, 16)).ToBe('0064FF9B0000000000000000C0000221');
  A := WSParseBindAddress('1:2:3:4:5:6:10.0.0.1');
  Expect<string>(HexOf(A, 16)).ToBe('0001000200030004000500060A000001');
end;

procedure TBindLiterals.TestRejections;
begin
  // Names: never resolved, so never accepted.
  Expect<Boolean>(Rejects('localhost')).ToBe(True);
  Expect<Boolean>(Rejects('example.com')).ToBe(True);
  // URL host syntax is not a bare literal.
  Expect<Boolean>(Rejects('[::1]')).ToBe(True);
  Expect<Boolean>(Rejects('[]')).ToBe(True);
  Expect<Boolean>(Rejects('fe80::1%en0')).ToBe(True);
  Expect<Boolean>(Rejects('127.0.0.1:80')).ToBe(True);
  // IPv4 strictness.
  Expect<Boolean>(Rejects('256.0.0.1')).ToBe(True);
  Expect<Boolean>(Rejects('1.2.3')).ToBe(True);
  Expect<Boolean>(Rejects('1.2.3.4.5')).ToBe(True);
  Expect<Boolean>(Rejects('1..2.3')).ToBe(True);
  Expect<Boolean>(Rejects('1.2.3.')).ToBe(True);
  Expect<Boolean>(Rejects('.1.2.3')).ToBe(True);
  Expect<Boolean>(Rejects('0001.2.3.4')).ToBe(True);
  Expect<Boolean>(Rejects(' 127.0.0.1')).ToBe(True);
  // IPv6 strictness.
  Expect<Boolean>(Rejects('1:2:3:4:5:6:7')).ToBe(True);
  Expect<Boolean>(Rejects('1:2:3:4:5:6:7:8:9')).ToBe(True);
  Expect<Boolean>(Rejects('1::2::3')).ToBe(True);
  Expect<Boolean>(Rejects('1:2:3:4:5:6:7:8::')).ToBe(True);
  Expect<Boolean>(Rejects(':::')).ToBe(True);
  Expect<Boolean>(Rejects(':')).ToBe(True);
  Expect<Boolean>(Rejects(':1')).ToBe(True);
  Expect<Boolean>(Rejects('1:')).ToBe(True);
  Expect<Boolean>(Rejects('1::2:')).ToBe(True);
  Expect<Boolean>(Rejects('12345::')).ToBe(True);
  Expect<Boolean>(Rejects('g::1')).ToBe(True);
  Expect<Boolean>(Rejects('::ffff:1.2.3')).ToBe(True);
  Expect<Boolean>(Rejects('::1.2.3.4:5')).ToBe(True);
  Expect<Boolean>(Rejects('1:2:3:4:5:6:7:1.2.3.4')).ToBe(True);
  Expect<Boolean>(Rejects('garbage')).ToBe(True);
end;

procedure TBindLiterals.SetupTests;
begin
  Test('empty string is every interface',       TestEmptyIsAny);
  Test('IPv4 dotted-quad',                       TestInet4);
  Test('IPv6 full form',                         TestInet6Full);
  Test('IPv6 :: compression',                    TestInet6Compressed);
  Test('IPv6 with embedded IPv4',                TestInet6EmbeddedInet4);
  Test('rejection matrix names the input',       TestRejections);
end;

begin
  TestRunnerProgram.AddSuite(TBindLiterals.Create('Transport: bind literals'));
  TestRunnerProgram.Run;
  ExitCode := TestResultToExitCode;
end.
