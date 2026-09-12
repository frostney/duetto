{ WS.Transport.Test — the bind-address literal parser every transport
  shares (WSParseBindAddress): '' is every interface, strict dotted-quad
  IPv4, RFC 4291 IPv6 text forms (full, '::' compression, embedded IPv4),
  and a rejection table (hostnames, brackets, zone ids, bad octets,
  wrong group counts, double '::', stray colons) — every row of which
  must raise naming the input rather than fall through to a resolver. }

program WS.Transport.Test;

{$I Shared.inc}

uses
  SysUtils,

  TestingPascalLibrary,
  WS.Transport;

type
  TBindLiterals = class(TTestSuite)
  private
    // Parse AText and pin family, echoed text and the leading bytes
    // (AHex: two digits per byte; 4 bytes for IPv4, 16 for IPv6).
    procedure ExpectLiteral(const AText: string; AFamily: TWSBindFamily;
      const AHex: string);
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

// The verdict names the input either way, so a failing row of the
// rejection table reads as "accepted 'foo'" rather than a bare False.
function Verdict(const AText: string): string;
begin
  try
    WSParseBindAddress(AText);
    Result := 'accepted ''' + AText + '''';
  except
    on E: Exception do
      if Pos('''' + AText + '''', E.Message) > 0 then
        Result := 'rejected ''' + AText + ''''
      else
        Result := 'rejected without naming ''' + AText + ''': ' + E.Message;
  end;
end;

const
  // Names (never resolved), URL host syntax (brackets, zone ids, ports),
  // IPv4 strictness, IPv6 strictness, and plain garbage.
  RejectedLiterals: array[0..28] of string = (
    'localhost', 'example.com',
    '[::1]', '[]', 'fe80::1%en0', '127.0.0.1:80',
    '256.0.0.1', '1.2.3', '1.2.3.4.5', '1..2.3', '1.2.3.', '.1.2.3',
    '0001.2.3.4', ' 127.0.0.1',
    '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '1::2::3', '1:2:3:4:5:6:7:8::',
    ':::', ':', ':1', '1:', '1::2:', '12345::', 'g::1', '::ffff:1.2.3',
    '::1.2.3.4:5', '1:2:3:4:5:6:7:1.2.3.4',
    'garbage');

procedure TBindLiterals.ExpectLiteral(const AText: string;
  AFamily: TWSBindFamily; const AHex: string);
var
  A: TWSBindAddress;
begin
  A := WSParseBindAddress(AText);
  Expect<Integer>(Ord(A.Family)).ToBe(Ord(AFamily));
  Expect<string>(A.Text).ToBe(AText);
  Expect<string>(HexOf(A, Length(AHex) div 2)).ToBe(AHex);
end;

procedure TBindLiterals.TestEmptyIsAny;
begin
  ExpectLiteral('', wbfAny, '00000000000000000000000000000000');
end;

procedure TBindLiterals.TestInet4;
begin
  ExpectLiteral('127.0.0.1', wbfInet4, '7F000001');
  ExpectLiteral('0.0.0.0', wbfInet4, '00000000');
  ExpectLiteral('255.255.255.255', wbfInet4, 'FFFFFFFF');
  ExpectLiteral('10.1.2.3', wbfInet4, '0A010203');
end;

procedure TBindLiterals.TestInet6Full;
begin
  ExpectLiteral('2001:0db8:0000:0000:0000:ff00:0042:8329', wbfInet6,
    '20010DB8000000000000FF0000428329');
  ExpectLiteral('1:2:3:4:5:6:7:8', wbfInet6,
    '00010002000300040005000600070008');
  ExpectLiteral('ABCD:ef01::', wbfInet6, 'ABCDEF01000000000000000000000000');
end;

procedure TBindLiterals.TestInet6Compressed;
begin
  ExpectLiteral('::1', wbfInet6, '00000000000000000000000000000001');
  ExpectLiteral('::', wbfInet6, '00000000000000000000000000000000');
  ExpectLiteral('2001:db8::1', wbfInet6, '20010DB8000000000000000000000001');
  ExpectLiteral('fe80::', wbfInet6, 'FE800000000000000000000000000000');
  ExpectLiteral('1:2:3:4:5:6:7::', wbfInet6, '00010002000300040005000600070000');
  ExpectLiteral('::2:3:4:5:6:7:8', wbfInet6, '00000002000300040005000600070008');
end;

procedure TBindLiterals.TestInet6EmbeddedInet4;
begin
  ExpectLiteral('::ffff:127.0.0.1', wbfInet6, '00000000000000000000FFFF7F000001');
  ExpectLiteral('64:ff9b::192.0.2.33', wbfInet6, '0064FF9B0000000000000000C0000221');
  ExpectLiteral('1:2:3:4:5:6:10.0.0.1', wbfInet6, '0001000200030004000500060A000001');
end;

procedure TBindLiterals.TestRejections;
var
  I: Integer;
begin
  for I := 0 to High(RejectedLiterals) do
    Expect<string>(Verdict(RejectedLiterals[I]))
      .ToBe('rejected ''' + RejectedLiterals[I] + '''');
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
