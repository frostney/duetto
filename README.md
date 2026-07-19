# duetto

WebSocket for Pascal — *duetto*, Italian for duet: both sides talking at
once over one full-duplex connection. RFC 6455 (v13) + RFC 7692
permessage-deflate in FreePascal, built and tested with
[lwpt](https://github.com/frostney/lwpt). A sans-I/O protocol core behind a
blocking client and a server with per-platform transports — epoll on
Linux, Network.framework on macOS (native `wss://`), IOCP on Windows —
validated by unit suites, a live-socket battery, and the Autobahn
testsuite. See [docs/architecture.md](docs/architecture.md).

## Install

```toml
duetto = "frostney/duetto@^0.1.0"   # in lwpt.toml [dependencies]
```

## Usage

Client, anywhere POSIX:

```pascal
uses WS.Client;

Cli := TWSClient.Create;
Cli.Connect('wss://example.org/feed', { offer deflate } True);
Cli.SendText('hello');
while Cli.ReadMessage(IsText, Data) do
  Handle(IsText, Data);
Cli.Close(1000);
```

Echo server (Linux, macOS, Windows) and probe, from the shipped programs:

```bash
lwpt build
./build/wsecho --port=9001                       # echo server
./build/wsprobe ws://localhost:9001/ --deflate   # client probe vs any server
./build/wsecho --pkcs12=id.p12 --pkcs12-pass=x   # wss:// (macOS, native TLS)
```

For the full program set (`wsinterop`, `wsbench`, `wsautobahn`) and every
development command, see [docs/quick-start.md](docs/quick-start.md) and
[docs/tooling.md](docs/tooling.md).

## Background

Every RFC 6455 rule — fragmentation, mask-direction policing, control-frame
interleave, fail-fast streaming UTF-8, close-code validation, RSV bits,
deflate — lives in one sans-I/O state machine (`WS.Protocol`), so the same
testable core sits behind the client, the server, and the benchmarks
unchanged. Conformance is enforced four ways: co-located unit suites
(including a 16.8M-case UTF-8 differential), the `wsinterop` live-socket
battery, the [Autobahn testsuite](docs/tooling.md#autobahn-testsuite) in
both directions, and cross-checks against the Python `websockets` reference
implementation. Measured numbers against Rust and Python peers live in
[docs/comparison.md](docs/comparison.md).

## Contribution

Install the [lwpt](https://github.com/frostney/lwpt) release binary,
then `lwpt install` + `lwpt test`. See
[docs/quick-start.md](docs/quick-start.md).

## References

- [Agent instructions](AGENTS.md)
- [License](LICENSE) (MIT)
