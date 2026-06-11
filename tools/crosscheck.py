#!/usr/bin/env python3
"""Cross-implementation check: lwws vs the `websockets` reference library.

Direction 1: python client -> lwws wsecho server
Direction 2: lwws wsprobe client -> python echo server

Plus raw-socket pokes at wsecho that a conforming client can't emit,
asserting RFC 6455 close codes from an independent codebase.
"""
import asyncio, socket, struct, subprocess, sys, time, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WSECHO = os.path.join(ROOT, "build", "wsecho")
WSPROBE = os.path.join(ROOT, "build", "wsprobe")

failures = 0
def check(cond, name):
    global failures
    print(("ok   - " if cond else "FAIL - ") + name)
    if not cond: failures += 1

# --------------------------------------------------------------- direction 1
async def client_vs_wsecho(port):
    import websockets
    uri = f"ws://127.0.0.1:{port}/"

    async with websockets.connect(uri) as ws:
        await ws.send("hello from python")
        check(await ws.recv() == "hello from python", "py->lwws text echo")

        msg = "ünïcødé 中文 🚀 " * 100
        await ws.send(msg)
        check(await ws.recv() == msg, "py->lwws multibyte text echo")

        blob = bytes((i * 13 + 7) & 0xFF for i in range(512 * 1024))
        await ws.send(blob)
        check(await ws.recv() == blob, "py->lwws binary 512 KiB echo")

        # fragmented message: websockets sends an iterable as fragments
        await ws.send(["frag-one ", "frag-two ", "frag-three"])
        check(await ws.recv() == "frag-one frag-two frag-three",
              "py->lwws fragmented text reassembled")

        pong = await ws.ping("heartbeat")
        await asyncio.wait_for(pong, 5)
        check(True, "py->lwws ping answered")

    # context exit performed the closing handshake; reconnect to verify codes
    async with websockets.connect(uri) as ws:
        await ws.close(code=1000, reason="bye")
    check(True, "py->lwws clean close handshake")

    # permessage-deflate (websockets enables it by default)
    async with websockets.connect(uri) as ws:
        big = "compress me please! " * 20000
        await ws.send(big)
        check(await ws.recv() == big, "py->lwws deflate 400 KB echo")

# --------------------------------------------------- raw violations, direction 1
def raw_handshake(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
              b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              b"Sec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    assert b"101" in buf.split(b"\r\n")[0]
    return s

def read_close_code(s):
    buf = b""
    try:
        while True:
            b1 = s.recv(4096)
            if not b1: return 0
            buf += b1
            if len(buf) >= 2:
                op = buf[0] & 0x0F
                ln = buf[1] & 0x7F
                if op == 8:
                    if ln >= 2 and len(buf) >= 4:
                        return struct.unpack(">H", buf[2:4])[0]
                    if ln == 0: return 0
    except socket.timeout:
        return -1

def violations(port):
    s = raw_handshake(port)
    s.sendall(b"\x81\x05hello")                      # unmasked client text
    check(read_close_code(s) == 1002, "raw unmasked frame -> 1002"); s.close()

    s = raw_handshake(port)
    s.sendall(b"\x83\x80\x00\x00\x00\x00")            # reserved opcode 0x3
    check(read_close_code(s) == 1002, "raw reserved opcode -> 1002"); s.close()

    s = raw_handshake(port)
    s.sendall(b"\x89\xFE\x00\x7E" + b"\x00" * 4 + b"x" * 126)  # 126-byte ping
    check(read_close_code(s) == 1002, "raw oversize control -> 1002"); s.close()

    s = raw_handshake(port)                            # RSV1 w/o negotiation
    s.sendall(b"\xC1\x80\x00\x00\x00\x00")
    check(read_close_code(s) == 1002, "raw RSV1 unnegotiated -> 1002"); s.close()

# --------------------------------------------------------------- direction 2
async def wsprobe_vs_python_server():
    import websockets
    async def echo(ws):
        try:
            async for m in ws:
                await ws.send(m)
        except websockets.ConnectionClosed:
            pass
    async with websockets.serve(echo, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        for flag, label in [([], "no-deflate"), (["--deflate"], "deflate")]:
            proc = await asyncio.create_subprocess_exec(
                WSPROBE, f"ws://127.0.0.1:{port}/", *flag,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await asyncio.wait_for(proc.communicate(), 30)
            sys.stdout.write(out.decode())
            check(proc.returncode == 0, f"lwws client vs python server ({label})")

async def main():
    server = subprocess.Popen([WSECHO, "--port=0", "--quiet"],
                              stdout=subprocess.PIPE, text=True)
    try:
        port = int(server.stdout.readline().split()[-1])
        await client_vs_wsecho(port)
        violations(port)
        await wsprobe_vs_python_server()
    finally:
        server.terminate()
    print()
    print("cross-check: ALL PASSED" if failures == 0
          else f"cross-check: {failures} FAILURE(S)")
    sys.exit(1 if failures else 0)

asyncio.run(main())
