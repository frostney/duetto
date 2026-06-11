#!/usr/bin/env python3
"""Echo server on the `websockets` reference library, for the bench matrix.
usage: pyecho.py PORT [deflate]
"""
import asyncio, sys, websockets

async def echo(ws):
    try:
        async for m in ws:
            await ws.send(m)
    except websockets.ConnectionClosed:
        pass

async def main():
    port = int(sys.argv[1])
    deflate = len(sys.argv) > 2 and sys.argv[2] == "deflate"
    kw = {} if deflate else {"compression": None}
    async with websockets.serve(echo, "127.0.0.1", port, **kw):
        print(f"listening on {port}", flush=True)
        await asyncio.Future()

asyncio.run(main())
