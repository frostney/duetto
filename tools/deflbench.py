#!/usr/bin/env python3
"""Neutral permessage-deflate echo throughput: N concurrent `websockets`
clients ping-ponging a 4 KiB JSON-ish payload for DUR seconds.

usage: deflbench.py ws://host:port/ [conns] [secs]

The generator is identical for every target server, so relative numbers
are comparable even though the (Python) client is the slower party.
"""
import asyncio, sys, time, websockets

URI = sys.argv[1]
CONNS = int(sys.argv[2]) if len(sys.argv) > 2 else 50
DUR = float(sys.argv[3]) if len(sys.argv) > 3 else 8.0

CHUNK = ('{"userId":12345,"action":"purchase","items":[{"id":"A1B2C3",'
         '"name":"Wireless Mouse","price":25.99,"quantity":1}]};')
PAYLOAD = (CHUNK * (4096 // len(CHUNK) + 1))[:4096]

total = 0

async def worker(stop):
    global total
    async with websockets.connect(URI) as ws:
        assert ws.protocol.extensions, "permessage-deflate not negotiated"
        while time.monotonic() < stop:
            await ws.send(PAYLOAD)
            if await ws.recv() != PAYLOAD:
                raise RuntimeError("echo mismatch")
            total += 1

async def main():
    stop = time.monotonic() + DUR
    await asyncio.gather(*(worker(stop) for _ in range(CONNS)))
    print(f"{total / DUR:.0f} msg/s ({CONNS} conns, {DUR:.0f}s, 4096 B, deflate)")

asyncio.run(main())
