---
name: Bug report
about: Something duetto does that the RFCs, the docs or common sense say it should not
labels: bug
---

## What happens

<!-- One or two sentences. The observable wrong behaviour. -->

## Reproduction

<!-- The smallest thing that shows it: a wsprobe invocation, a raw-socket
     recipe, a frame sequence, a client/server snippet. Which transport
     (epoll / Network.framework / IOCP) and whether ws:// or wss://. -->

## Expected

<!-- What should happen, and why — cite the RFC section or the doc when
     one applies. -->

## Environment

- duetto version / commit:
- Platform (`uname -a` / `systeminfo`, `fpc -iV`, lwpt version):
- Peer implementation, if the bug is interop:

## Evidence

<!-- Output of the failing gate, wsinterop line, Autobahn case id,
     crosscheck output — whatever you have. -->
