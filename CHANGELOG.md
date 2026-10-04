# Changelog

All notable changes to duetto are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); entries are generated from Conventional Commits by git-cliff.

## [0.6.0] - 2026-10-04

### Bug Fixes

- send an owed keepalive ping before judging the idle bound (#83)
- accept IPv6, userinfo and query-only ws URLs, send a correct Host and resolve IPv4 and IPv6 (#94)
- bound connect, handshake and close, and survive resets, TLS errors and EINTR (#91)
- bound the plaintext close drain and silence completions after SubmitClose (#84)
- let OnMessage answer a message before a failing frame's close (#87)
- stop truncating long handshakes and answer 431 past the header cap (#86)

### Documentation

- document the resource bounds, session clocks and close-drain budget (#90)

### Internal

- refresh project Agent Skills (#93)
- bump softprops/action-gh-release from 2.6.2 to 3.0.3 (#78)
- pin the project-skills caller to known-good-route c2c76e4 (#92)

### New Features

- add --bind and passphrase sources outside the command line (#85)
- pass OnUpgradeRequest a mutable upgrade context (#89)
- contain handler exceptions behind OnError (#88)

## [0.5.1] - 2026-10-03

### Bug Fixes

- pass C bools to Network.framework as 0/1 (#75)

### Internal

- refresh project Agent Skills (#77)
- publish a GitHub Release for each version tag (#76)

## [0.5.0] - 2026-09-27

### Bug Fixes

- drive every deadline from a monotonic clock (#71)
- accept a compressed message exactly at the cap (#70)
- make the benchmark tooling runnable and accurate (#52)
- release on a raising OnClientClose, and pair it at Destroy (#58)
- bound the reads one readiness event takes (#53)
- audit correctness batch — inflater truncation, server teardown, wss reads, close codes (#33)
- keep the inflate window free of memory the peer never sent (#50)

### Documentation

- re-measure on the optimised build (#57)

### Internal

- use the shared excludeVendoredSkills instead of inline logic (#69)
- stop reviewing vendored Agent Skills, keep project-authored ones (#67)
- refresh project Agent Skills (#65)
- pin the skills updater to the hosted-runner fix (#64)
- refresh project Agent Skills and adopt the consolidated delivery loop (#36)
- run the battery as section procedures (#60)
- enforce analysis ceilings, require TLS coverage, pin actions, fix docs drift (#35)
- run the PR workflow for stacked pull requests (#59)
- bump lwpt to 0.7.0 (#31)

### New Features

- run the win32 battery under Wine in Docker (#51)
- resource bounds, peer clocks and transport accept/close hardening (#34)
- optional bind address and OnUpgradeRequest handshake hook (#32)

### Performance

- gather-write sends on the epoll transport (#56)
- fewer payload copies on the hot path (#55)

## [0.4.0] - 2026-08-14

### Documentation

- retro hardening — concurrency re-review rule + spike pattern (#18)

### Internal

- graduate native Autobahn onto the arm64 macOS merge leg (#17)

### New Features

- implement all remaining open issues (#19–#26) on lwpt 0.6.0 (#27)

## [0.3.0] - 2026-07-19

### Bug Fixes

- defer protocol-failure drops until pending output drains (#15)

### New Features

- Windows support — WinSock2 client, IOCP transport, win64+win32 CI (#14)

## [0.2.0] - 2026-07-19

### Internal

- scope the x86_64-darwin leg to build + unit suites (#12)

### New Features

- completion-shaped transport seam + Network.framework macOS transport (#9)

## [0.1.0] - 2026-07-19

### Bug Fixes

- post-merge review triage for #1 (#5)
- text echo check broke when the probe string was renamed
- guard SSE2 masking bench behind x86_64 Linux

### Documentation

- add VISION, Definition of Ready, and Definition of Done (#7)

### Internal

- upgrade to lwpt 0.2.0 and prepare the 0.1.0 release (#1)
- rename project from lwws to duetto
- install lwpt from its release instead of bootstrapping a checkout
- consume lwpt and its packages from the 0.1.0 release
- parse flags via lwpt's cli package
- add PR gate and main-branch workflows
- add Autobahn testsuite integration in both directions
- adopt known-good-route project structure
- split source into source/units and source/apps
- import lwws prototype spike


