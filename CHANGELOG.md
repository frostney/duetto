# Changelog

All notable changes to duetto are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); entries are generated from Conventional Commits by git-cliff.
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


