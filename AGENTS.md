# Agent Instructions

This repository uses `AGENTS.md` for project-specific guidance to coding agents. Keep this file concise, factual, and updated when build or test workflows change.

## Project Overview

- This is the top-level GlobalPlatform project for smart card management.
- Main components:
  - `globalplatform/`: C library implementing OpenPlatform/GlobalPlatform APIs.
  - `gpshell/`: command-line tools, including legacy `gpshell` and newer `gpshell3`.
  - `gppcscconnectionplugin/`: PC/SC connection plugin used by the library and tools.
  - `helloworldapplet/`: Java Card example applet built with Maven and Java Card SDKs.
  - `docs/`: Jekyll/docs content plus generated Doxygen API output.
  - `cmocka-cmocka-1.1.5/`, `zlib-1.2.8/`, `zlib-1.3.1/`: vendored or bundled dependency sources/build assets.

## Worktree Rules

- Assume the worktree may contain user changes. Do not revert, overwrite, or clean unrelated modifications.
- Avoid editing generated or build output directories unless explicitly asked: `build/`, `out/`, `cmake-build-*`, `CMakeFiles/`, `Testing/`, `_CPack_Packages/`, `docs/api/`, `globalplatform/doc/`, and `helloworldapplet/target/`.
- Prefer adding focused source changes over broad formatting or mechanical churn.
- Keep generated binaries, packages, and local test executables out of source changes unless the user explicitly requests release artifact work.

## Build Commands

Use out-of-source CMake builds.

```sh
cmake -S . -B out/build/dev -DCMAKE_BUILD_TYPE=Debug -DTESTING=ON
cmake --build out/build/dev
```

The included preset enables tests and integration-test configuration:

```sh
cmake --preset with-tests
cmake --build out/build/with-tests
```

Static GPShell-focused build:

```sh
cmake -S . -B out/build/static -DCMAKE_BUILD_TYPE=Release -DSTATIC=ON
cmake --build out/build/static
```

Useful CMake options:

- `TESTING=ON`: configure unit tests.
- `INTEGRATION_TESTING=ON`: configure card-backed integration tests when dependencies are available.
- `TOOLS=OFF`: skip GPShell tools.
- `STATIC=ON`: build static variants only.
- `GLOBALPLATFORM_ENABLE_ASAN=ON|OFF`: control AddressSanitizer in debug builds.
- `GLOBALPLATFORM_BUILD_DOCS=ON`: build Doxygen docs during normal builds.

Dependencies commonly needed on Linux: C compiler, CMake, pkg-config, PC/SC Lite development headers, OpenSSL 3, zlib, cmocka, pandoc, Doxygen, and Graphviz.

## Test Commands

Run unit tests without integration tests:

```sh
cmake --build out/build/dev --target test-unit
```

Equivalent direct CTest command:

```sh
ctest --test-dir out/build/dev -LE integration --output-on-failure
```

Integration tests require a build configured with `INTEGRATION_TESTING=ON` plus a suitable smart card/reader. They should not be run by default:

```sh
export OPGP_PLUGIN_PATH="$(pwd)/out/build/dev/gppcscconnectionplugin/src"
cmake --build out/build/dev --target test-integration
```

Important: unsuccessful mutual-authentication attempts can lock real cards. Do not run integration tests, example scripts, or commands that authenticate against a card unless the user explicitly confirms the card, keys, and protocol.

Unit-test coverage is mainly in `globalplatform/src/*Test.c`. Linux unit tests include mocked SCP tests for `scp01Test`, `scp02Test`, and `scp03Test`, plus cmocka tests such as `scp11Test`, `cryptoTest`, `statusTest`, `installDataTest`, `getDataTest`, and `storeDataTest`.

## Code Conventions

- This is C code with cross-platform Unix/Windows support. Preserve existing `#ifdef WIN32`, Unicode, PC/SC, and OpenSSL patterns.
- Public API headers live under `globalplatform/src/globalplatform/`; internal implementation and helpers live in `globalplatform/src/`.
- Preserve established naming: `OPGP_*`, `GP211_*`, `OP201_*`, `BYTE`, `DWORD`, `LONG`, and related typedefs from the project headers.
- Prefer existing helpers for TLV parsing, APDU handling, SCP/session logic, crypto, string conversion, and error reporting instead of duplicating protocol logic.
- When adding source files, update the relevant `CMakeLists.txt` source list:
  - Library: `globalplatform/src/CMakeLists.txt`
  - GPShell tools: `gpshell/src/CMakeLists.txt`
  - PC/SC plugin: `gppcscconnectionplugin/src/CMakeLists.txt`
- Public source files generally carry LGPL notices plus the OpenSSL linking exception. Preserve existing license headers and use the same form for comparable new files.
- Keep comments useful and technical. Do not reformat whole files just to match a different style.

## Documentation And Packaging

- Source manuals are `gpshell/src/gpshell.1.md` and `gpshell/src/gpshell3.1.md`; generated man pages are build artifacts.
- Keep command implementations and manuals in sync:
  - when adding or changing commands in `gpshell/src/gpshell3.c`, update `gpshell/src/gpshell3.1.md` in the same change.
  - when adding or changing commands in `gpshell/src/gpshell.c`, update `gpshell/src/gpshell.1.md` in the same change.
- Doxygen source configuration is under `globalplatform/`; generated HTML API docs are in `docs/api/`.
- Jekyll documentation content is under `docs/`.
- Packaging uses CPack. Typical package commands are run from a configured build directory, for example `cpack -G DEB`, `cpack -G RPM`, `cpack -G ZIP`, or `cpack -G WIX` depending on platform.
- The GitHub workflow `.github/workflows/package-gpshell.yml` is the best reference for release packaging behavior and artifact sanity checks.

## Security Notes

- Do not introduce real smart-card keys, production certificates, card dumps, or private customer data.
- Existing PEM/CAP files under source directories are test fixtures unless the user says otherwise.
- `GLOBALPLATFORM_DEBUG=1` and `GLOBALPLATFORM_LOGFILE=<file>` enable verbose logs; these logs may contain sensitive key or APDU material.
- Treat GPShell examples as potentially destructive against real cards if they install, delete, put keys, or authenticate.

## Java Card Applet

- `helloworldapplet/` is separate from the C/CMake build.
- Java Card 2 builds require `JC212_HOME` and usually a Java 8 compiler.
- Java Card 3 builds require `JC310_HOME` and the Maven `jc3` profile.
- Do not change applet build assumptions unless working directly on the applet.
