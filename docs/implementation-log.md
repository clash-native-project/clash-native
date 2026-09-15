# Implementation Log

This file records completed implementation changes. It is intentionally
separate from `docs/architecture.md`, which describes the project blueprint.

## 2026-09-15

- Established the Stage 0 CMake product boundary:
  - `clash-native-core` owns the runtime, platform adapter, and experimental
    SOCKS5 proxy sources.
  - `clash-native` owns the CLI, process entry point, and application lifecycle
    over the core library.
  - `clash-native-tests` links `clash-native-core` without recompiling core
    sources.
- Fixed the first-configuration CMake toolchain argument ordering in
  `scripts/build.py` so a clean MSYS2/vcpkg configure can run.
- Added the dated implementation-log rule to `AGENTS.md`.

### Stage 0 foundations

- Added the dependency-light core error taxonomy and stream/datagram outbound
  contracts with a shared unsupported-capability conformance harness.
- Added the Asio scheduler adapter and configurable `RuntimeSet`, including
  explicit single-use runtime lifecycle behavior.
- Added owned standard-library channel primitives for oneshot, bounded MPSC,
  unbounded MPSC, and zero-capacity rendezvous delivery with stop-token-aware
  waiting and close propagation.
- Added the core-only `clash-native-test-host`, deterministic Go process
  ownership helpers, and independent TCP/UDP endpoint scaffolding.
- Added x64 and x86 MSYS2 Clang profile configuration. The x64 UCRT64 profile
  passed; the x86 probe remains unvalidated because the local environment
  lacks 32-bit runtime and Windows import libraries.
- Added platform documentation routing and the Windows UCRT64 toolchain notes.
- Validation completed on Windows UCRT64: 18/18 CTest cases passed, the Go
  TCP process black-box case passed, `go vet ./...` passed, and the UDP
  endpoint case was explicitly skipped because UDP loopback is unavailable in
  the environment.
- Documented that current Windows testing is limited to x64 with MSYS2 UCRT64
  Clang; Win32/x86 remains unvalidated and outside the current test gate.
- Added the `tl::expected` dependency behind the project-owned `Result<T>` and
  `Status` aliases. Proxy listener startup now returns structured transport
  errors, while the application and test host translate them at their
  process-level boundaries.
- Added `fmt 12.2.0` as a vcpkg dependency and used `fmt::format` for proxy
  listener error-context construction.
