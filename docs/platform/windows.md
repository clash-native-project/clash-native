# Windows Platform Notes

## Current development profile

- Operating system: Windows.
- Target architecture: x86-64 only.
- C and C++ compiler: standalone LLVM `clang-cl`.
- MSVC toolchain: Visual Studio C++ headers, libraries, linker, and Windows SDK.
- Build tools: CMake and Ninja managed by Pixi.
- Build system: CMake with Ninja, managed by Pixi.
- Dependency manager: vcpkg manifest mode.
- vcpkg triplet: `x64-windows-clang-cl`.
- C runtime linkage: static MSVC/UCRT runtime (`/MT` for Release, `/MTd` for
  Debug).
- MSVC STL iterator debugging: disabled consistently with
  `_HAS_ITERATOR_DEBUGGING=0` for the project and vcpkg dependencies.

The canonical build command is:

```powershell
pixi run python scripts/build.py --build-type Release --llvm-root "C:\Program Files\LLVM" --vs-installation "C:\Program Files\Microsoft Visual Studio\18\Community"
```

The CMake build script resolves CMake and Ninja from the Pixi environment and
uses standalone LLVM `clang-cl` with the MSVC toolchain. ngtcp2 is acquired by
CMake FetchContent; HTTP, TLS, QUIC, Protobuf, and KCP dependencies are
otherwise resolved by the vcpkg manifest. The gRPC client wire protocol is
implemented over the existing HTTP/2 session and uses Protobuf serialization;
the upstream gRPC C++ runtime is not linked. KCP uses the upstream
`skywind3000/kcp` C library under MIT.
The manifest constrains package versions against the pinned vcpkg baseline.
This Windows profile does not use MSYS2 or auxiliary build systems.
Static CRT linkage does not remove Windows operating-system DLL dependencies;
the executable still uses Windows networking, diagnostics, kernel, and
synchronization APIs.

## Profiles

The current Windows test gate and development target are Windows x86-64 with
the standalone LLVM clang-cl and MSVC profile. Win32/32-bit x86 support is
deferred and is not part of Stage 0, the current release scope, or the
validation matrix.

The repository may retain historical MSYS2/MinGW triplet files. They are not
maintained or validated profiles and must not be interpreted as a support
claim. Reintroducing 32-bit x86 requires an explicit architecture decision and
a new toolchain, dependency, runtime, and final-artifact validation effort.

## Validation boundary

The QUIC/HTTP dependency replacement must be validated in a fresh build
directory before its configure, build, and test results are considered current.
Windows x64 validation does not prove
32-bit x86, Linux, Zig, musl, router, TUN, transparent-proxy, or
route-management behavior.

Do not use this document as evidence for another platform. Add or update the
corresponding platform document when that platform is actually configured or
tested.

The current KCP interop check is Windows x64 only: build the
`clash-native-kcp-client` host with the command above, set
`CLASH_NATIVE_KCP_CLIENT` to that executable, and run
`go test -count=1 -run '^TestKCPClientInteroperability$' -v .` from
`tests/interop`. The test uses an independent `kcp-go` server and validates a
256 KiB bidirectional exchange. It does not cover mKCP or a KCP-based proxy
protocol.
