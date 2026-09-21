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

The WebSocket interop check is also Windows x64 only. The standard build script
sets `CLASH_NATIVE_WEBSOCKET_CLIENT` to the built host and runs
`go test -count=1 -run '^TestWebSocketClientInteroperability$' -v .` from
`tests/interop` when the Go suite is enabled. The test starts an independent
Gorilla WebSocket server, validates the HTTP/1.1 Upgrade path and a custom
header, sends a ping control frame, and checks a 256 KiB binary echo. The
carrier is limited to HTTP/1.1 Upgrade; HTTP/2 and HTTP/3 Extended CONNECT are
not covered.

The local HTTP proxy Upgrade path is validated separately with
`TestHTTPForwardProxyUpgradeIndependentEndpoint`. The test runs the built
native test host as the proxy and an independent Go TCP service as the
Upgrade origin, checking the `101` handshake, forwarded headers, coalesced
initial data, and later bidirectional stream data.

The Shadowsocks `simple-obfs` HTTP and TLS carriers are validated on Windows
x64 with a real Mihomo listener. The checks cover classic AEAD and Shadowsocks
2022 TCP; native Shadowsocks UDP is intentionally unwrapped by these plugins.
The client sends the carrier handshake before opening the stream and consumes
the HTTP 101 or fake TLS server response lazily on the first read.

The Shadowsocks `v2ray-plugin` and `gost-plugin` WebSocket carriers are also
validated on Windows x64 with an independent Go/Gorilla WebSocket server. The
interop test covers both plugin names, a plain HTTP/1.1 Upgrade, and a TLS
wrapped WebSocket. Plugin multiplexing and WebSocket-wrapped native UDP are
outside this check.

The Shadowsocks UDP-over-TCP version 1 and version 2 outbound paths are
validated on Windows x64 with a real Mihomo listener and an independently
built Go interop executable. The test uses a non-loopback IPv4 UDP echo
endpoint when required by the Windows networking environment.

The Shadowsocks `kcptun` outbound path is also validated on Windows x64 with a
real Mihomo listener and the same separately built Go interop executable. The
focused test covers TCP and UDP-over-TCP relay through KCP, SMUX, AES packet
encryption, 10/3 FEC, and Snappy framing. The default `aes` and the
`aes-128-gcm` packet profiles pass this real listener check; alternate crypt and
FEC profiles can be selected as described in `docs/testing.md`. The focused relay case does not
exercise TCP half-close because the tested Mihomo listener closes the full
kcptun stream when its peer sends FIN. It also opens concurrent streams through
the bounded KCP/SMUX session pool. The independent Go packet-pipeline fixture
separately validates AES-GCM + 10/3 FEC without that listener wrapper.

The raw QUIC carrier interop check is Windows x64 only. The standard build
script sets `CLASH_NATIVE_HTTP_TUNNEL_CLIENT` and runs
`TestQUICCarrierExposesStreamsAndDatagrams` from `tests/interop`. The test uses
an independent `quic-go` server, opens four concurrent bidirectional streams
on one QUIC connection, and echoes a QUIC DATAGRAM through the common
`StreamHandle` and `DatagramHandle` adapters. It does not prove DoQ, DoH/3, or
HTTP/3 proxy semantics.
