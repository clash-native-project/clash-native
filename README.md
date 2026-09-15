# clash-native
An experimental native reimplementation inspired by Mihomo. This project is in a very early stage of development and is not recommended for use at this time.

## Build

The initial build uses CMake, Ninja, and Clang from an MSYS2 64-bit environment. The build script downloads and bootstraps the latest vcpkg checkout when needed. Dependency versions are controlled by `vcpkg.json` and its registry baseline.

Set `MSYS2_ROOT` to the MSYS2 installation directory, then run:

```powershell
$env:MSYS2_ROOT = "C:\msys64"
python scripts/build.py
```

The default environment is `ucrt64`. Use `--msys2-environment mingw64` when the MinGW 64-bit environment is required. Use `--update-vcpkg` to update an existing vcpkg checkout. The executable, dependency installation, and CMake files are written below `build/<msys2-environment>/` unless `--build-dir` is supplied.

To run the executable directly from PowerShell, add the selected MSYS2 environment to `PATH`:

```powershell
$env:PATH = "$env:MSYS2_ROOT\ucrt64\bin;$env:PATH"
& .\build\ucrt64\clash-native.exe --version
```

## Current Ordinary Proxy Flow

The experimental proxy can accept unauthenticated SOCKS5 `CONNECT` and HTTP
`CONNECT` requests:

```powershell
& .\build\ucrt64\clash-native.exe --listen 127.0.0.1:1080
```

The current implementation supports IPv4, IPv6, and domain-name targets with
TCP bidirectional relay. The core also has initial direct/reject outbounds and
first-match routing primitives; named outbounds, configured DNS-aware routing,
UDP association, BIND, and username/password authentication are not implemented
in the CLI yet. Press `Ctrl+C` to stop the listener.

## Implemented Build Boundaries

The current CMake build defines these targets:

- `clash-native-core`: a reusable static library containing the runtime,
  platform adapter, ordinary proxy data-plane code, and routing primitives;
- `clash-native`: the standalone process, including CLI parsing and
  process-level application lifecycle, linked to `clash-native-core`;
- `clash-native-tests`: the C++ test executable, which links to
  `clash-native-core` instead of compiling core sources again.

This is a build and ownership boundary. The broader engine, DNS, additional
protocols, and C API described in `docs/architecture.md` remain planned work;
the Stage 1 routing primitives are intentionally not a complete routing or
DNS implementation.

Stage 0 also includes the initial runtime set and scheduler adapter, owned
channel primitives, a core-only test host, and Go process/network test
scaffolding. These foundations do not implement the later protocol or
platform traffic-capture stages.

## Stage 2 DNS and Routing Foundations

The core now contains initial ordered routing snapshots, destination-IP CIDR
matching with lazy enrichment, a dependency-free DNS codec, system resolver
adapter, DNS policy matcher, and UDP/TCP resolver service with TTL caching and
in-flight query coalescing. This is not a complete configuration engine:
upstream groups, local DNS service, FakeIP, encrypted DNS transports, and
platform traffic-capture integration remain planned work.
