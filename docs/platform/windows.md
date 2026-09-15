# Windows Platform Notes

## Current development profile

- Operating system: Windows.
- Environment: MSYS2 UCRT64.
- C and C++ compiler: Clang 22.1.8 from `D:\msys2\ucrt64\bin`.
- Build generator: Ninja.
- Build system: CMake driven by `scripts/build.py`.
- Dependency manager: vcpkg manifest mode.
- vcpkg triplet: `x64-msys2-clang` for the validated profile.
- C runtime linkage: dynamic UCRT64 runtime.

The canonical build command is:

```powershell
python scripts/build.py --msys2-root D:\msys2
```

For the configured x86 profile, use `--architecture x86`; its default build
directory is `build\ucrt64-x86`.

The script prepends the selected MSYS2 environment to `PATH` so executables
and tests can find their runtime DLLs. Direct CTest invocation must preserve
the same PATH setup:

```powershell
$env:PATH = "D:\msys2\ucrt64\bin;$env:PATH"
ctest --test-dir build\ucrt64 --output-on-failure
```

## Profiles

The current Windows test gate and development target are Windows x64 with the
MSYS2 UCRT64 Clang profile. Win32/x86 is not currently tested or treated as a
release target. The x86 profile remains configuration-only for possible future
compatibility work and is not a support claim.

The build script exposes `x64` and `x86` profile names. The x86 profile uses
the `x86-msys2-clang` triplet; it remains unvalidated until an installed
32-bit Clang and matching dependency set are available. The current x86 probe
selected `i686-w64-windows-gnu` but failed while linking Boost's compiler test
because the UCRT64 linker could not find 32-bit runtime and Windows import
libraries such as `-lkernel32`, `-lstdc++`, and `-lmingw32`.

## Validation boundary

Windows x64 validation covers the CMake configure/build path, the core and
frontend targets, the C++ tests, the Go black-box harness when invoked by the
build script, and the experimental SOCKS5 loopback flow. It does not prove
x86, Linux, Zig, musl, router, TUN, transparent-proxy, or route-management
behavior.

Do not use this document as evidence for another platform. Add or update the
corresponding platform document when that platform is actually configured or
tested.
