# Vendored QUICHE

## Source

- Upstream repository: https://github.com/google/quiche
- Upstream commit: `364478046fe60979aae31cebb45bc6480a294688`
- Vendored date: 2026-09-16
- Vendored source directory: `third_party/quiche`
- Upstream license: `third_party/quiche/LICENSE`

The source is vendored for build and integration work. It is not connected to
the project's CMake targets yet.

The Windows x64 build probe is invoked through:

```powershell
python scripts/build_quiche.py --llvm-root "C:\Program Files\LLVM" --vs-installation "C:\Program Files\Microsoft Visual Studio\18\Community" --msys2-root D:\msys2 --bazelisk build\quiche-tools\bazelisk.exe
```

The script uses `build/quiche-tools/bazelisk.exe` when present, or a Bazelisk
executable available on `PATH`.

## Local changes

The vendored copy contains the following changes required by the Windows x64
LLVM clang-cl build probe:

- Added the `x64_windows-clang-cl` platform to the root `BUILD.bazel`.
- Added the `platforms` dependency and the `cc_configure` repository to
  `MODULE.bazel`; `MODULE.bazel.lock` was regenerated accordingly.
- Added the `windows_platform_impl` header target to `quiche/BUILD.bazel`.
- Selected the Windows platform include directory before the default platform
  directory for `quiche_core`.
- Added `WIN32_LEAN_AND_MEAN` to the `quiche_core` compile options so the
  Windows SDK does not introduce unrelated COM/OLE macros into QUICHE headers.
- Added
  `quiche/common/platform/windows/quiche_platform_impl/quiche_logging_impl.h`
  to preserve the default logging implementation, remove the Windows
  `interface` macro when present, and provide the `_0` severity aliases needed
  when the Windows `ERROR` macro is active.

The build script applies the required `DUMPBIN` discovery change to Bazel's
generated external `rules_cc` cache at build time. This change is not part of
the vendored source and is not written into the repository.

## Validation

The following target was built on Windows x86-64 with standalone LLVM clang-cl
and the MSVC environment, with ICU disabled:

```text
//quiche:quiche_core
```

The resulting static library was reported at
`bazel-out/x64_windows-fastbuild/bin/quiche/quiche_core.lib` under the Bazel
output base. This validates only the QUICHE core build probe. It does not
validate CMake integration, QUICHE tests or tools, Win32/x86, Linux, Zig, musl,
or other platforms.
