# Debian/WSL Linux Notes

Linux is a build/validation target for memory-safety diagnosis only
(`#194` Socks5 UDP SEGFAULT). It is not a release target: no portable
artifact, no glibc-floor promise, no coverage claim beyond the named scope.

## Layout

- Toolchain: pixi-pinned `zig 0.16.0` (`[target.linux-64.dependencies]`
  in `pixi.toml`), providing `zig c++` for portable experiments.
- Linux env lives in `.pixi-linux/` (detached-environments, WSL-only,
  git-ignored) so the Windows `.pixi/` is never clobbered: each OS runs
  its own `pixi install`. The WSL global config
  (`~/.pixi/config.toml` inside Debian) points at
  `/mnt/d/Project/cpp/clash-native/.pixi-linux`.
- Verified 2026-09-29: `zig c++ -target x86_64-linux-gnu.2.17 -std=c++20`
  builds a libc++ hello with no system-header mixing (`ldd` shows no
  `libstdc++`/`libc++.so`); the C++ runtime is statically linked.

## C++ library rule

- `zig c++` uses its bundled LLVM `libc++`/`libc++abi` (static). Never add
  `-isystem /usr/include/c++/...` or `-lstdc++`: that mixes glibc 2.41
  headers against `-D__GLIBC_MINOR__=17` and breaks the link
  (`pthread_setspecific@GLIBC_2.34` not found; worked around only with
  `-Wl,--allow-shlib-undefined`, which is not a fix).
- pixi's `libstdcxx` is runtime-only (no `include/c++`); it cannot serve
  as a build sysroot. If a libstdc++-based zig build is ever wanted, add
  a `sysroot_linux-64` dev package first; do not borrow `/usr/include`.
- All vcpkg ports must be built with the same `zig c++` driver, otherwise
  libc++ vs libstdc++ ABI mismatch breaks the link.

## Sanitizer rule

- `zig cc -fsanitize=address` is unsupported upstream (no ASan runtime
  shipped; `__asan_unregister_elf_globals` undefined). Do not wire
  sanitizers into zig wrappers.
- Memory bugs: use system `clang++-19 -fsanitize=address` (Debian ships
  `libclang_rt.asan-x86_64.so` + `libclang_rt.asan_static-x86_64.a`;
  verified on a heap-overflow probe). Known-good link consumes both
  runtime files as local operands plus `-Wl,--allow-shlib-undefined`
  for zig's bundled glibc-2.17 objects, with `LD_LIBRARY_PATH` covering
  the ASan `.so` at runtime.
- The deleted `scripts/zig-cc.sh`, `scripts/zig-cxx.sh`, and
  `cmake/toolchains/debian-zig-cc.cmake` mixed zig driver + system
  libstdc++ + clang-19 ASan runtime and are removed; do not resurrect.
