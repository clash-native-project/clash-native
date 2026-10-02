# Platform Documentation

This directory contains platform-specific build, validation, and integration
notes. Read the document for the platform being changed or tested before
choosing a toolchain or claiming platform coverage.

- [Windows](windows.md): MSYS2 Clang and UCRT64 development profile.
- [Debian](debian.md): WSL memory-safety diagnosis only (zig c++, system clang ASan).
- [Memory budget](memory-budget.md): cross-cutting note on constrained-device
  memory (iOS jetsam caps, small routers) and the optimization plan. Not a
  platform target and not validation coverage.

Add a separate `<platform>.md` document when a new platform becomes an
implementation or validation target. Platform notes must not replace the
portable architecture or implementation log.
