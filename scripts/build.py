#!/usr/bin/env python3
"""Configure, build, and test clash-native with CMake and Ninja."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VCPKG_REPOSITORY = "https://github.com/microsoft/vcpkg.git"
DEFAULT_VCPKG_ROOT = PROJECT_ROOT / ".tools" / "vcpkg"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=None,
        help="CMake build directory (default: build/<msys2-environment>[-<architecture>])",
    )
    parser.add_argument(
        "--build-type",
        choices=("Debug", "Release", "RelWithDebInfo", "MinSizeRel"),
        default="Debug",
        help="CMake build type (default: Debug)",
    )
    parser.add_argument(
        "--msys2-root",
        type=Path,
        default=None,
        help="MSYS2 installation root; MSYS2_ROOT is used when omitted",
    )
    parser.add_argument(
        "--msys2-environment",
        choices=("ucrt64", "mingw64"),
        default="ucrt64",
        help="MSYS2 environment used for the compiler (default: ucrt64)",
    )
    parser.add_argument(
        "--architecture",
        choices=("x64", "x86"),
        default="x64",
        help="Windows target architecture (default: x64)",
    )
    parser.add_argument(
        "--vcpkg-root",
        type=Path,
        default=None,
        help="vcpkg source directory; VCPKG_ROOT is used when omitted",
    )
    parser.add_argument(
        "--update-vcpkg",
        action="store_true",
        help="Update an existing vcpkg checkout before bootstrapping it",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Build without running CTest",
    )
    return parser.parse_args()


def resolve_program(
    name: str,
    candidates: list[Path],
    *,
    prefer_candidates: bool = False,
) -> Path:
    paths = candidates[:]
    on_path = shutil.which(name)
    if on_path:
        paths.append(Path(on_path))

    if not prefer_candidates and on_path:
        paths = [Path(on_path), *candidates]

    for candidate in paths:
        if candidate.is_file():
            return candidate.resolve()

    searched = ", ".join(str(candidate) for candidate in paths)
    raise RuntimeError(f"Could not find {name}. Searched PATH and: {searched}")


def resolve_msys2_root(explicit_root: Path | None) -> Path:
    root = explicit_root or (
        Path(os.environ["MSYS2_ROOT"])
        if os.environ.get("MSYS2_ROOT")
        else None
    )
    if root is None:
        raise RuntimeError(
            "MSYS2_ROOT is not set. Pass --msys2-root or set MSYS2_ROOT."
        )

    root = root.expanduser().resolve()
    if not root.is_dir():
        raise RuntimeError(f"MSYS2 root does not exist: {root}")
    return root


def run(
    command: list[str],
    environment: dict[str, str],
    *,
    cwd: Path = PROJECT_ROOT,
) -> None:
    print(
        "+",
        " ".join(f'"{part}"' if " " in part else part for part in command),
        flush=True,
    )
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def resolve_vcpkg_root(explicit_root: Path | None) -> Path:
    root = explicit_root or (
        Path(os.environ["VCPKG_ROOT"])
        if os.environ.get("VCPKG_ROOT")
        else DEFAULT_VCPKG_ROOT
    )
    return root.expanduser().resolve()


def ensure_vcpkg(
    explicit_root: Path | None,
    update: bool,
    environment: dict[str, str],
) -> Path:
    root = resolve_vcpkg_root(explicit_root)
    git = resolve_program("git", [])
    vcpkg_executable = root / "vcpkg.exe"
    bootstrap_script = root / "bootstrap-vcpkg.bat"

    if not root.exists():
        root.parent.mkdir(parents=True, exist_ok=True)
        run(
            [str(git), "clone", VCPKG_REPOSITORY, str(root)],
            environment,
            cwd=root.parent,
        )
    elif not (root / ".git").is_dir() and not bootstrap_script.is_file():
        raise RuntimeError(
            f"vcpkg root is neither a Git checkout nor a vcpkg source tree: {root}"
        )

    shallow_marker = root / ".git" / "shallow"
    if shallow_marker.is_file():
        run([str(git), "fetch", "--unshallow"], environment, cwd=root)

    if update and (root / ".git").is_dir():
        run([str(git), "pull", "--ff-only"], environment, cwd=root)

    if not vcpkg_executable.is_file():
        if not bootstrap_script.is_file():
            raise RuntimeError(f"vcpkg bootstrap script is missing: {bootstrap_script}")
        run(
            ["cmd.exe", "/d", "/c", str(bootstrap_script), "-disableMetrics"],
            environment,
            cwd=root,
        )

    if not vcpkg_executable.is_file():
        raise RuntimeError(f"vcpkg bootstrap did not produce: {vcpkg_executable}")

    return root


def validate_build_cache(build_dir: Path, toolchain_file: Path, triplet: str) -> bool:
    cache_file = build_dir / "CMakeCache.txt"
    if not cache_file.is_file():
        return False

    cache_lines = cache_file.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines()
    cache_toolchain = next(
        (
            line.split("=", 1)[1]
            for line in cache_lines
            if line.startswith("CMAKE_TOOLCHAIN_FILE:") and "=" in line
        ),
        None,
    )
    if cache_toolchain is None:
        raise RuntimeError(
            f"Build directory was configured without vcpkg: {build_dir}. "
            "Use a new --build-dir."
        )

    if Path(cache_toolchain).resolve() != toolchain_file.resolve():
        raise RuntimeError(
            f"Build directory uses a different CMake toolchain: {build_dir}. "
            "Use a new --build-dir."
        )

    if "VCPKG_MANIFEST_INSTALL:BOOL=ON" not in cache_lines:
        raise RuntimeError(
            f"Build directory was not initialized by vcpkg manifest mode: {build_dir}. "
            "Use a new --build-dir."
        )

    cache_triplet = next(
        (
            line.split("=", 1)[1]
            for line in cache_lines
            if line.startswith("VCPKG_TARGET_TRIPLET:") and "=" in line
        ),
        None,
    )
    if cache_triplet != triplet:
        raise RuntimeError(
            f"Build directory uses a different vcpkg triplet: {build_dir}. "
            "Use a new --build-dir."
        )

    return True


def main() -> int:
    arguments = parse_args()
    try:
        msys2_root = resolve_msys2_root(arguments.msys2_root)
        msys2_bin = msys2_root / arguments.msys2_environment / "bin"
        if not msys2_bin.is_dir():
            raise RuntimeError(f"MSYS2 environment does not exist: {msys2_bin}")

        cmake = resolve_program(
            "cmake",
            [msys2_bin / "cmake.exe"],
        )
        ninja = resolve_program(
            "ninja",
            [msys2_bin / "ninja.exe"],
        )
        clang = resolve_program(
            "clang.exe",
            [msys2_bin / "clang.exe"],
            prefer_candidates=True,
        )
        clangxx = resolve_program(
            "clang++.exe",
            [msys2_bin / "clang++.exe"],
            prefer_candidates=True,
        )

        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join(
            [str(msys2_bin), environment.get("PATH", "")]
        )
        environment["CLASH_NATIVE_MSYS2_BIN"] = str(msys2_bin)
        environment["CLASH_NATIVE_TARGET_ARCHITECTURE"] = arguments.architecture

        vcpkg_root = ensure_vcpkg(
            arguments.vcpkg_root,
            arguments.update_vcpkg,
            environment,
        )

        build_dir = (
            arguments.build_dir
            if arguments.build_dir is not None
            else PROJECT_ROOT
            / "build"
            / (
                arguments.msys2_environment
                if arguments.architecture == "x64"
                else f"{arguments.msys2_environment}-{arguments.architecture}"
            )
        ).expanduser()
        if not build_dir.is_absolute():
            build_dir = PROJECT_ROOT / build_dir
        build_dir = build_dir.resolve()
        build_dir.mkdir(parents=True, exist_ok=True)

        toolchain_file = (
            vcpkg_root / "scripts" / "buildsystems" / "vcpkg.cmake"
        ).resolve()
        triplet = f"{arguments.architecture}-msys2-clang"
        has_cached_toolchain = validate_build_cache(build_dir, toolchain_file, triplet)

        configure_command = [
            str(cmake),
            "-S",
            str(PROJECT_ROOT),
            "-B",
            str(build_dir),
            "-G",
            "Ninja",
            f"-DCMAKE_MAKE_PROGRAM={ninja}",
            f"-DVCPKG_TARGET_TRIPLET={triplet}",
            f"-DVCPKG_OVERLAY_TRIPLETS={PROJECT_ROOT / 'triplets'}",
            "-DVCPKG_MANIFEST_MODE=ON",
            f"-DCMAKE_C_COMPILER={clang}",
            f"-DCMAKE_CXX_COMPILER={clangxx}",
            f"-DCMAKE_BUILD_TYPE={arguments.build_type}",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ]
        if not has_cached_toolchain:
            configure_command.insert(7, f"-DCMAKE_TOOLCHAIN_FILE={toolchain_file}")
        run(configure_command, environment)

        run([str(cmake), "--build", str(build_dir), "--parallel"], environment)

        if not arguments.skip_tests:
            run(
                [str(cmake), "--build", str(build_dir), "--target", "test"],
                environment,
            )

            go = resolve_program("go", [])
            environment["CLASH_NATIVE_TEST_HOST"] = str(
                build_dir / "clash-native-test-host.exe"
            )
            run(
                [str(go), "test", "./..."],
                environment,
                cwd=PROJECT_ROOT / "tests" / "interop",
            )
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        return 1

    print(f"Build completed successfully: {build_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
