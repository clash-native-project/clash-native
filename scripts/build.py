#!/usr/bin/env python3
"""Configure, build, and test clash-native with CMake and Ninja."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from windows_clang import prepare_windows_clang


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VCPKG_REPOSITORY = "https://github.com/microsoft/vcpkg.git"
DEFAULT_VCPKG_ROOT = PROJECT_ROOT / ".tools" / "vcpkg"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=None,
        help="CMake build directory (default: build/windows-clang-cl-x64)",
    )
    parser.add_argument(
        "--build-type",
        choices=("Debug", "Release", "RelWithDebInfo", "MinSizeRel"),
        default="Debug",
        help="CMake build type (default: Debug)",
    )
    parser.add_argument(
        "--architecture",
        choices=("x64",),
        default="x64",
        help="Windows target architecture (default: x64)",
    )
    parser.add_argument(
        "--llvm-root",
        type=Path,
        default=None,
        help="Standalone LLVM root; LLVM_ROOT is used when omitted",
    )
    parser.add_argument(
        "--vs-installation",
        type=Path,
        default=None,
        help="Visual Studio installation; VSINSTALLDIR is used when omitted",
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


def cmake_path(path: Path) -> str:
    """Return a CMake cache path with portable separators on Windows."""
    return path.resolve().as_posix()


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


def prepare_vcpkg_ports() -> Path:
    """Validate project-owned overlay ports before configuring vcpkg."""
    botan_port = PROJECT_ROOT / "third_party" / "vcpkg" / "ports" / "botan"
    required_files = ("portfile.cmake", "vcpkg.json", "configure", "jls-random.patch")
    missing = [name for name in required_files if not (botan_port / name).is_file()]
    if missing:
        raise RuntimeError(
            "Project Botan overlay is incomplete; missing: " + ", ".join(missing)
        )
    boringssl_port = PROJECT_ROOT / "third_party" / "vcpkg" / "ports" / "boringssl"
    required_files = (
        "portfile.cmake",
        "vcpkg.json",
        "install-pc-files.cmake",
        "openssl.pc.in",
        "usage",
        "0001-remove-WX-Werror.patch",
        "0002-clash-native-overlay-marker.patch",
        "0003-chrome-client-hello-profile.patch",
        "0004-client-hello-mutator.patch",
    )
    missing = [name for name in required_files if not (boringssl_port / name).is_file()]
    if missing:
        raise RuntimeError(
            "Project BoringSSL overlay is incomplete; missing: " + ", ".join(missing)
        )
    return botan_port.parent


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
        cmake = resolve_program(
            "cmake",
            [
                PROJECT_ROOT / ".pixi" / "envs" / "default" / "Library" / "bin" / "cmake.exe",
            ],
            prefer_candidates=True,
        )
        ninja = resolve_program(
            "ninja",
            [
                PROJECT_ROOT / ".pixi" / "envs" / "default" / "Library" / "bin" / "ninja.exe",
                PROJECT_ROOT / ".pixi" / "envs" / "default" / "Scripts" / "ninja.exe",
            ],
            prefer_candidates=True,
        )
        toolchain = prepare_windows_clang(
            arguments.llvm_root,
            arguments.vs_installation,
        )
        environment = toolchain.environment.copy()
        environment["CLASH_NATIVE_TARGET_ARCHITECTURE"] = arguments.architecture

        vcpkg_root = ensure_vcpkg(
            arguments.vcpkg_root,
            arguments.update_vcpkg,
            environment,
        )
        overlay_ports = prepare_vcpkg_ports()

        build_dir = (
            arguments.build_dir
            if arguments.build_dir is not None
            else PROJECT_ROOT
            / "build"
            / "windows-clang-cl-x64"
        ).expanduser()
        if not build_dir.is_absolute():
            build_dir = PROJECT_ROOT / build_dir
        build_dir = build_dir.resolve()
        build_dir.mkdir(parents=True, exist_ok=True)

        toolchain_file = (
            vcpkg_root / "scripts" / "buildsystems" / "vcpkg.cmake"
        ).resolve()
        triplet = "x64-windows-clang-cl"
        has_cached_toolchain = validate_build_cache(build_dir, toolchain_file, triplet)

        configure_command = [
            str(cmake),
            "-S",
            cmake_path(PROJECT_ROOT),
            "-B",
            cmake_path(build_dir),
            "-G",
            "Ninja",
            f"-DCMAKE_MAKE_PROGRAM={cmake_path(ninja)}",
            f"-DVCPKG_TARGET_TRIPLET={triplet}",
            f"-DVCPKG_OVERLAY_TRIPLETS={cmake_path(PROJECT_ROOT / 'triplets')}",
            f"-DVCPKG_OVERLAY_PORTS={cmake_path(overlay_ports)}",
            "-DVCPKG_MANIFEST_MODE=ON",
            f"-DCMAKE_C_COMPILER={cmake_path(toolchain.clang_cl)}",
            f"-DCMAKE_CXX_COMPILER={cmake_path(toolchain.clang_cl)}",
            f"-DCMAKE_LINKER={cmake_path(toolchain.msvc_link)}",
            f"-DCMAKE_RC_COMPILER={cmake_path(toolchain.resource_compiler)}",
            f"-DCMAKE_BUILD_TYPE={arguments.build_type}",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ]
        if not has_cached_toolchain:
            configure_command.insert(
                7, f"-DCMAKE_TOOLCHAIN_FILE={cmake_path(toolchain_file)}"
            )
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
            environment["CLASH_NATIVE_HTTP_TUNNEL_CLIENT"] = str(
                build_dir / "clash-native-http-tunnel-client.exe"
            )
            environment["CLASH_NATIVE_GRPC_CLIENT"] = str(
                build_dir / "clash-native-grpc-client.exe"
            )
            environment["CLASH_NATIVE_WEBSOCKET_CLIENT"] = str(
                build_dir / "clash-native-websocket-client.exe"
            )
            # Go's HTTP/2 server disables Extended CONNECT by default.
            godebug = [
                setting
                for setting in environment.get("GODEBUG", "").split(",")
                if setting and setting.split("=", 1)[0] != "http2xconnect"
            ]
            godebug.append("http2xconnect=1")
            environment["GODEBUG"] = ",".join(godebug)
            interop_dir = PROJECT_ROOT / "tests" / "interop"
            interop_binary = build_dir / "clash-native-interop-tests.exe"
            # Keep a stable test executable path so Windows firewall approval is
            # attached to one binary instead of a new temporary go test image
            # on every invocation.
            run(
                [str(go), "test", "-c", "-o", str(interop_binary), "."],
                environment,
                cwd=interop_dir,
            )
            run(
                [str(interop_binary), "-test.count=1"],
                environment,
                cwd=interop_dir,
            )
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        return 1

    print(f"Build completed successfully: {build_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
