#!/usr/bin/env python3
"""Configure and build clash-native on Debian WSL with pixi clang + ASan.

Linux-only one-shot driver (not wired into pixi tasks): resolves the pixi
linux-64 env under .pixi-linux/, bootstraps a separate vcpkg checkout for
Linux (never the Windows .tools/vcpkg), configures with the pixi clang 23
toolchain + x64-linux triplet + overlay triplets/ports, enables ASan+UBSan,
then builds. CTest is left to the caller so target filters stay flexible.

Usage (inside Debian WSL, from the repo root on /mnt/d/...):
    python3 scripts/build_linux_asan.py [--build-dir build/debian-clang-x64-asan]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VCPKG_REPOSITORY = "https://github.com/microsoft/vcpkg.git"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path("build/debian-clang-x64-asan"),
        help="CMake build directory (default: build/debian-clang-x64-asan)",
    )
    parser.add_argument(
        "--build-type",
        choices=("Debug", "Release", "RelWithDebInfo", "MinSizeRel"),
        default="RelWithDebInfo",
        help="CMake build type (default: RelWithDebInfo)",
    )
    parser.add_argument(
        "--vcpkg-root",
        type=Path,
        default=None,
        help="Linux vcpkg checkout (default: .tools/vcpkg-linux)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Build parallelism (default: nproc)",
    )
    parser.add_argument(
        "--configure-only",
        action="store_true",
        help="Stop after CMake configure (skip the build)",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="CMake build target (repeatable; default: all)",
    )
    return parser.parse_args()


def run(command: list[str], environment: dict[str, str], *, cwd: Path) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def resolve_pixi_env() -> Path:
    override = os.environ.get("LINUX_PIXI_ENV")
    if override:
        candidate = Path(override)
        if (candidate / "bin" / "clang++").is_file():
            return candidate
        raise RuntimeError(f"LINUX_PIXI_ENV has no bin/clang++: {candidate}")
    roots = sorted((PROJECT_ROOT / ".pixi-linux").glob("*/envs/default"))
    for root in roots:
        if (root / "bin" / "clang++").is_file():
            return root
    raise RuntimeError(
        "No pixi linux-64 env with bin/clang++ under .pixi-linux/; "
        "run `pixi install` inside Debian WSL first."
    )


def ensure_vcpkg(root: Path, environment: dict[str, str]) -> Path:
    if not root.exists():
        root.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", VCPKG_REPOSITORY, str(root)], environment, cwd=root.parent)
    executable = root / "vcpkg"
    bootstrap = root / "bootstrap-vcpkg.sh"
    if not executable.is_file():
        if not bootstrap.is_file():
            raise RuntimeError(f"vcpkg bootstrap script is missing: {bootstrap}")
        run(["sh", str(bootstrap), "-disableMetrics"], environment, cwd=root)
    if not executable.is_file():
        raise RuntimeError(f"vcpkg bootstrap did not produce: {executable}")
    return root


def main() -> int:
    arguments = parse_args()
    try:
        pixi_env = resolve_pixi_env()
        pixi_bin = pixi_env / "bin"
        cmake = pixi_bin / "cmake"
        ninja = pixi_bin / "ninja"
        cxx = pixi_bin / "clang++"
        cc = pixi_bin / "clang"
        for tool in (cmake, ninja, cxx, cc):
            if not tool.is_file():
                raise RuntimeError(f"Missing pixi tool: {tool}")

        environment = os.environ.copy()
        environment["PATH"] = f"{pixi_bin}{os.pathsep}{environment.get('PATH', '')}"
        environment["CC"] = str(cc)
        environment["CXX"] = str(cxx)

        vcpkg_root = (
            arguments.vcpkg_root.expanduser()
            if arguments.vcpkg_root is not None
            else PROJECT_ROOT / ".tools" / "vcpkg-linux"
        )
        ensure_vcpkg(vcpkg_root, environment)

        build_dir = arguments.build_dir.expanduser()
        if not build_dir.is_absolute():
            build_dir = PROJECT_ROOT / build_dir
        build_dir.mkdir(parents=True, exist_ok=True)

        botan_port = PROJECT_ROOT / "third_party" / "vcpkg" / "ports" / "botan"
        if not (botan_port / "portfile.cmake").is_file():
            raise RuntimeError("Project Botan overlay is incomplete")

        triplet = "x64-linux"
        # conda clang.cfg injects `-isystem <env>/include` (conda OpenSSL
        # lives there) BEFORE command-line flags, so -I reordering cannot
        # beat it. Fix: hide <env>/include/openssl for the duration of the
        # configure+build by renaming it aside, then restore afterwards.
        # Only <env>/include/openssl moves; everything else (libstdcxx via
        # cfg sysroot paths, curl headers, etc.) stays untouched.
        import shutil
        hidden_ssl = pixi_env / "include" / "openssl"
        parked_ssl = pixi_env / "include" / "openssl.hidden-for-boringssl"
        ssl_parked = False
        # 9p/DrvFs (Windows-mounted /mnt/d) does not support rename of a
        # non-empty dir; move the ~200 headers one by one instead.
        if hidden_ssl.is_dir() and not parked_ssl.exists():
            parked_ssl.mkdir(parents=True, exist_ok=True)
            for header in list(hidden_ssl.iterdir()):
                shutil.move(str(header), str(parked_ssl / header.name))
            try:
                hidden_ssl.rmdir()
            except OSError:
                pass
            ssl_parked = True
        configure_command = [
            str(cmake),
            "-S", str(PROJECT_ROOT),
            "-B", str(build_dir),
            "-G", "Ninja",
            f"-DCMAKE_MAKE_PROGRAM={ninja}",
            f"-DCMAKE_TOOLCHAIN_FILE={vcpkg_root / 'scripts' / 'buildsystems' / 'vcpkg.cmake'}",
            f"-DVCPKG_TARGET_TRIPLET={triplet}",
            f"-DVCPKG_OVERLAY_TRIPLETS={PROJECT_ROOT / 'triplets'}",
            f"-DVCPKG_OVERLAY_PORTS={botan_port.parent}",
            "-DVCPKG_MANIFEST_MODE=ON",
            f"-DCMAKE_C_COMPILER={cc}",
            f"-DCMAKE_CXX_COMPILER={cxx}",
            f"-DCMAKE_BUILD_TYPE={arguments.build_type}",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DCLASH_NATIVE_ENABLE_SANITIZERS=ON",
        ]
        run(configure_command, environment, cwd=PROJECT_ROOT)
        if arguments.configure_only:
            if ssl_parked and parked_ssl.is_dir():
                hidden_ssl.mkdir(parents=True, exist_ok=True)
                for header in list(parked_ssl.iterdir()):
                    shutil.move(str(header), str(hidden_ssl / header.name))
                try:
                    parked_ssl.rmdir()
                except OSError:
                    pass
                ssl_parked = False
            print(f"Configure completed: {build_dir}")
            return 0

        build_command = [str(cmake), "--build", str(build_dir)]
        if arguments.jobs:
            build_command += ["--parallel", str(arguments.jobs)]
        else:
            build_command += ["--parallel"]
        for target in arguments.target:
            build_command += ["--target", target]
        run(build_command, environment, cwd=PROJECT_ROOT)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Build failed: {error}", file=sys.stderr)
        return 1
    finally:
        if ssl_parked and parked_ssl.is_dir():
            hidden_ssl.mkdir(parents=True, exist_ok=True)
            for header in list(parked_ssl.iterdir()):
                shutil.move(str(header), str(hidden_ssl / header.name))
            try:
                parked_ssl.rmdir()
            except OSError:
                pass

    print(f"Build completed successfully: {arguments.build_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
