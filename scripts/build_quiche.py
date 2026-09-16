#!/usr/bin/env python3
"""Build the vendored QUICHE core with LLVM clang-cl and MSVC libraries."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from windows_clang import prepare_windows_clang


PROJECT_ROOT = Path(__file__).resolve().parents[1]
QUICHE_ROOT = PROJECT_ROOT / "third_party" / "quiche"
DEFAULT_BAZELISK = PROJECT_ROOT / "build" / "quiche-tools" / "bazelisk.exe"
RULES_CC_CONFIGURE_RELATIVE_PATH = (
    Path("external")
    / "rules_cc+"
    / "cc"
    / "private"
    / "toolchain"
    / "windows_cc_configure.bzl"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--msys2-root",
        type=Path,
        default=None,
        help="MSYS2 installation root for Bazel Bash; MSYS2_ROOT is used when omitted",
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
        "--bazelisk",
        type=Path,
        default=None,
        help=(
            "Bazelisk executable; build/quiche-tools/bazelisk.exe or PATH "
            "is used when omitted"
        ),
    )
    return parser.parse_args()


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


def resolve_bazelisk(explicit_path: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit_path is not None:
        candidates.append(explicit_path)
    candidates.append(DEFAULT_BAZELISK)

    for candidate in candidates:
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        if candidate.is_file():
            return candidate.resolve()

    for name in ("bazelisk.exe", "bazelisk"):
        on_path = shutil.which(name)
        if on_path:
            return Path(on_path).resolve()

    searched = ", ".join(str(path) for path in candidates)
    raise RuntimeError(
        f"Could not find Bazelisk. Searched: {searched} and PATH."
    )


def format_command(command: list[str]) -> str:
    return subprocess.list2cmdline(command)


def run(
    command: list[str],
    environment: dict[str, str],
    *,
    capture_output: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    print("+", format_command(command), flush=True)
    result = subprocess.run(
        command,
        cwd=QUICHE_ROOT,
        env=environment,
        check=False,
        capture_output=capture_output,
        text=True,
    )
    if capture_output:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, command)
    return result


def bazel_repository_arguments(
    llvm_root: Path,
    bazel_sh: Path | None,
) -> list[str]:
    arguments = [
        "--repo_env=BAZEL_LLVM=" + str(llvm_root),
        "--repo_env=USE_CLANG_CL=1",
    ]
    if bazel_sh is not None:
        arguments.append("--repo_env=BAZEL_SH=" + str(bazel_sh))
    return arguments


def query_output_base(
    bazelisk: Path,
    environment: dict[str, str],
    llvm_root: Path,
    bazel_sh: Path | None,
) -> Path:
    result = run(
        [
            str(bazelisk),
            "info",
            "output_base",
            *bazel_repository_arguments(llvm_root, bazel_sh),
        ],
        environment,
        capture_output=True,
    )
    output_base_lines = [
        line.strip() for line in result.stdout.splitlines() if line.strip()
    ]
    if not output_base_lines:
        raise RuntimeError("Bazel did not report an output base.")
    return Path(output_base_lines[-1]).resolve()


def find_rules_cc_configure(output_base: Path) -> Path | None:
    direct_path = output_base / RULES_CC_CONFIGURE_RELATIVE_PATH
    if direct_path.is_file():
        return direct_path

    external_root = output_base / "external"
    if not external_root.is_dir():
        return None
    matches = sorted(
        external_root.glob(
            "rules_cc*/cc/private/toolchain/windows_cc_configure.bzl"
        )
    )
    return matches[0] if matches else None


def materialize_rules_cc(
    bazelisk: Path,
    environment: dict[str, str],
    llvm_root: Path,
    output_base: Path,
    bazel_sh: Path | None,
) -> Path:
    configure_file = find_rules_cc_configure(output_base)
    if configure_file is not None:
        return configure_file

    result = run(
        [
            str(bazelisk),
            "fetch",
            "@rules_cc//:all",
            *bazel_repository_arguments(llvm_root, bazel_sh),
            "--experimental_convenience_symlinks=ignore",
        ],
        environment,
        capture_output=True,
        check=False,
    )
    configure_file = find_rules_cc_configure(output_base)
    if configure_file is None:
        raise RuntimeError(
            "Bazel could not materialize the rules_cc toolchain source "
            f"(fetch exit code {result.returncode})."
        )
    if result.returncode != 0:
        print(
            "Bazel dependency materialization reported an error, but the "
            "rules_cc source is available; continuing with the toolchain "
            "patch.",
            file=sys.stderr,
        )
    return configure_file


def patch_rules_cc_configure(configure_file: Path) -> None:
    content = configure_file.read_text(encoding="utf-8")
    original_content = content

    dumpbin_line = (
        '        build_tools["DUMPBIN"] = '
        'find_msvc_tool(repository_ctx, vc_path, "dumpbin.exe", "x64")\n'
    )
    if 'build_tools["DUMPBIN"] = find_msvc_tool' not in content:
        lib_line = (
            '        build_tools["LIB"] = '
            'find_llvm_tool(repository_ctx, llvm_path, "llvm-lib.exe")\n'
        )
        if lib_line not in content:
            raise RuntimeError(
                f"Unsupported rules_cc toolchain source: {configure_file}"
            )
        content = content.replace(lib_line, lib_line + dumpbin_line, 1)

    old_version_line = '    return first_line.split(" ")[-1]\n'
    new_version_lines = (
        "    # MSYS2 appends a parenthesized repository revision after the version.\n"
        '    version_start = first_line.find("clang version ") + len("clang version ")\n'
        '    return first_line[version_start:].split(" ")[0]\n'
    )
    if old_version_line in content:
        content = content.replace(old_version_line, new_version_lines, 1)

    if content != original_content:
        configure_file.write_text(content, encoding="utf-8", newline="\n")
        print(f"Patched generated rules_cc toolchain source: {configure_file}")


def main() -> int:
    arguments = parse_args()
    try:
        if os.name != "nt":
            raise RuntimeError(
                "This build script currently supports Windows x86-64 only."
            )

        if not (QUICHE_ROOT / "MODULE.bazel").is_file():
            raise RuntimeError(f"Vendored QUICHE source is missing: {QUICHE_ROOT}")

        bazel_sh = None
        if arguments.msys2_root is not None or os.environ.get("MSYS2_ROOT"):
            msys2_root = resolve_msys2_root(arguments.msys2_root)
            bazel_sh = msys2_root / "usr" / "bin" / "bash.exe"
            if not bazel_sh.is_file():
                raise RuntimeError(f"MSYS2 Bash is missing: {bazel_sh}")

        toolchain = prepare_windows_clang(
            arguments.llvm_root,
            arguments.vs_installation,
        )

        bazelisk = resolve_bazelisk(arguments.bazelisk)
        environment = toolchain.environment.copy()
        if bazel_sh is not None:
            environment["PATH"] = os.pathsep.join(
                [environment.get("PATH", ""), str(bazel_sh.parent)]
            )
            environment["BAZEL_SH"] = str(bazel_sh)
        llvm_root = toolchain.llvm_root
        environment["USE_CLANG_CL"] = "1"
        environment["BAZEL_LLVM"] = str(llvm_root)

        output_base = query_output_base(
            bazelisk,
            environment,
            llvm_root,
            bazel_sh,
        )
        configure_file = materialize_rules_cc(
            bazelisk,
            environment,
            llvm_root,
            output_base,
            bazel_sh,
        )
        patch_rules_cc_configure(configure_file)

        command = [
            str(bazelisk),
            "build",
            "//quiche:quiche_core",
            "--platforms=//:x64_windows-clang-cl",
            "--extra_execution_platforms=//:x64_windows-clang-cl",
            "--extra_toolchains=@local_config_cc//:cc-toolchain-x64_windows-clang-cl",
            *bazel_repository_arguments(llvm_root, bazel_sh),
            "--@com_google_googleurl//build_config:system_icu=0",
            "--cxxopt=/std:c++20",
            "--host_cxxopt=/std:c++20",
            "--experimental_convenience_symlinks=ignore",
            "--verbose_failures",
        ]
        run(command, environment)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"QUICHE build failed: {error}", file=sys.stderr)
        return 1

    print("QUICHE core build completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
