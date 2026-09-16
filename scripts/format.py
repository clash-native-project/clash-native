#!/usr/bin/env python3
"""Format or validate the project's C and C++ sources."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORIES = ("include", "src", "tests")
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check formatting without modifying files",
    )
    return parser.parse_args()


def resolve_clang_format() -> Path:
    on_path = shutil.which("clang-format")
    if on_path:
        return Path(on_path).resolve()

    pixi_path = (
        PROJECT_ROOT
        / ".pixi"
        / "envs"
        / "default"
        / "Library"
        / "bin"
        / "clang-format.exe"
    )
    if pixi_path.is_file():
        return pixi_path.resolve()

    raise RuntimeError(
        "Could not find clang-format. Run this command through the Pixi environment."
    )


def source_files() -> list[Path]:
    files: list[Path] = []
    for directory in SOURCE_DIRECTORIES:
        root = PROJECT_ROOT / directory
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
        )
    return sorted(files)


def main() -> int:
    arguments = parse_args()
    try:
        clang_format = resolve_clang_format()
        files = source_files()
        if not files:
            raise RuntimeError("No project C or C++ source files were found.")

        command = [str(clang_format)]
        if arguments.check:
            command.extend(("--dry-run", "--Werror"))
        else:
            command.append("-i")
        command.extend(str(path) for path in files)
        print("+", subprocess.list2cmdline(command), flush=True)
        return subprocess.run(command, cwd=PROJECT_ROOT, check=False).returncode
    except (OSError, RuntimeError) as error:
        print(f"Formatting failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
