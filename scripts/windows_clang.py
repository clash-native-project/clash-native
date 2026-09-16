#!/usr/bin/env python3
"""Resolve the standalone LLVM clang-cl and the installed MSVC environment."""

from __future__ import annotations

from dataclasses import dataclass
import locale
import os
from pathlib import Path
import shutil
import subprocess


@dataclass(frozen=True)
class WindowsClangToolchain:
    llvm_root: Path
    clang_cl: Path
    lld_link: Path
    msvc_link: Path
    resource_compiler: Path
    environment: dict[str, str]


def _valid_llvm_root(candidate: Path) -> Path | None:
    candidate = candidate.expanduser()
    if candidate.is_file() and candidate.name.lower() == "clang-cl.exe":
        candidate = candidate.parent.parent
    if (candidate / "bin" / "clang-cl.exe").is_file():
        return candidate.resolve()
    return None


def resolve_llvm_root(explicit_root: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit_root is not None:
        candidates.append(explicit_root)
    for variable in ("LLVM_ROOT", "LLVM_INSTALL_DIR"):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value))
    candidates.extend(
        [
            Path(r"C:\Program Files\LLVM"),
            Path(r"C:\Program Files (x86)\LLVM"),
        ]
    )

    clang_cl = shutil.which("clang-cl.exe")
    if clang_cl:
        candidates.append(Path(clang_cl).parent.parent)

    for candidate in candidates:
        resolved = _valid_llvm_root(candidate)
        if resolved is not None:
            return resolved

    searched = ", ".join(str(candidate) for candidate in candidates)
    raise RuntimeError(
        "Could not find standalone LLVM clang-cl. "
        f"Searched: {searched}. Pass --llvm-root or set LLVM_ROOT."
    )


def _valid_vs_installation(candidate: Path) -> Path | None:
    candidate = candidate.expanduser()
    if (candidate / "VC" / "Auxiliary" / "Build" / "vcvars64.bat").is_file():
        return candidate.resolve()
    return None


def resolve_vs_installation(explicit_path: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit_path is not None:
        candidates.append(explicit_path)

    for variable in ("VSINSTALLDIR", "VS_INSTALLATION"):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value))

    vswhere_candidates = [
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"),
        Path(r"C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"),
    ]
    vswhere = next(
        (candidate for candidate in vswhere_candidates if candidate.is_file()),
        None,
    )
    if vswhere is None:
        on_path = shutil.which("vswhere.exe")
        if on_path:
            vswhere = Path(on_path)

    if vswhere is not None:
        result = subprocess.run(
            [
                str(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
        )
        candidates.extend(
            Path(line.strip())
            for line in result.stdout.splitlines()
            if line.strip()
        )

    for root in (
        Path(r"C:\Program Files\Microsoft Visual Studio"),
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio"),
    ):
        if root.is_dir():
            candidates.extend(root.glob("*/*"))

    for candidate in candidates:
        resolved = _valid_vs_installation(candidate)
        if resolved is not None:
            return resolved

    searched = ", ".join(str(candidate) for candidate in candidates)
    raise RuntimeError(
        "Could not find a Visual Studio installation with vcvars64.bat. "
        f"Searched: {searched}. Pass --vs-installation or set VSINSTALLDIR."
    )


def _load_msvc_environment(vs_installation: Path) -> dict[str, str]:
    vcvars = vs_installation / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    command = f'call "{vcvars}" >nul 2>&1 && set'
    result = subprocess.run(
        f"cmd.exe /d /c {command}",
        check=False,
        capture_output=True,
        text=True,
        encoding=locale.getpreferredencoding(False),
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"MSVC environment setup failed with exit code {result.returncode}: "
            f"{vcvars}"
        )

    environment = os.environ.copy()
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key and not key.startswith("="):
            environment[key] = value
    return environment


def prepare_windows_clang(
    explicit_llvm_root: Path | None = None,
    explicit_vs_installation: Path | None = None,
) -> WindowsClangToolchain:
    llvm_root = resolve_llvm_root(explicit_llvm_root)
    vs_installation = resolve_vs_installation(explicit_vs_installation)
    environment = _load_msvc_environment(vs_installation)

    llvm_bin = llvm_root / "bin"
    vc_tools = Path(environment["VCToolsInstallDir"])
    vc_bin = vc_tools / "bin" / "Hostx64" / "x64"
    sdk_dir = Path(environment["WindowsSdkDir"])
    sdk_version = environment["WindowsSDKVersion"].strip("\\/")
    sdk_bin = sdk_dir / "bin" / sdk_version / "x64"

    clang_cl = llvm_bin / "clang-cl.exe"
    lld_link = llvm_bin / "lld-link.exe"
    msvc_link = vc_bin / "link.exe"
    resource_compiler = sdk_bin / "rc.exe"
    required_tools = [clang_cl, lld_link, msvc_link, resource_compiler]
    missing = [str(path) for path in required_tools if not path.is_file()]
    if missing:
        raise RuntimeError(
            "The Windows clang-cl toolchain is incomplete. Missing: "
            + ", ".join(missing)
        )

    environment["PATH"] = os.pathsep.join(
        [str(llvm_bin), str(vc_bin), str(sdk_bin), environment.get("PATH", "")]
    )
    environment["CC"] = str(clang_cl)
    environment["CXX"] = str(clang_cl)
    environment["BAZEL_LLVM"] = str(llvm_root)
    environment["USE_CLANG_CL"] = "1"

    return WindowsClangToolchain(
        llvm_root=llvm_root,
        clang_cl=clang_cl.resolve(),
        lld_link=lld_link.resolve(),
        msvc_link=msvc_link.resolve(),
        resource_compiler=resource_compiler.resolve(),
        environment=environment,
    )
