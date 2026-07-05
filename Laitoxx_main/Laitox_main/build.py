#!/usr/bin/env python3
"""
Build script for LAITOXX-DDoS — compiles the C++ native engine.

Usage:
    python build.py          # build
    python build.py clean    # remove build artifacts
"""

import os
import sys
import platform
import subprocess
import shutil
from pathlib import Path

HERE      = Path(__file__).resolve().parent   # project root (gui/)
BIN_DIR   = HERE / "bin"                      # compiled output
BUILD_DIR = HERE / "_build"                   # cmake working dir


def log(msg):  print(f"[BUILD] {msg}")
def err(msg):  print(f"[ERROR] {msg}", file=sys.stderr); sys.exit(1)


def run(cmd, cwd=None):
    log("Running: " + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.stdout: print(r.stdout, end="")
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        err(f"Command failed (exit {r.returncode})")
    return r


def build_cpp():
    log("Building C++ engine...")

    BUILD_DIR.mkdir(exist_ok=True)
    BIN_DIR.mkdir(exist_ok=True)

    try:
        import pybind11
        pb11_cmake = Path(pybind11.__file__).parent / "share" / "cmake" / "pybind11"
        log(f"pybind11: {pybind11.__file__}")
    except ImportError:
        err("pybind11 not found — run: pip install pybind11")

    cmake_args = [
        "cmake", str(HERE),                   # CMakeLists.txt lives here
        f"-Dpybind11_DIR={pb11_cmake}",
    ]

    if platform.system() == "Windows":
        gcc = shutil.which("gcc")
        if gcc:
            log(f"Using MinGW gcc: {gcc}")
            cmake_args += ["-G", "MinGW Makefiles"]
        else:
            cmake_args += ["-G", "Visual Studio 17 2022", "-A", "x64"]

    run(cmake_args, cwd=BUILD_DIR)
    run(["cmake", "--build", ".", "--config", "Release"], cwd=BUILD_DIR)

    # Locate built .pyd / .so
    pattern = "laitoxx_core*.pyd" if platform.system() == "Windows" else "laitoxx_core*.so"
    candidates = (
        list((BUILD_DIR / "Release").glob(pattern)) +
        list(BUILD_DIR.glob(pattern))
    )
    if not candidates:
        err(f"Built module not found in {BUILD_DIR}")

    for pyd in candidates:
        dest = BIN_DIR / pyd.name
        shutil.copy2(pyd, dest)
        log(f"Copied -> {dest}")

    # Copy MinGW runtime DLLs
    if platform.system() == "Windows":
        gcc = shutil.which("gcc")
        if gcc:
            gcc_bin = Path(gcc).parent
            for dll in ["libgcc_s_seh-1.dll", "libstdc++-6.dll", "libwinpthread-1.dll"]:
                src = gcc_bin / dll
                if src.exists():
                    shutil.copy2(src, BIN_DIR / dll)
                    log(f"Copied runtime DLL -> {BIN_DIR / dll}")

    log("C++ engine built successfully.")


def build_go_bypass():
    """Build go_bypass/ as a Windows DLL into bin/."""
    log("Building Go bypass DLL...")

    go_dir = HERE / "go_bypass"
    if not go_dir.exists():
        log("go_bypass/ directory not found — skipping Go bypass build")
        return

    go_exe = shutil.which("go")
    if not go_exe:
        log("WARNING: 'go' not found in PATH — skipping Go bypass build")
        return

    BIN_DIR.mkdir(exist_ok=True)

    env = os.environ.copy()
    env["GONOSUMDB"] = "*"
    env["GOFLAGS"] = "-mod=mod"
    if platform.system() == "Windows":
        env["GOOS"] = "windows"
        env["GOARCH"] = "amd64"
        out_name = "bypass.dll"
    else:
        out_name = "bypass.so"

    out_path = BIN_DIR / out_name
    cmd = ["go", "build", "-buildmode=c-shared", f"-o={out_path}", "."]
    log("Running: " + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd, cwd=go_dir, env=env, capture_output=True, text=True)
    if r.stdout:
        print(r.stdout, end="")
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        log(f"WARNING: Go bypass build failed (exit {r.returncode}) — continuing without it")
        return
    log(f"Go bypass DLL -> {out_path}")


def clean():
    log("Cleaning build artifacts...")
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
        log(f"Removed {BUILD_DIR}")
    for f in BIN_DIR.glob("laitoxx_core*"):
        f.unlink()
        log(f"Removed {f}")
    for f in BIN_DIR.glob("bypass.*"):
        f.unlink()
        log(f"Removed {f}")
    log("Clean done.")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
        return

    log(f"Platform : {platform.system()} {platform.machine()}")
    log(f"Python   : {sys.version}")

    build_cpp()
    build_go_bypass()

    log("")
    log("=" * 55)
    log("BUILD SUCCESSFUL")
    log("=" * 55)
    log(f"Compiled modules -> {BIN_DIR}")
    log("Run the tool     : python console_app.py")


if __name__ == "__main__":
    main()
