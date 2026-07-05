#!/usr/bin/env python3
"""
Build the Avalonia GUI and copy the output exe to gui/ directory.

Usage:
    python build_gui.py          # publish release exe -> gui/LaitoxxGui.exe
    python build_gui.py clean    # remove _gui_publish/ and LaitoxxGui.exe
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

HERE       = Path(__file__).resolve().parent   # gui/
GUI_SRC    = HERE / "avalonia_gui"
PUBLISH    = HERE / "_gui_publish"
EXE_DEST   = HERE / "LaitoxxGui.exe"


def log(msg): print(f"[GUI BUILD] {msg}")
def err(msg): print(f"[ERROR] {msg}", file=sys.stderr); sys.exit(1)


def build():
    dotnet = shutil.which("dotnet")
    if not dotnet:
        err("'dotnet' not found in PATH. Install .NET SDK 6+.")

    log("Publishing Avalonia GUI (self-contained, win-x64)...")
    PUBLISH.mkdir(exist_ok=True)

    cmd = [
        dotnet, "publish",
        str(GUI_SRC / "LaitoxxGui.csproj"),
        "-c", "Release",
        "-r", "win-x64",
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-o", str(PUBLISH),
    ]

    log("Running: " + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd, capture_output=False, text=True)
    if r.returncode != 0:
        err(f"dotnet publish failed (exit {r.returncode})")

    # Find the built exe
    candidates = list(PUBLISH.glob("LaitoxxGui.exe"))
    if not candidates:
        err(f"LaitoxxGui.exe not found in {PUBLISH}")

    src = candidates[0]
    shutil.copy2(src, EXE_DEST)
    log(f"Copied -> {EXE_DEST}")

    log("")
    log("=" * 55)
    log("GUI BUILD SUCCESSFUL")
    log("=" * 55)
    log(f"Executable : {EXE_DEST}")
    log("Run        : LaitoxxGui.exe")


def clean():
    log("Cleaning GUI build artifacts...")
    if PUBLISH.exists():
        shutil.rmtree(PUBLISH)
        log(f"Removed {PUBLISH}")
    if EXE_DEST.exists():
        EXE_DEST.unlink()
        log(f"Removed {EXE_DEST}")
    log("Clean done.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
    else:
        build()
