#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LaitoxxDDoS Control Panel v2.0 — entrypoint.

All logic lives in the `laitoxx` package next to this file.
"""

import os
import sys

# ── stdout/stderr line-buffering ─────────────────────────────────────────
# Must happen before any print() so GUI subprocess readers receive output
# immediately without waiting for a full buffer flush.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(line_buffering=True)
        except Exception:
            pass

# ── Native engine path bootstrap ─────────────────────────────────────────
# Add bin/ so laitoxx_core.pyd is importable, and add project root as
# fallback.  Also register bin/ as a Windows DLL search directory so the
# MinGW runtime DLLs bundled there are found automatically.
_ROOT = os.path.dirname(os.path.abspath(__file__))

for _p in (os.path.join(_ROOT, "bin"), _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

if sys.platform == "win32":
    _bin = os.path.join(_ROOT, "bin")
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(_bin)
    os.environ["PATH"] = _bin + os.pathsep + os.environ.get("PATH", "")

# ── Optional C++ engine initialisation ───────────────────────────────────
try:
    import laitoxx_core
    laitoxx_core.initialize_native()
except ImportError:
    pass

# ── Dispatch ─────────────────────────────────────────────────────────────

from laitoxx.cli.pipeline import build_arg_parser, run as run_pipeline
from laitoxx.system.admin import is_admin, relaunch_as_admin


def main() -> None:
    parser = build_arg_parser()

    if len(sys.argv) > 1:
        # CLI / pipeline mode — used by the Avalonia GUI subprocess
        args = parser.parse_args()
        sys.exit(run_pipeline(args))

    # Interactive TUI mode
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm

    console = Console()

    if not is_admin():
        console.print(Panel(
            "[bold yellow]⚡ Not running as Administrator[/bold yellow]\n\n"
            "L2/L3/L4 raw-socket attacks require elevated privileges and will be skipped.\n\n"
            "You can continue without them, or restart elevated now.",
            border_style="yellow", expand=False,
        ))
        try:
            answer = Confirm.ask("[yellow]Relaunch as Administrator?[/yellow]", default=False)
        except (EOFError, KeyboardInterrupt):
            answer = False
        if answer:
            if relaunch_as_admin():
                console.print("[green]Elevated process started.[/green]")
                sys.exit(0)
            else:
                console.print("[red]Elevation failed or denied — continuing without admin.[/red]")
        console.print()

    try:
        from laitoxx.ui.app import ConsoleApp
        # Pass --unsafe / --i-know-what-im-doing through to TUI if user typed it
        # without any other args (edge-case: `python console_app.py --unsafe`)
        _unsafe_tui = "--unsafe" in sys.argv or "--i-know-what-im-doing" in sys.argv
        ConsoleApp(unsafe=_unsafe_tui).run()
    except KeyboardInterrupt:
        Console().print("\n[bold]Interrupted. Bye.[/bold]")
        sys.exit(0)


if __name__ == "__main__":
    main()
