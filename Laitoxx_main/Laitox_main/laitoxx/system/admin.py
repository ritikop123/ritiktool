"""Administrator privilege detection and UAC elevation."""

import ctypes
import os
import sys


def is_admin() -> bool:
    if sys.platform != "win32":
        return os.getuid() == 0
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Relaunch the current process elevated via UAC.

    Returns ``True`` if the elevated process was started successfully
    (caller should then exit the current process).
    """
    if sys.platform != "win32":
        return False
    try:
        params = " ".join(f'"{a}"' for a in sys.argv)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1  # SW_SHOWNORMAL
        )
        return int(rc) > 32
    except Exception:
        return False


def prompt_relaunch_as_admin(attack_name: str = "") -> None:
    """Interactive UAC elevation prompt (Rich console).

    Prints a warning panel and, if the user agrees, relaunches elevated.
    Import is deferred to avoid a hard dependency on Rich in non-TUI contexts.
    """
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm
    from rich.markup import escape

    con = Console()
    con.print()
    con.print(Panel(
        f"[bold yellow]⚡ Administrator Required[/bold yellow]\n\n"
        f"[white]{escape(attack_name)}[/white] uses raw sockets and requires "
        f"[bold]Administrator[/bold] privileges.\n\n"
        f"Restart now as Administrator?",
        border_style="yellow", expand=False,
    ))
    try:
        answer = Confirm.ask("[yellow]Relaunch as Administrator[/yellow]", default=True)
    except (EOFError, KeyboardInterrupt):
        answer = False

    if not answer:
        return

    con.print("[dim]Requesting elevation via UAC…[/dim]")
    if relaunch_as_admin():
        con.print("[green]Elevated process started. This window will close.[/green]")
        sys.exit(0)
    else:
        con.print(
            "[red]UAC elevation failed or was denied.[/red]\n"
            "[dim]Right-click the script and choose 'Run as administrator'.[/dim]"
        )
