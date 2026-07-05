"""ConsoleApp — Rich TUI interactive controller."""

import sys
import time
import threading
import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt, IntPrompt, Confirm
from rich import box
from rich.rule import Rule
from rich.markup import escape

from ..core.taxonomy import ATTACK_CATEGORIES, ATTACK_NAME_MAP, RAW_SOCKET_ATTACKS, ATTACK_TO_CATEGORY, L7_CATEGORIES
from ..core.validation import is_l7_attack
from ..config import settings as _settings_mod
from ..config import proxies as _proxies_mod
from ..engine.manager import AttackManager, native_available
from ..engine.instance import AttackInstance
from ..system.admin import is_admin, relaunch_as_admin
from ..core.dns import has_pysocks
from ..poo import (
    check_cached, verify_dns, verify_reverse, unsafe_bypass,
    is_verified, all_verified, revoke, generate,
    VerificationResult,
)
from ..poo.dns_verify import txt_record_name, has_dnspython
from ..poo.reverse_verify import get_local_ip, DEFAULT_TIMEOUT
from .formatters import (
    BANNER, LOG_LEVEL_STYLES,
    format_pps, format_bps, format_duration, clamp,
)

console = Console()


class ConsoleApp:
    def __init__(self, unsafe: bool = False) -> None:
        self.settings = _settings_mod.load()
        self.proxies  = _proxies_mod.load()
        self.unsafe   = unsafe
        self.manager  = AttackManager(self.settings, self.proxies, unsafe=unsafe)
        self._running = True
        self._ticker  = threading.Thread(target=self._tick_loop, daemon=True)
        self._ticker.start()

    # ── Background ticker ─────────────────────────────────────────────────

    def _tick_loop(self) -> None:
        while self._running:
            self.manager.tick()
            time.sleep(1)

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self) -> None:
        while self._running:
            self._show_main_menu()

    def _show_main_menu(self) -> None:
        console.clear()
        engine = "Native C++" if native_available() else "Mock"
        console.print(BANNER.format(engine=engine, platform=sys.platform))

        running = self.manager.get_running()
        status  = (f"[bold green]{len(running)} active[/bold green]"
                   if running else "[dim]No active attacks[/dim]")

        summary = Table(show_header=False, box=box.SIMPLE_HEAVY, expand=True,
                        border_style="cyan", pad_edge=True, padding=(0, 2))
        summary.add_column(justify="center")
        summary.add_row(
            f"[bold]Active:[/bold] {status}  |  "
            f"PPS: [cyan]{format_pps(self.manager.total_pps)}[/cyan]  |  "
            f"BPS: [green]{format_bps(self.manager.total_bps)}[/green]  |  "
            f"Conns: [yellow]{self.manager.total_connections}[/yellow]"
        )
        console.print(summary)
        console.print()

        menu = Table(show_header=False, box=None, padding=(0, 3))
        menu.add_column(style="bold cyan", justify="right", width=4)
        menu.add_column()
        menu.add_row("1", "[bold]Quick Attack[/bold]     — Launch an attack fast")
        menu.add_row("2", "[bold]Attack Browser[/bold]   — Browse all 50+ methods")
        menu.add_row("3", "[bold]Active Attacks[/bold]   — Monitor & manage running attacks")
        menu.add_row("4", "[bold]Statistics[/bold]        — Session stats & breakdown")
        menu.add_row("5", "[bold]Logs[/bold]             — View event log")
        menu.add_row("6", "[bold]Settings[/bold]         — Configure defaults & network")
        menu.add_row("7", "[bold]Proxies[/bold]          — Manage proxy list")
        poo_count = len(all_verified())
        poo_label = f"[bold]Proof-of-Ownership[/bold]  — Verified targets: [green]{poo_count}[/green]"
        if self.unsafe:
            poo_label += "  [yellow](unsafe mode)[/yellow]"
        menu.add_row("8", poo_label)
        menu.add_row("0", "[bold red]Exit[/bold red]")
        console.print(Panel(menu, title="[bold]Main Menu[/bold]",
                            border_style="bright_blue", box=box.ROUNDED))

        choice = Prompt.ask("[cyan]▸[/cyan]",
                            choices=["0","1","2","3","4","5","6","7","8"],
                            default="1", show_choices=False)
        {
            "1": self._quick_attack,
            "2": self._attack_browser,
            "3": self._active_attacks,
            "4": self._statistics,
            "5": self._logs_view,
            "6": self._settings_menu,
            "7": self._proxies_menu,
            "8": self._poo_menu,
            "0": self._exit,
        }[choice]()

    # ══════════════════════════════════════════════════════════════════════
    #  1. Quick Attack
    # ══════════════════════════════════════════════════════════════════════

    def _quick_attack(self) -> None:
        console.clear()
        console.print(Rule("[bold cyan]Quick Attack[/bold cyan]"))
        console.print()

        result = self._ask_target()
        if result is None:
            Prompt.ask("[dim]Press Enter[/dim]", default="")
            return
        target, ttype = result
        port = IntPrompt.ask("[bold]Port[/bold]", default=self.settings["default_port"])

        # L7 methods need a domain; filter them out for raw IPs
        all_quick = [
            ("HTTP GET Flood",      True),
            ("HTTP POST Flood",     True),
            ("TCP SYN Flood",       False),
            ("UDP Flood",           False),
            ("ICMP Flood",          False),
            ("Cloudflare Bypass",   True),
            ("DDoS-Guard Bypass",   True),
            ("CPS Flood",           False),
            ("STRESS Attack",       True),
            ("HTTP/2 Stream Flood", True),
            ("WebSocket Flood",     True),
            ("KILLER Attack",       True),
        ]
        available = [name for name, needs_domain in all_quick
                     if not (needs_domain and ttype == "ip")]

        if not available:
            console.print("[red]No available methods for this target type[/red]")
            Prompt.ask("[dim]Press Enter[/dim]", default="")
            return

        table = Table(show_header=True, box=box.SIMPLE, border_style="dim")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Method", style="bold")
        table.add_column("Code", style="dim")
        for i, m in enumerate(available, 1):
            table.add_row(str(i), m, ATTACK_NAME_MAP.get(m, "?"))

        if ttype == "ip":
            console.print("[yellow]Target is IP — L7 (HTTP) methods hidden[/yellow]\n")
        console.print(table)

        idx = IntPrompt.ask("[bold]Method #[/bold]", default=1)
        if not 1 <= idx <= len(available):
            console.print("[red]Invalid selection[/red]")
            Prompt.ask("[dim]Press Enter[/dim]", default="")
            return

        method   = available[idx - 1]
        s        = self.settings
        duration = clamp(IntPrompt.ask("[bold]Duration[/bold] (sec)", default=s["default_duration"]), 1, s["max_duration"])
        threads  = clamp(IntPrompt.ask("[bold]Threads[/bold]",        default=s["default_threads"]),  1, s["max_threads"])
        rps      = clamp(IntPrompt.ask("[bold]RPS[/bold]",            default=s["default_rps"]),      1, s["max_rps"])

        console.print()
        console.print(f"[bold]Launching:[/bold] {method} → {target}:{port}  "
                      f"threads={threads} duration={duration}s rps={rps}")

        if Confirm.ask("[yellow]Confirm?[/yellow]", default=True):
            if not self._ensure_ownership(target, method):
                console.print("[red]Cannot launch — target ownership not verified.[/red]")
                Prompt.ask("[dim]Press Enter[/dim]", default="")
                return
            attack = self.manager.start_attack(method, target, port, duration, threads, rps)
            if attack:
                console.print(f"[bold green]✓ Attack #{attack.id} started[/bold green]")
                if self.settings["auto_monitor"]:
                    self._monitor_single(attack)
            else:
                console.print("[bold red]✗ Failed to start attack[/bold red]")

        console.print()
        Prompt.ask("[dim]Press Enter to continue[/dim]", default="")

    # ══════════════════════════════════════════════════════════════════════
    #  2. Attack Browser
    # ══════════════════════════════════════════════════════════════════════

    def _attack_browser(self) -> None:
        while True:
            console.clear()
            console.print(Rule("[bold cyan]Attack Browser[/bold cyan]"))
            console.print()

            cats  = list(ATTACK_CATEGORIES.keys())
            table = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
            table.add_column("#", style="bold cyan", width=4)
            table.add_column("Category", style="bold")
            table.add_column("Attacks", justify="right", style="green")
            for i, cat in enumerate(cats, 1):
                table.add_row(str(i), cat, str(len(ATTACK_CATEGORIES[cat])))
            table.add_row("0", "[dim]Back[/dim]", "")
            console.print(table)

            choice = Prompt.ask("[cyan]▸ Category #[/cyan]", default="0")
            if choice == "0":
                return
            try:
                idx = int(choice) - 1
                if not 0 <= idx < len(cats):
                    raise ValueError
            except ValueError:
                console.print("[red]Invalid[/red]")
                continue

            console.clear()
            self._show_category(cats[idx], ATTACK_CATEGORIES[cats[idx]])

    def _show_category(self, cat_name: str, attacks: dict) -> None:
        console.clear()
        console.print(Rule(f"[bold cyan]{cat_name}[/bold cyan]"))
        console.print()

        table = Table(show_header=True, box=box.SIMPLE_HEAVY, border_style="blue")
        table.add_column("#", style="cyan", width=4)
        table.add_column("Attack", style="bold", min_width=25)
        table.add_column("Code", style="dim", width=12)
        table.add_column("Description")

        attack_list = list(attacks.items())
        for i, (name, (code, desc)) in enumerate(attack_list, 1):
            marker = "⚡" if code in RAW_SOCKET_ATTACKS else ""
            table.add_row(str(i), f"{name} {marker}", code, desc)
        table.add_row("0", "[dim]Back[/dim]", "", "")
        console.print(table)

        if any(code in RAW_SOCKET_ATTACKS for _, (code, _) in attack_list):
            console.print("[dim]⚡ = Requires Administrator privileges[/dim]")
        if cat_name in ("L2 Data Link", "L3 Network") and sys.platform == "win32":
            console.print("[yellow]⚠ L2/L3 attacks use raw sockets — Linux only[/yellow]")

        choice = Prompt.ask("[cyan]▸ Select attack # to launch (0=back)[/cyan]", default="0")
        if choice == "0":
            return
        try:
            idx = int(choice) - 1
            if not 0 <= idx < len(attack_list):
                raise ValueError
        except ValueError:
            console.print("[red]Invalid[/red]")
            return

        self._launch_attack_wizard(attack_list[idx][0])

    def _launch_attack_wizard(self, attack_name: str) -> None:
        console.clear()
        code  = ATTACK_NAME_MAP[attack_name]
        is_l7 = is_l7_attack(attack_name)
        console.print()
        console.print(f"[bold]Configure: {attack_name}[/bold] [dim]({code})[/dim]")
        if is_l7:
            console.print("[dim]L7 attack — requires a domain target[/dim]")
        console.print()

        result = self._ask_target()
        if result is None:
            Prompt.ask("[dim]Press Enter[/dim]", default="")
            return
        target, ttype = result

        if is_l7 and ttype == "ip":
            console.print(
                f"[bold red]✗ {attack_name} is an L7 attack and requires a domain, not an IP.[/bold red]\n"
                "[dim]L7 attacks work at the application layer (HTTP/HTTPS).[/dim]"
            )
            Prompt.ask("[dim]Press Enter[/dim]", default="")
            return

        s        = self.settings
        port     = IntPrompt.ask("[bold]Port[/bold]",     default=s["default_port"])
        duration = clamp(IntPrompt.ask("[bold]Duration[/bold] (sec)", default=s["default_duration"]), 1, s["max_duration"])
        threads  = clamp(IntPrompt.ask("[bold]Threads[/bold]",        default=s["default_threads"]),  1, s["max_threads"])
        rps      = clamp(IntPrompt.ask("[bold]RPS[/bold]",            default=s["default_rps"]),      1, s["max_rps"])

        if Confirm.ask(f"[yellow]Launch {attack_name} → {target}:{port}?[/yellow]", default=True):
            if not self._ensure_ownership(target, attack_name):
                console.print("[red]Cannot launch — target ownership not verified.[/red]")
                Prompt.ask("[dim]Press Enter[/dim]", default="")
                return
            attack = self.manager.start_attack(attack_name, target, port, duration, threads, rps)
            if attack:
                console.print(f"[bold green]✓ Attack #{attack.id} started[/bold green]")
                if self.settings["auto_monitor"] and Confirm.ask("[dim]Monitor?[/dim]", default=True):
                    self._monitor_single(attack)
            else:
                console.print("[bold red]✗ Failed[/bold red]")
                Prompt.ask("[dim]Press Enter[/dim]", default="")

    # ══════════════════════════════════════════════════════════════════════
    #  3. Active Attacks
    # ══════════════════════════════════════════════════════════════════════

    def _active_attacks(self) -> None:
        console.clear()
        console.print(Rule("[bold cyan]Active Attacks[/bold cyan]"))
        console.print()

        attacks = self.manager.get_all()
        if not attacks:
            console.print("[dim]No attacks in session[/dim]")
            Prompt.ask("[dim]Press Enter[/dim]", default="")
            return

        self._print_attacks_table(attacks)
        console.print()

        opts = Table(show_header=False, box=None, padding=(0, 2))
        opts.add_column(style="cyan bold", width=4)
        opts.add_column()
        opts.add_row("M", "Monitor all (live dashboard)")
        opts.add_row("S", "Stop attack by ID")
        opts.add_row("A", "Stop ALL attacks")
        opts.add_row("R", "Remove finished/stopped from list")
        opts.add_row("0", "[dim]Back[/dim]")
        console.print(opts)

        choice = Prompt.ask("[cyan]▸[/cyan]", default="0").upper()

        if choice == "M":
            self._monitor_all()
        elif choice == "S":
            aid = IntPrompt.ask("[bold]Attack ID to stop[/bold]")
            self.manager.stop_attack(aid)
            console.print(f"[yellow]Stop signal sent to #{aid}[/yellow]")
        elif choice == "A":
            if Confirm.ask("[red]Stop ALL attacks?[/red]", default=False):
                self.manager.stop_all()
                console.print("[yellow]All attacks stopped[/yellow]")
        elif choice == "R":
            removed = self.manager.remove_finished()
            console.print(f"[dim]Removed {removed} entries[/dim]")

        Prompt.ask("[dim]Press Enter[/dim]", default="")

    def _print_attacks_table(self, attacks: list[AttackInstance]) -> None:
        table = Table(show_header=True, box=box.ROUNDED, border_style="blue", expand=True)
        table.add_column("ID",       style="bold cyan", width=4)
        table.add_column("Type",     style="bold",      min_width=18)
        table.add_column("Target",                      min_width=20)
        table.add_column("Status",                      width=10)
        table.add_column("PPS",      justify="right",   width=10)
        table.add_column("BPS",      justify="right",   width=10)
        table.add_column("Conns",    justify="right",   width=6)
        table.add_column("Progress",                    width=20)
        table.add_column("Elapsed",                     width=10)

        for a in attacks:
            if a.status == "Running":
                status = "[bold green]● RUNNING[/bold green]"
            elif a.status == "Finished":
                status = "[blue]● DONE[/blue]"
            else:
                status = "[dim]● STOPPED[/dim]"

            pct    = a.progress_pct
            filled = int(12 * pct / 100)
            bar    = f"[green]{'█' * filled}[/green][dim]{'░' * (12 - filled)}[/dim] {pct:.0f}%"

            table.add_row(
                str(a.id), a.attack_type, a.display_target,
                status, format_pps(a.pps), format_bps(a.bps),
                str(a.connections), bar, format_duration(a.elapsed),
            )
        console.print(table)

    # ── Live Monitor ──────────────────────────────────────────────────────

    def _monitor_single(self, attack: AttackInstance) -> None:
        self._live_monitor(lambda: [attack])

    def _monitor_all(self) -> None:
        self._live_monitor(self.manager.get_all)

    def _live_monitor(self, get_attacks) -> None:
        console.print("[dim]Live monitor — press Ctrl+C to exit[/dim]\n")
        try:
            with Live(console=console, refresh_per_second=1, screen=False) as live:
                while True:
                    attacks = get_attacks()
                    live.update(self._build_monitor_view(attacks))
                    running = [a for a in attacks if a.status == "Running"]
                    if not running and attacks:
                        time.sleep(1)
                        break
                    time.sleep(1)
        except KeyboardInterrupt:
            pass
        console.print("[dim]Monitor closed[/dim]")

    def _build_monitor_view(self, attacks: list[AttackInstance]) -> Table:
        running     = [a for a in attacks if a.status == "Running"]
        total_pps   = sum(a.pps for a in running)
        total_bps   = sum(a.bps for a in running)
        total_conns = sum(a.connections for a in running)
        uptime      = (datetime.datetime.now() - self.manager.session_start).total_seconds()

        header = Text()
        header.append("  LIVE  ", style="bold white on green")
        header.append(f"  Active: {len(running)}  ", style="bold")
        header.append(f"│ PPS: {format_pps(total_pps)}  ", style="cyan bold")
        header.append(f"│ BPS: {format_bps(total_bps)}  ", style="green bold")
        header.append(f"│ Connections: {total_conns}  ", style="yellow bold")
        header.append(f"│ Uptime: {format_duration(uptime)}", style="dim")

        outer = Table(show_header=False, box=box.HEAVY, border_style="cyan",
                      expand=True, padding=0)
        outer.add_column()
        outer.add_row(header)

        for a in attacks:
            st     = ("[bold green]● RUNNING[/bold green]" if a.status == "Running"
                      else "[blue]● DONE[/blue]" if a.status == "Finished"
                      else "[dim]● STOP[/dim]")
            pct    = a.progress_pct
            filled = int(20 * pct / 100)
            bar    = f"[green]{'█' * filled}[/green][dim]{'░' * (20 - filled)}[/dim]"
            outer.add_row(
                f"  [cyan bold]#{a.id}[/cyan bold]  "
                f"[bold]{escape(a.attack_type):<22}[/bold]"
                f" → {a.display_target:<20} {st}  "
                f"PPS:[cyan]{format_pps(a.pps):>8}[/cyan]  "
                f"BPS:[green]{format_bps(a.bps):>10}[/green]  "
                f"Conns:[yellow]{a.connections:>5}[/yellow]  "
                f"{bar} {pct:.0f}%  [dim]{format_duration(a.elapsed)}[/dim]"
            )

        recent = self.manager.logs[-5:]
        if recent:
            outer.add_row("[dim]─── Recent Logs ───[/dim]")
            for ts, level, msg in recent:
                style = LOG_LEVEL_STYLES.get(level, "white")
                outer.add_row(
                    f"  [dim]{ts}[/dim] [{style}]{level:<8}[/{style}] {escape(msg)}"
                )

        return outer

    # ══════════════════════════════════════════════════════════════════════
    #  4. Statistics
    # ══════════════════════════════════════════════════════════════════════

    def _statistics(self) -> None:
        console.clear()
        console.print(Rule("[bold cyan]Session Statistics[/bold cyan]"))
        console.print()

        s      = self.manager.stats
        uptime = (datetime.datetime.now() - self.manager.session_start).total_seconds()

        overview = Table(show_header=False, box=box.ROUNDED, border_style="green",
                         title="[bold]Session Overview[/bold]", expand=True)
        overview.add_column("Metric", style="bold",  min_width=25)
        overview.add_column("Value",  style="cyan",  justify="right")
        overview.add_row("Session uptime",         format_duration(uptime))
        overview.add_row("Engine",                 "Native C++" if native_available() else "Mock")
        overview.add_row("─" * 20,                 "─" * 15)
        overview.add_row("Total attacks started",  str(s["total_started"]))
        overview.add_row("Total attacks finished", str(s["total_finished"]))
        overview.add_row("Total attacks stopped",  str(s["total_stopped"]))
        overview.add_row("Currently running",      str(len(self.manager.get_running())))
        overview.add_row("─" * 20,                 "─" * 15)
        overview.add_row("Peak PPS",               format_pps(s["peak_pps"]))
        overview.add_row("Peak bandwidth",         format_bps(s["peak_bps"]))
        overview.add_row("Total packets sent",     f"{s['total_packets']:,}")
        overview.add_row("Current PPS",            format_pps(self.manager.total_pps))
        overview.add_row("Current BPS",            format_bps(self.manager.total_bps))
        console.print(overview)
        console.print()

        if s["attack_types"]:
            total    = sum(s["attack_types"].values())
            breakdown = Table(show_header=True, box=box.SIMPLE_HEAVY, border_style="blue",
                              title="[bold]Attack Type Breakdown[/bold]")
            breakdown.add_column("Attack Type", style="bold")
            breakdown.add_column("Count", justify="right", style="cyan")
            breakdown.add_column("Share", justify="right")
            for atype, count in sorted(s["attack_types"].items(), key=lambda x: -x[1]):
                pct    = count / total * 100
                filled = int(15 * pct / 100)
                bar    = f"[green]{'█' * filled}[/green][dim]{'░' * (15 - filled)}[/dim] {pct:.0f}%"
                breakdown.add_row(atype, str(count), bar)
            console.print(breakdown)

        console.print()
        Prompt.ask("[dim]Press Enter[/dim]", default="")

    # ══════════════════════════════════════════════════════════════════════
    #  5. Logs
    # ══════════════════════════════════════════════════════════════════════

    def _logs_view(self) -> None:
        console.clear()
        console.print(Rule("[bold cyan]Event Log[/bold cyan]"))
        console.print()

        filter_level = Prompt.ask(
            "[bold]Filter level[/bold]",
            choices=["ALL", "DEBUG", "INFO", "WARNING", "ERROR"],
            default=self.settings["log_level"],
        )

        logs = self.manager.logs
        if filter_level != "ALL":
            logs = [(ts, lvl, msg) for ts, lvl, msg in logs if lvl == filter_level]

        if not logs:
            console.print("[dim]No log entries[/dim]")
        else:
            table = Table(show_header=True, box=box.SIMPLE, expand=True)
            table.add_column("Time",    style="dim", width=10)
            table.add_column("Level",               width=10)
            table.add_column("Message")
            for ts, level, msg in logs[-50:]:
                style = LOG_LEVEL_STYLES.get(level, "white")
                table.add_row(ts, f"[{style}]{level}[/{style}]", escape(msg))
            console.print(table)
            if len(logs) > 50:
                console.print(f"[dim]Showing last 50 of {len(logs)} entries[/dim]")

        console.print()
        Prompt.ask("[dim]Press Enter[/dim]", default="")

    # ══════════════════════════════════════════════════════════════════════
    #  6. Settings
    # ══════════════════════════════════════════════════════════════════════

    def _settings_menu(self) -> None:
        while True:
            console.clear()
            console.print(Rule("[bold cyan]Settings[/bold cyan]"))
            console.print(f"[dim]Config: {_settings_mod.CONFIG_FILE}[/dim]\n")

            s     = self.settings
            table = Table(show_header=True, box=box.ROUNDED, border_style="green",
                          title="[bold]Current Settings[/bold]", expand=True)
            table.add_column("#", style="cyan bold", width=4)
            table.add_column("Setting", style="bold", min_width=25)
            table.add_column("Value",   style="cyan",  justify="right")

            rows = [
                ("1",  "Default port",     str(s["default_port"])),
                ("2",  "Default threads",  str(s["default_threads"])),
                ("3",  "Default duration", f"{s['default_duration']}s"),
                ("4",  "Default RPS",      str(s["default_rps"])),
                ("─",  "─" * 20,           "─" * 10),
                ("5",  "Max threads",      str(s["max_threads"])),
                ("6",  "Max duration",     f"{s['max_duration']}s"),
                ("7",  "Max RPS",          str(s["max_rps"])),
                ("─",  "─" * 20,           "─" * 10),
                ("8",  "Log level",        s["log_level"]),
                ("9",  "Auto-monitor",     "ON" if s["auto_monitor"] else "OFF"),
                ("─",  "─" * 20,           "─" * 10),
                ("10", "SSL verify",       "ON" if s["ssl_verify"] else "OFF"),
                ("11", "Connect timeout",  f"{s['connect_timeout']}s"),
                ("12", "Read timeout",     f"{s['read_timeout']}s"),
                ("13", "Max retries",      str(s["max_retries"])),
                ("─",  "─" * 20,           "─" * 10),
                ("14", "Headers dir",      s["headers_dir"] or "[dim]default[/dim]"),
                ("15", "IP ranges dir",    s["ip_ranges_dir"] or "[dim]default[/dim]"),
            ]
            for num, label, val in rows:
                table.add_row(num, label, val)
            console.print(table)
            console.print()

            opts = Table(show_header=False, box=None, padding=(0, 2))
            opts.add_column(style="cyan bold", width=6)
            opts.add_column()
            opts.add_row("1-15", "Edit a setting by number")
            opts.add_row("R",    "Reset all to defaults")
            opts.add_row("0",    "[dim]Back (auto-saves)[/dim]")
            console.print(opts)

            choice = Prompt.ask("[cyan]▸[/cyan]", default="0").upper()

            if choice == "0":
                _settings_mod.save(self.settings)
                return
            if choice == "R":
                if Confirm.ask("[red]Reset all settings to defaults?[/red]", default=False):
                    self.settings = dict(_settings_mod.DEFAULT_SETTINGS)
                    _settings_mod.save(self.settings)
                    self.manager.settings = self.settings
                    console.print("[green]Settings reset[/green]")
                continue

            try:
                self._edit_setting(int(choice))
            except ValueError:
                pass

    def _edit_setting(self, num: int) -> None:
        s = self.settings
        _actions = {
            1:  lambda: s.update(default_port     = clamp(IntPrompt.ask("Default port",         default=s["default_port"]),     1, 65535)),
            2:  lambda: s.update(default_threads  = clamp(IntPrompt.ask("Default threads",      default=s["default_threads"]),  1, s["max_threads"])),
            3:  lambda: s.update(default_duration = clamp(IntPrompt.ask("Default duration (s)", default=s["default_duration"]), 1, s["max_duration"])),
            4:  lambda: s.update(default_rps      = clamp(IntPrompt.ask("Default RPS",          default=s["default_rps"]),      1, s["max_rps"])),
            5:  lambda: s.update(max_threads      = clamp(IntPrompt.ask("Max threads",          default=s["max_threads"]),      1, 100000)),
            6:  lambda: s.update(max_duration     = clamp(IntPrompt.ask("Max duration (s)",     default=s["max_duration"]),     1, 86400)),
            7:  lambda: s.update(max_rps          = clamp(IntPrompt.ask("Max RPS",              default=s["max_rps"]),          1, 1000000)),
            8:  lambda: s.update(log_level        = Prompt.ask("Log level", choices=["ALL","DEBUG","INFO","WARNING","ERROR"], default=s["log_level"])),
            9:  lambda: s.update(auto_monitor     = Confirm.ask("Auto-monitor?",     default=s["auto_monitor"])),
            10: lambda: s.update(ssl_verify       = Confirm.ask("SSL verification?", default=s["ssl_verify"])),
            11: lambda: s.update(connect_timeout  = clamp(IntPrompt.ask("Connect timeout (s)", default=s["connect_timeout"]), 1, 120)),
            12: lambda: s.update(read_timeout     = clamp(IntPrompt.ask("Read timeout (s)",    default=s["read_timeout"]),    1, 300)),
            13: lambda: s.update(max_retries      = clamp(IntPrompt.ask("Max retries",         default=s["max_retries"]),     0, 20)),
            14: lambda: s.update(headers_dir      = Prompt.ask("Headers dir (empty=default)",   default=s["headers_dir"]).strip()),
            15: lambda: s.update(ip_ranges_dir    = Prompt.ask("IP ranges dir (empty=default)", default=s["ip_ranges_dir"]).strip()),
        }
        action = _actions.get(num)
        if action is None:
            console.print("[red]Invalid number[/red]")
            return
        action()
        _settings_mod.save(s)
        self.manager.settings = s
        console.print("[green]✓ Saved[/green]")

    # ══════════════════════════════════════════════════════════════════════
    #  7. Proxies
    # ══════════════════════════════════════════════════════════════════════

    def _proxies_menu(self) -> None:
        while True:
            console.clear()
            console.print(Rule("[bold cyan]Proxy Manager[/bold cyan]"))
            console.print(f"[dim]File: {_proxies_mod.PROXIES_FILE}[/dim]")

            has_socks = any(
                p.get("type", "").startswith("socks") and p.get("enabled", True)
                for p in self.proxies
            )
            if self.proxies and not has_socks:
                console.print("[yellow]⚠ HTTP proxies do not protect DNS. "
                              "Use SOCKS5 for DNS leak prevention.[/yellow]")
            elif has_socks and not has_pysocks():
                console.print("[yellow]⚠ PySocks not installed — DNS uses system resolver. "
                              "Install: pip install pysocks[/yellow]")
            elif has_socks:
                console.print("[green]✓ SOCKS proxy active — DNS routed through proxy[/green]")
            console.print()

            if self.proxies:
                table = Table(show_header=True, box=box.ROUNDED, border_style="blue",
                              title=f"[bold]Proxies ({len(self.proxies)})[/bold]", expand=True)
                table.add_column("#",       style="cyan bold", width=4)
                table.add_column("Type",    width=8)
                table.add_column("Host",    min_width=20)
                table.add_column("Port",    width=7, justify="right")
                table.add_column("Auth",    width=10)
                table.add_column("Enabled", width=8, justify="center")
                for i, p in enumerate(self.proxies, 1):
                    auth    = f"{p.get('username', '')}:***" if p.get("username") else "[dim]—[/dim]"
                    enabled = "[green]●[/green]" if p.get("enabled", True) else "[red]○[/red]"
                    table.add_row(str(i), p.get("type","http").upper(),
                                  p.get("host",""), str(p.get("port","")), auth, enabled)
                console.print(table)
            else:
                console.print("[dim]No proxies configured[/dim]")

            console.print()
            opts = Table(show_header=False, box=None, padding=(0, 2))
            opts.add_column(style="cyan bold", width=4)
            opts.add_column()
            opts.add_row("A", "Add proxy")
            opts.add_row("I", "Import from text")
            opts.add_row("E", "Edit proxy by #")
            opts.add_row("T", "Toggle enable/disable by #")
            opts.add_row("D", "Delete proxy by #")
            opts.add_row("C", "Clear all proxies")
            opts.add_row("X", "Export to file")
            opts.add_row("0", "[dim]Back (auto-saves)[/dim]")
            console.print(opts)

            choice = Prompt.ask("[cyan]▸[/cyan]", default="0").upper()

            if choice == "0":
                _proxies_mod.save(self.proxies)
                self.manager.proxies = self.proxies
                return
            elif choice == "A":  self._add_proxy()
            elif choice == "I":  self._import_proxies()
            elif choice == "E":  self._edit_proxy()
            elif choice == "T":  self._toggle_proxy()
            elif choice == "D":  self._delete_proxy()
            elif choice == "X":  self._export_proxies()
            elif choice == "C":
                if Confirm.ask("[red]Clear ALL proxies?[/red]", default=False):
                    self.proxies.clear()
                    _proxies_mod.save(self.proxies)
                    console.print("[yellow]All proxies cleared[/yellow]")

    def _add_proxy(self) -> None:
        console.print()
        ptype    = Prompt.ask("[bold]Type[/bold]",
                              choices=["http","https","socks4","socks5"], default="http")
        host     = Prompt.ask("[bold]Host[/bold]").strip()
        if not host:
            console.print("[red]Host cannot be empty[/red]")
            return
        port     = clamp(IntPrompt.ask("[bold]Port[/bold]", default=8080), 1, 65535)
        username = Prompt.ask("[bold]Username[/bold] (empty=none)", default="")
        password = Prompt.ask("[bold]Password[/bold]", default="") if username else ""
        self.proxies.append({"type": ptype, "host": host, "port": port,
                              "username": username, "password": password, "enabled": True})
        _proxies_mod.save(self.proxies)
        console.print(f"[green]✓ Added {ptype.upper()}://{host}:{port}[/green]")

    def _import_proxies(self) -> None:
        console.print()
        console.print("[dim]Formats: host:port  |  host:port:user:pass  |  "
                      "type://host:port  |  type://user:pass@host:port[/dim]")
        console.print("[dim]Enter one per line. Empty line to finish.[/dim]\n")
        added = 0
        while True:
            line  = Prompt.ask("[dim]proxy[/dim]", default="").strip()
            if not line:
                break
            proxy = _proxies_mod.parse_line(line)
            if proxy:
                self.proxies.append(proxy)
                added += 1
                console.print(f"  [green]+ {proxy['type']}://{proxy['host']}:{proxy['port']}[/green]")
            else:
                console.print(f"  [red]✗ Cannot parse: {escape(line)}[/red]")
        if added:
            _proxies_mod.save(self.proxies)
        console.print(f"\n[bold]Imported {added} proxies[/bold]")

    def _edit_proxy(self) -> None:
        if not self.proxies:
            console.print("[dim]No proxies to edit[/dim]")
            return
        idx = IntPrompt.ask("[bold]Proxy #[/bold]") - 1
        if not 0 <= idx < len(self.proxies):
            console.print("[red]Invalid #[/red]")
            return
        p = self.proxies[idx]
        console.print(f"[dim]Editing: {p['type']}://{p['host']}:{p['port']}[/dim]\n")
        p["type"]     = Prompt.ask("Type", choices=["http","https","socks4","socks5"], default=p["type"])
        host          = Prompt.ask("Host", default=p["host"]).strip()
        if host:
            p["host"] = host
        p["port"]     = clamp(IntPrompt.ask("Port", default=p["port"]), 1, 65535)
        p["username"] = Prompt.ask("Username (empty=none)", default=p.get("username", ""))
        p["password"] = (Prompt.ask("Password", default=p.get("password", ""))
                         if p["username"] else "")
        _proxies_mod.save(self.proxies)
        console.print("[green]✓ Updated[/green]")

    def _toggle_proxy(self) -> None:
        if not self.proxies:
            console.print("[dim]No proxies[/dim]")
            return
        idx = IntPrompt.ask("[bold]Proxy # to toggle[/bold]") - 1
        if not 0 <= idx < len(self.proxies):
            console.print("[red]Invalid #[/red]")
            return
        self.proxies[idx]["enabled"] = not self.proxies[idx].get("enabled", True)
        state = "enabled" if self.proxies[idx]["enabled"] else "disabled"
        _proxies_mod.save(self.proxies)
        console.print(f"[yellow]Proxy #{idx+1} {state}[/yellow]")

    def _delete_proxy(self) -> None:
        if not self.proxies:
            console.print("[dim]No proxies[/dim]")
            return
        idx = IntPrompt.ask("[bold]Proxy # to delete[/bold]") - 1
        if not 0 <= idx < len(self.proxies):
            console.print("[red]Invalid #[/red]")
            return
        removed = self.proxies.pop(idx)
        _proxies_mod.save(self.proxies)
        console.print(f"[yellow]Deleted {removed['host']}:{removed['port']}[/yellow]")

    def _export_proxies(self) -> None:
        if not self.proxies:
            console.print("[dim]No proxies to export[/dim]")
            return
        lines = []
        for p in self.proxies:
            if not p.get("enabled", True):
                continue
            if p.get("username"):
                lines.append(f"{p['type']}://{p['username']}:{p['password']}@{p['host']}:{p['port']}")
            else:
                lines.append(f"{p['host']}:{p['port']}")
        console.print(Panel("\n".join(lines), title="[bold]Export[/bold]",
                            border_style="green", expand=False))
        path = Prompt.ask("[dim]Save to file? (path or empty to skip)[/dim]", default="").strip()
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
                console.print(f"[green]✓ Saved to {escape(path)}[/green]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    # ══════════════════════════════════════════════════════════════════════
    #  Exit
    # ══════════════════════════════════════════════════════════════════════

    def _exit(self) -> None:
        running = self.manager.get_running()
        if running:
            if not Confirm.ask(
                f"[red]{len(running)} attacks still running. Stop all and exit?[/red]",
                default=True,
            ):
                return
            self.manager.stop_all()
        _settings_mod.save(self.settings)
        _proxies_mod.save(self.proxies)
        self._running = False
        console.print("[bold]Goodbye.[/bold]")
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════════════
    #  PoO — Proof-of-Ownership wizard
    # ══════════════════════════════════════════════════════════════════════

    def _poo_menu(self) -> None:
        """Dedicated menu: show verified targets and run new verifications."""
        while True:
            console.clear()
            console.print(Rule("[bold cyan]Proof-of-Ownership[/bold cyan]"))
            console.print(
                "[dim]Verify that you own a target before attacking it.[/dim]\n"
            )

            verified = all_verified()
            if verified:
                tbl = Table(show_header=True, box=box.ROUNDED, border_style="green",
                            title="[bold]Verified Targets[/bold]", expand=True)
                tbl.add_column("Target",     style="bold")
                tbl.add_column("Method",     style="cyan",  width=18)
                tbl.add_column("Expires",    style="dim",   width=22)
                import datetime as _dt, time as _t
                for tgt, rec in verified.items():
                    exp = _dt.datetime.fromtimestamp(rec["expires_at"]).strftime("%Y-%m-%d %H:%M")
                    tbl.add_row(tgt, rec.get("method","?"), exp)
                console.print(tbl)
            else:
                console.print("[dim]No verified targets yet.[/dim]\n")

            opts = Table(show_header=False, box=None, padding=(0, 2))
            opts.add_column(style="bold cyan", width=4)
            opts.add_column()
            opts.add_row("D", "Verify domain (L7) — DNS TXT record")
            opts.add_row("R", "Verify server (L4) — reverse connection")
            opts.add_row("X", "Revoke a verification")
            opts.add_row("0", "[dim]Back[/dim]")
            console.print(opts)

            choice = Prompt.ask("[cyan]▸[/cyan]", default="0").upper()
            if choice == "0":
                return
            elif choice == "D":
                self._poo_wizard_dns()
            elif choice == "R":
                self._poo_wizard_reverse()
            elif choice == "X":
                target = Prompt.ask("[bold]Target to revoke[/bold]").strip()
                if target:
                    revoke(target)
                    console.print(f"[yellow]Revoked: {target}[/yellow]")
            Prompt.ask("[dim]Press Enter[/dim]", default="")

    def _poo_wizard_dns(self) -> None:
        """Interactive DNS TXT verification flow."""
        console.print()
        console.print(Rule("[bold]DNS TXT Verification (L7)[/bold]"))

        if not has_dnspython():
            console.print(Panel(
                "[yellow]dnspython is not installed.[/yellow]\n\n"
                "Run: [bold]pip install dnspython[/bold]\n\n"
                "Without it, DNS TXT lookups are not possible.",
                border_style="yellow", expand=False,
            ))
            return

        domain = Prompt.ask("[bold]Domain to verify[/bold]").strip().lower()
        if not domain:
            return

        if is_verified(domain):
            console.print(f"[green]✓ {domain} is already verified.[/green]")
            return

        tok  = generate()
        name = txt_record_name(domain)

        console.print(Panel(
            f"[bold]Add this DNS TXT record to your domain:[/bold]\n\n"
            f"  [cyan]Name :[/cyan]  {name}\n"
            f"  [cyan]Type :[/cyan]  TXT\n"
            f"  [cyan]Value:[/cyan]  [bold green]{tok}[/bold green]\n\n"
            "[dim]Most DNS providers propagate within 30–120 seconds.[/dim]",
            title="[bold cyan]Step 1 — Add DNS record[/bold cyan]",
            border_style="cyan", expand=False,
        ))

        console.print("\nWaiting for you to add the record. Press Enter to check,")
        console.print("or type [bold]skip[/bold] to cancel.\n")

        for attempt in range(1, 11):
            answer = Prompt.ask(f"[cyan]Check attempt {attempt}/10[/cyan]",
                                default="check").strip().lower()
            if answer == "skip":
                console.print("[dim]Cancelled.[/dim]")
                return

            result = verify_dns(domain, tok)
            if result.ok:
                console.print(f"\n[bold green]✓ Ownership verified: {domain}[/bold green]")
                console.print("[dim]Verification cached for 24 hours.[/dim]")
                return
            else:
                console.print(f"  [red]✗ Not yet:[/red] {result.error}")

        console.print("[red]Verification timed out after 10 attempts.[/red]")

    def _poo_wizard_reverse(self) -> None:
        """Interactive reverse-connection verification flow."""
        console.print()
        console.print(Rule("[bold]Reverse-Connection Verification (L4)[/bold]"))
        console.print(
            "[dim]The target server must be able to make outbound HTTP requests.[/dim]\n"
            "[dim]If it can't (game server, DB), use --unsafe instead.[/dim]\n"
        )

        ip = Prompt.ask("[bold]Target IP to verify[/bold]").strip()
        if not ip:
            return

        if is_verified(ip):
            console.print(f"[green]✓ {ip} is already verified.[/green]")
            return

        from ..poo.reverse_verify import ReverseVerifyServer
        tok      = generate()
        local_ip = get_local_ip()

        with ReverseVerifyServer(token=tok, expected_ip=ip) as server:
            console.print(Panel(
                f"[bold]From the target server ({ip}), run:[/bold]\n\n"
                f"  [bold green]curl \"http://{local_ip}:{server.port}/verify?token={tok}\"[/bold green]\n\n"
                "[dim]Or with wget:[/dim]\n"
                f"  [dim]wget -qO- \"http://{local_ip}:{server.port}/verify?token={tok}\"[/dim]\n\n"
                f"[dim]Waiting up to {DEFAULT_TIMEOUT // 60} minutes…[/dim]",
                title="[bold cyan]Step 1 — Run from target server[/bold cyan]",
                border_style="cyan", expand=False,
            ))
            console.print("[dim](Press Ctrl+C to cancel)[/dim]\n")

            try:
                ok, src_ip = server.wait(DEFAULT_TIMEOUT)
            except KeyboardInterrupt:
                console.print("\n[dim]Cancelled.[/dim]")
                return

        if ok:
            from ..poo.token import mark_verified
            mark_verified(ip, tok, "reverse_connect")
            console.print(
                f"\n[bold green]✓ Ownership verified: {ip}[/bold green]  "
                f"[dim](source IP: {src_ip})[/dim]"
            )
            console.print("[dim]Verification cached for 24 hours.[/dim]")
        else:
            console.print(
                f"\n[red]✗ No valid connection received from {ip} within the timeout.[/red]\n"
                "[dim]Ensure the server can reach this machine and retry.[/dim]\n"
                "[dim]Or use --unsafe to skip ownership checks.[/dim]"
            )

    def _ensure_ownership(self, target: str, attack_type: str) -> bool:
        """Return True if the target is verified (or unsafe mode is on).

        If not verified, offers to run the appropriate wizard inline.
        """
        if self.unsafe:
            return True
        if is_verified(target):
            return True

        # Not verified — offer to verify now
        category   = ATTACK_TO_CATEGORY.get(attack_type, "")
        method     = "dns_txt" if category in L7_CATEGORIES else "reverse_connect"
        method_lbl = "DNS TXT" if method == "dns_txt" else "reverse-connection"

        console.print(Panel(
            f"[bold yellow]⚠ Ownership not verified[/bold yellow]\n\n"
            f"[white]{target}[/white] has not been verified as yours.\n\n"
            f"Verification method: [bold]{method_lbl}[/bold]\n\n"
            "Run the wizard now, or use [bold]--unsafe[/bold] to skip.",
            border_style="yellow", expand=False,
        ))

        choice = Prompt.ask(
            "[yellow]Verify now[/yellow]",
            choices=["yes", "no", "unsafe"],
            default="yes",
        )

        if choice == "unsafe":
            self.unsafe = True
            self.manager.unsafe = True
            console.print("[yellow]⚠ Unsafe mode enabled for this session.[/yellow]")
            return True
        if choice == "no":
            return False

        if method == "dns_txt":
            self._poo_wizard_dns()
        else:
            self._poo_wizard_reverse()

        return is_verified(target)

    # ── Internal helpers ──────────────────────────────────────────────────

    def _ask_target(self) -> tuple[str, str] | None:
        """Prompt for a target and validate it.  Returns ``(target, type)`` or ``None``."""
        from ..core.validation import validate_target
        target = Prompt.ask("[bold]Target[/bold] (IP or domain)").strip()
        if not target:
            console.print("[red]Target cannot be empty[/red]")
            return None
        ttype = validate_target(target)
        if ttype is None:
            console.print(f"[red]Invalid target:[/red] '{escape(target)}' is not a valid IP or domain")
            return None
        return target, ttype
