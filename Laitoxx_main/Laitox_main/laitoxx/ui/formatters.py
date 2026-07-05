"""Display formatting helpers and UI constants."""


# ── Metric formatters ─────────────────────────────────────────────────────

def format_pps(pps: int | float) -> str:
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.1f}M"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f}K"
    return str(int(pps))


def format_bps(bps: float) -> str:
    if bps >= 1000:
        return f"{bps / 1000:.2f} GB/s"
    return f"{bps:.1f} MB/s"


def format_duration(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def clamp(val: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, val))


# ── ASCII banner ──────────────────────────────────────────────────────────

BANNER = r"""[bold cyan]
  ██╗      █████╗ ██╗████████╗ ██████╗ ██╗  ██╗██╗  ██╗
  ██║     ██╔══██╗██║╚══██╔══╝██╔═══██╗╚██╗██╔╝╚██╗██╔╝
  ██║     ███████║██║   ██║   ██║   ██║ ╚███╔╝  ╚███╔╝
  ██║     ██╔══██║██║   ██║   ██║   ██║ ██╔██╗  ██╔██╗
  ███████╗██║  ██║██║   ██║   ╚██████╔╝██╔╝ ██╗██╔╝ ██╗
  ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
[/bold cyan][bold white]          DDoS Control Panel v2.0 — Console Edition[/bold white]
[dim]         Engine: {engine}  |  Platform: {platform}[/dim]
"""

# Styles for log levels in Rich markup
LOG_LEVEL_STYLES: dict[str, str] = {
    "DEBUG":    "dim",
    "INFO":     "cyan",
    "WARNING":  "yellow",
    "ERROR":    "red",
    "CRITICAL": "bold red",
}
