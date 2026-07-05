"""Non-interactive CLI pipeline mode (used by the GUI subprocess reader)."""

import argparse
import json
import sys
import time

from ..core.taxonomy import ATTACK_CATEGORIES
from ..core.validation import validate_target
from ..config import settings as _settings_mod
from ..config import proxies as _proxies_mod
from ..engine.manager import AttackManager
from ..ui.formatters import format_pps, format_duration

# L2/L3 categories that rely on raw sockets and are Linux-only
_L2_L3_CATEGORIES = frozenset({"L2 Data Link", "L3 Network"})


def available_method_codes() -> set[str]:
    """Return the set of method codes valid on the current platform.

    L2/L3 raw-socket methods are hidden on Windows and macOS.
    """
    codes: set[str] = set()
    for cat_name, attacks in ATTACK_CATEGORIES.items():
        if cat_name in _L2_L3_CATEGORIES and sys.platform != "linux":
            continue
        for _, (code, _) in attacks.items():
            codes.add(code)
    return codes


def build_arg_parser() -> argparse.ArgumentParser:
    all_codes = sorted(available_method_codes())
    p = argparse.ArgumentParser(
        prog="console_app.py",
        description="Laitoxx-DDoS — CLI pipeline mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python console_app.py --method GET --target example.com --port 443 --threads 8 --duration 30\n"
            "  python console_app.py --method UDP --target 1.2.3.4 --port 80 --threads 32 --duration 60\n\n"
            f"Available method codes:\n  {', '.join(all_codes)}"
        ),
    )
    p.add_argument("--method",   required=True, metavar="CODE",
                   help="Attack method code (e.g. GET, UDP, CFB, KILLER)")
    p.add_argument("--target",   required=True, metavar="HOST",
                   help="Target IP or domain")
    p.add_argument("--port",     type=int, default=80,  metavar="PORT",
                   help="Target port (default: 80)")
    p.add_argument("--threads",  type=int, default=8,   metavar="N",
                   help="Thread/goroutine count (default: 8)")
    p.add_argument("--duration", type=int, default=60,  metavar="SEC",
                   help="Attack duration in seconds (default: 60)")
    p.add_argument("--rps",      type=int, default=0,   metavar="N",
                   help="Max requests/sec total — 0 = unlimited (default: 0)")
    p.add_argument("--proxy",    metavar="[type://]host:port",
                   help="Single proxy, e.g. socks5://127.0.0.1:9050")
    p.add_argument("--proxy-file", metavar="PATH",
                   help="Path to a .txt file with one proxy per line; distributed across threads")
    p.add_argument("--json",     action="store_true",
                   help="Output stats as JSON lines (for GUI consumption)")
    p.add_argument("--interval", type=float, default=1.0, metavar="SEC",
                   help="Stats polling interval in seconds (default: 1.0)")

    # ── Proof-of-Ownership bypass ─────────────────────────────────────────
    unsafe_group = p.add_mutually_exclusive_group()
    unsafe_group.add_argument(
        "--unsafe",
        action="store_true",
        help=(
            "Skip Proof-of-Ownership verification entirely. "
            "Use only if you own the target and PoO cannot work "
            "(e.g. no DNS control, no outbound HTTP from target)."
        ),
    )
    unsafe_group.add_argument(
        "--i-know-what-im-doing",
        action="store_true",
        dest="unsafe",
        help="Alias for --unsafe.",
    )

    return p


def run(args: argparse.Namespace) -> int:
    """Execute the attack described by *args* and stream stats to stdout.

    Exit codes:
      0 — success
      1 — invalid arguments
      2 — engine error
    """
    method = args.method.upper()

    if method not in available_method_codes():
        print(f"ERROR: unknown method '{method}'. Run with --help for the full list.",
              file=sys.stderr)
        return 1

    target = args.target.strip()
    if validate_target(target) is None:
        print(f"ERROR: '{target}' is not a valid IP or domain.", file=sys.stderr)
        return 1

    proxy_cfg: dict | None = None
    proxies: list[dict] = []

    proxy_file = getattr(args, "proxy_file", None)
    if proxy_file:
        from pathlib import Path
        lines = Path(proxy_file).read_text(encoding="utf-8").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = _proxies_mod.parse_line(line)
            if parsed:
                proxies.append(parsed)
        if not proxies:
            print(f"ERROR: no valid proxies found in '{proxy_file}'.", file=sys.stderr)
            return 1
        print(f"[LAITOXX] Loaded {len(proxies)} proxies from {proxy_file}", file=sys.stderr)
    elif args.proxy:
        proxy_cfg = _proxies_mod.parse_line(args.proxy)
        if proxy_cfg is None:
            print(f"ERROR: bad proxy format '{args.proxy}'.", file=sys.stderr)
            return 1
        proxies = [proxy_cfg]

    unsafe   = getattr(args, "unsafe", False)
    settings = _settings_mod.load()
    if not proxies:
        proxies = _proxies_mod.load()
    manager  = AttackManager(settings, proxies, unsafe=unsafe)

    if not unsafe:
        # Check PoO cache; if not verified, print guidance and abort
        from ..poo import check_cached, is_verified
        from ..core.taxonomy import ATTACK_TO_CATEGORY, L7_CATEGORIES
        category = ATTACK_TO_CATEGORY.get(method, "")
        poo_method = "dns_txt" if category in L7_CATEGORIES else "reverse_connect"
        if not is_verified(target):
            print(
                f"\n[PoO] Target '{target}' has not been verified as yours.\n"
                f"{'Domain ownership check required (DNS TXT).' if poo_method == 'dns_txt' else 'Server ownership check required (reverse connect).'}\n\n"
                f"Run the TUI or GUI to complete verification, then retry.\n"
                f"Or pass --unsafe to skip this check entirely.\n",
                file=sys.stderr,
            )
            return 1

    attack = manager.start_attack(
        attack_type=method,
        target=target,
        port=args.port,
        duration=args.duration,
        threads=args.threads,
        rps=args.rps,
    )
    if attack is None:
        print("ERROR: failed to start attack (check logs above).", file=sys.stderr)
        return 2

    if not args.json:
        print(f"[LAITOXX] {method} -> {target}:{args.port} | "
              f"threads={args.threads} duration={args.duration}s "
              f"rps={args.rps or 'unlimited'}")
        print("[LAITOXX] Press Ctrl+C to stop early.\n")

    t0        = time.time()
    prev_pkts = 0
    peak_pkts = 0

    def _packets() -> int:
        nonlocal peak_pkts
        v = attack._native.get_packets_sent() if attack._native else 0
        peak_pkts = max(peak_pkts, v)
        return v

    try:
        while attack.status == "Running":
            time.sleep(args.interval)
            manager.tick()

            elapsed   = time.time() - t0
            pkts_now  = _packets()
            pps       = max(0, pkts_now - prev_pkts) / args.interval
            prev_pkts = pkts_now
            remaining = max(0.0, args.duration - elapsed)

            if args.json:
                print(json.dumps({
                    "t":         round(elapsed, 1),
                    "pps":       round(pps, 1),
                    "packets":   pkts_now,
                    "remaining": round(remaining, 1),
                    "status":    attack.status,
                }), flush=True)
            else:
                bar_w  = 20
                filled = int(bar_w * elapsed / args.duration) if args.duration else 0
                bar    = "#" * filled + "-" * (bar_w - filled)
                print(f"\r  [{bar}] {elapsed:5.1f}s  "
                      f"PPS: {format_pps(int(pps)):>7}  "
                      f"Total: {format_pps(pkts_now):>7}  "
                      f"ETA: {remaining:.0f}s   ",
                      end="", flush=True)

    except KeyboardInterrupt:
        attack.stop()
        if not args.json:
            print("\n[LAITOXX] Stopped by user.")

    elapsed    = time.time() - t0
    pkts_final = max(_packets(), peak_pkts)

    if not args.json:
        print()
        print(f"[LAITOXX] Done.  Total packets: {format_pps(pkts_final)}  "
              f"Elapsed: {format_duration(elapsed)}  "
              f"Avg PPS: {format_pps(int(pkts_final / max(elapsed, 1)))}")
    else:
        print(json.dumps({
            "t":         round(elapsed, 1),
            "pps":       0,
            "packets":   pkts_final,
            "remaining": 0,
            "status":    "done",
        }), flush=True)

    return 0
