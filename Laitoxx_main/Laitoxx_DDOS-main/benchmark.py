#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laitoxx DDoS — Community Benchmark Script
==========================================

Run this against YOUR OWN server or infrastructure you have explicit
permission to test. See the PoO section in README.md.

Usage
-----
    python benchmark.py --target YOUR_HOST --port 443

    # Choose specific methods only
    python benchmark.py --target YOUR_HOST --port 443 --methods GET,POST,CFB,UDP

    # Full suite — all methods in a category
    python benchmark.py --target YOUR_HOST --port 80 --category l4

    # Tune duration and thread count
    python benchmark.py --target YOUR_HOST --port 443 --threads 16 --duration 30 --runs 5

    # Markdown output only (pipe into a file)
    python benchmark.py --target YOUR_HOST --port 443 --markdown > my_results.md

Output
------
Results are printed as a console table and optionally as Markdown.
Share the Markdown output in a GitHub issue/discussion so others can
compare results across different machines and network conditions.

⚠️  ONLY run against infrastructure you own or have explicit written
    permission to test. Using --unsafe bypasses the PoO check.
"""

import argparse
import json
import os
import platform
import socket
import ssl
import statistics
import subprocess
import sys
import threading
import time
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — edit these placeholders for your environment
# ─────────────────────────────────────────────────────────────────────────────

# Replace with your own server hostname or IP
DEFAULT_TARGET  = "YOUR_SERVER_HOSTNAME_OR_IP"   # e.g. "my-vps.example.com" or "192.168.1.100"

# Default ports — adjust to match your server
DEFAULT_PORT_HTTP  = 80     # used for L4 methods
DEFAULT_PORT_HTTPS = 443    # used for L7 methods

# ─────────────────────────────────────────────────────────────────────────────

ROOT   = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(ROOT, "console_app.py")

# Available method groups
METHOD_GROUPS = {
    "l7_basic": [
        ("GET",        DEFAULT_PORT_HTTPS),
        ("POST",       DEFAULT_PORT_HTTPS),
        ("HEAD",       DEFAULT_PORT_HTTPS),
        ("OVH",        DEFAULT_PORT_HTTPS),
        ("RHEX",       DEFAULT_PORT_HTTPS),
        ("STOMP",      DEFAULT_PORT_HTTPS),
        ("STRESS",     DEFAULT_PORT_HTTPS),
        ("DYN",        DEFAULT_PORT_HTTPS),
        ("NULL",       DEFAULT_PORT_HTTPS),
        ("COOKIE",     DEFAULT_PORT_HTTPS),
        ("PPS",        DEFAULT_PORT_HTTPS),
        ("EVEN",       DEFAULT_PORT_HTTPS),
        ("DOWNLOADER", DEFAULT_PORT_HTTPS),
    ],
    "l7_bypass": [
        ("CFB",    DEFAULT_PORT_HTTPS),
        ("CFBUAM", DEFAULT_PORT_HTTPS),
        ("DGB",    DEFAULT_PORT_HTTPS),
        ("AVB",    DEFAULT_PORT_HTTPS),
        ("BOT",    DEFAULT_PORT_HTTPS),
        ("GSB",    DEFAULT_PORT_HTTPS),
        ("BYPASS", DEFAULT_PORT_HTTPS),
        ("KILLER", DEFAULT_PORT_HTTPS),
    ],
    "l7_specialized": [
        ("WS",         DEFAULT_PORT_HTTPS),
        ("H2STREAM",   DEFAULT_PORT_HTTPS),
        ("H2HPACK",    DEFAULT_PORT_HTTPS),
        ("H2RST",      DEFAULT_PORT_HTTPS),
        ("H2SETTINGS", DEFAULT_PORT_HTTPS),
        ("QUIC",       DEFAULT_PORT_HTTPS),
        ("GRAPHQL",    DEFAULT_PORT_HTTPS),
        ("WEBDAV",     DEFAULT_PORT_HTTPS),
    ],
    "l4": [
        ("UDP",        DEFAULT_PORT_HTTP),
        ("CPS",        DEFAULT_PORT_HTTP),
        ("CONNECTION", DEFAULT_PORT_HTTP),
        ("TCP-SYN",    DEFAULT_PORT_HTTP),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def probe_latency(host: str, port: int, tls: bool, n: int = 10) -> dict:
    """Measure TCP connect + optional TLS handshake latency across n probes."""
    connect_ms, tls_ms = [], []
    errors = 0
    for _ in range(n):
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((host, port), timeout=5)
            connect_ms.append((time.perf_counter() - t0) * 1000)
            if tls:
                ctx = ssl.create_default_context()
                t1 = time.perf_counter()
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                tls_ms.append((time.perf_counter() - t1) * 1000)
                ssock.close()
            else:
                sock.close()
        except Exception:
            errors += 1

    def pcts(arr: list) -> dict:
        if not arr:
            return {"p50": 0, "p95": 0, "p99": 0, "max": 0, "mean": 0}
        s = sorted(arr)
        n = len(s)
        return {
            "p50":  round(s[int(n * 0.50)], 1),
            "p95":  round(s[min(int(n * 0.95), n - 1)], 1),
            "p99":  round(s[min(int(n * 0.99), n - 1)], 1),
            "max":  round(s[-1], 1),
            "mean": round(statistics.mean(s), 1),
        }

    return {
        "connect": pcts(connect_ms),
        "tls":     pcts(tls_ms) if tls else None,
        "errors":  errors,
    }


def run_once(method: str, port: int, target: str, threads: int,
             duration: int, interval: float, unsafe: bool) -> Optional[dict]:
    """Run one attack and return per-interval stats."""
    cmd = [
        sys.executable, "-u", SCRIPT,
        "--method",   method,
        "--target",   target,
        "--port",     str(port),
        "--threads",  str(threads),
        "--duration", str(duration),
        "--rps",      "0",
        "--json",
        "--interval", str(interval),
    ]
    if unsafe:
        cmd.append("--unsafe")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=ROOT,
    )

    lines: list[str] = []

    def _reader():
        for ln in proc.stdout:
            ln = ln.strip()
            if ln:
                lines.append(ln)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    # Try to sample client resource usage if psutil is available
    cpu_s, rss_s = [], []
    try:
        import psutil
        ps = psutil.Process(proc.pid)
    except Exception:
        ps = None  # psutil not installed — skip resource sampling

    t_start = time.time()
    while proc.poll() is None and (time.time() - t_start) < duration + 5:
        time.sleep(0.5)
        if ps:
            try:
                cpu_s.append(ps.cpu_percent(interval=None))
                rss_s.append(ps.memory_info().rss / 1024 / 1024)
            except Exception:
                pass

    proc.wait(timeout=10)
    t.join(timeout=2)

    stderr_lines = len(
        [ln for ln in (proc.stderr.read() or "").splitlines() if ln.strip()]
    )

    pps_series, pkts_series = [], []
    for ln in lines:
        if not ln.startswith("{"):
            continue
        try:
            d = json.loads(ln)
            pps_series.append(d.get("pps", 0))
            pkts_series.append(d.get("packets", 0))
        except Exception:
            pass

    if not pps_series:
        return None

    # Drop first 4 samples (2 s warm-up at interval=0.5s)
    steady = pps_series[4:] if len(pps_series) > 6 else pps_series

    def _pct(arr: list, p: float) -> float:
        s = sorted(arr)
        idx = min(int(len(s) * p / 100), len(s) - 1)
        return round(s[idx], 1)

    return {
        "avg_pps":    round(statistics.mean(steady), 1),
        "peak_pps":   round(max(steady), 1),
        "p50_pps":    _pct(steady, 50),
        "p95_pps":    _pct(steady, 95),
        "total_pkts": max(pkts_series) if pkts_series else 0,
        "jitter":     round(statistics.stdev(steady), 1) if len(steady) > 1 else 0.0,
        "err_lines":  stderr_lines,
        "cpu_avg":    round(statistics.mean(cpu_s), 1) if cpu_s else None,
        "cpu_peak":   round(max(cpu_s), 1) if cpu_s else None,
        "rss_mb":     round(statistics.mean(rss_s), 1) if rss_s else None,
    }


def bench_method(method: str, port: int, target: str, threads: int,
                 duration: int, interval: float, runs: int, unsafe: bool) -> dict:
    """Run `runs` times and return aggregate (median) statistics."""
    results = []
    for _ in range(runs):
        r = run_once(method, port, target, threads, duration, interval, unsafe)
        if r:
            results.append(r)
        time.sleep(1)

    if not results:
        return {"method": method, "port": port, "error": "all runs failed / no output"}

    avgs = [r["avg_pps"] for r in results]
    mean_avgs = statistics.mean(avgs)
    cv = (statistics.stdev(avgs) / mean_avgs * 100) if len(avgs) > 1 and mean_avgs > 0 else 0.0

    def med(key):
        vals = [r[key] for r in results if r.get(key) is not None]
        return round(statistics.median(vals), 1) if vals else None

    return {
        "method":     method,
        "port":       port,
        "runs":       len(results),
        "avg_pps":    med("avg_pps"),
        "peak_pps":   med("peak_pps"),
        "p50_pps":    med("p50_pps"),
        "p95_pps":    med("p95_pps"),
        "total_pkts": med("total_pkts"),
        "jitter":     med("jitter"),
        "cv_pct":     round(cv, 1),
        "err_lines":  med("err_lines"),
        "cpu_avg":    med("cpu_avg"),
        "cpu_peak":   med("cpu_peak"),
        "rss_mb":     med("rss_mb"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Output formatters
# ─────────────────────────────────────────────────────────────────────────────

def _fmt(v, unit="", na="N/A") -> str:
    return f"{v}{unit}" if v is not None else na


def print_results_console(results: list[dict]) -> None:
    header = (
        f"  {'Method':<14}  {'Avg PPS':>9}  {'Peak PPS':>9}  "
        f"{'p95 PPS':>9}  {'Jitter':>8}  {'CV%':>5}  "
        f"{'CPU%':>6}  {'RSS MB':>7}"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in results:
        if "error" in r:
            print(f"  {r['method']:<14}  ERROR: {r['error']}")
            continue
        print(
            f"  {r['method']:<14}  "
            f"{_fmt(r['avg_pps']):>9}  {_fmt(r['peak_pps']):>9}  "
            f"{_fmt(r['p95_pps']):>9}  {_fmt(r['jitter']):>8}  "
            f"{_fmt(r['cv_pct'], '%'):>5}  "
            f"{_fmt(r['cpu_avg'], '%'):>6}  {_fmt(r['rss_mb'], 'MB'):>7}"
        )


def build_markdown(
    target: str,
    port: int,
    threads: int,
    duration: int,
    runs: int,
    lat: dict,
    all_results: dict[str, list[dict]],
) -> str:
    lines = []
    lines.append("## Laitoxx DDoS — Community Benchmark Results\n")
    lines.append("**System info** *(fill in your details)*\n")
    lines.append("| Parameter | Value |")
    lines.append("|---|---|")
    lines.append(f"| OS | {platform.platform()} |")
    lines.append("| CPU | <!-- e.g. Intel Core i7-12700K --> |")
    lines.append("| RAM | <!-- e.g. 32 GB --> |")
    lines.append("| Network | <!-- e.g. 1 Gbps fibre --> |")
    lines.append(f"| Target | `{target}` (your own server) |")
    lines.append(f"| Port | {port} |")
    lines.append(f"| Threads | {threads} |")
    lines.append(f"| Duration per run | {duration} s |")
    lines.append(f"| Runs per method | {runs} |")
    lines.append("")

    lines.append("**Baseline latency**\n")
    lines.append("| | p50 | p95 | max |")
    lines.append("|---|---|---|---|")
    c = lat["connect"]
    lines.append(f"| TCP connect | {c['p50']} ms | {c['p95']} ms | {c['max']} ms |")
    if lat.get("tls"):
        tl = lat["tls"]
        lines.append(f"| TLS handshake | {tl['p50']} ms | {tl['p95']} ms | {tl['max']} ms |")
    lines.append("")

    header_row = "| Method | Avg PPS | Peak PPS | p50 PPS | p95 PPS | Jitter | CV% | CPU% | RSS MB |"
    sep_row    = "|---|---|---|---|---|---|---|---|---|"

    group_titles = {
        "l7_basic":      "### L7 HTTP Basic",
        "l7_bypass":     "### L7 Protection Bypass",
        "l7_specialized":"### L7 Specialized",
        "l4":            "### L4 Transport",
    }

    for key, title in group_titles.items():
        results = all_results.get(key, [])
        if not results:
            continue
        lines.append(f"{title}\n")
        lines.append(header_row)
        lines.append(sep_row)
        for r in results:
            if "error" in r:
                lines.append(f"| `{r['method']}` | *error* | | | | | | | |")
                continue
            cpu = _fmt(r["cpu_avg"], "%")
            rss = _fmt(r["rss_mb"], " MB")
            lines.append(
                f"| `{r['method']}` | {_fmt(r['avg_pps'])} | {_fmt(r['peak_pps'])} | "
                f"{_fmt(r['p50_pps'])} | {_fmt(r['p95_pps'])} | "
                f"{_fmt(r['jitter'])} | {_fmt(r['cv_pct'], '%')} | {cpu} | {rss} |"
            )
        lines.append("")

    lines.append("---")
    lines.append("*Generated by [Laitoxx DDoS benchmark.py](https://github.com/laitoxx/laitoxx-ddos)*")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="benchmark.py",
        description=(
            "Laitoxx DDoS community benchmark script.\n"
            "Run against YOUR OWN server only.\n\n"
            "Examples:\n"
            "  python benchmark.py --target my-vps.example.com --port 443\n"
            "  python benchmark.py --target 192.168.1.100 --port 80 --category l4\n"
            "  python benchmark.py --target my-server.com --methods GET,H2RST,UDP --threads 16\n"
            "  python benchmark.py --target my-server.com --port 443 --markdown > results.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--target", required=True, metavar="HOST",
        help="Your server hostname or IP (you must own this target)",
    )
    p.add_argument(
        "--port", type=int, default=DEFAULT_PORT_HTTPS, metavar="PORT",
        help=f"Default port for L7 methods (default: {DEFAULT_PORT_HTTPS})",
    )
    p.add_argument(
        "--port-http", type=int, default=DEFAULT_PORT_HTTP, metavar="PORT",
        help=f"Port for L4/raw methods (default: {DEFAULT_PORT_HTTP})",
    )
    p.add_argument(
        "--threads", type=int, default=8, metavar="N",
        help="Thread count per attack (default: 8)",
    )
    p.add_argument(
        "--duration", type=int, default=20, metavar="SEC",
        help="Duration of each run in seconds (default: 20)",
    )
    p.add_argument(
        "--runs", type=int, default=3, metavar="N",
        help="Number of runs per method for stability CV (default: 3)",
    )
    p.add_argument(
        "--interval", type=float, default=0.5, metavar="SEC",
        help="Stats polling interval (default: 0.5)",
    )
    p.add_argument(
        "--category",
        choices=["l7_basic", "l7_bypass", "l7_specialized", "l4", "all"],
        default="all",
        help="Benchmark only one category (default: all)",
    )
    p.add_argument(
        "--methods", metavar="CODE[,CODE...]",
        help="Comma-separated list of specific method codes to benchmark, e.g. GET,H2RST,UDP",
    )
    p.add_argument(
        "--unsafe", action="store_true",
        help=(
            "Pass --unsafe to console_app.py (skip Proof-of-Ownership check). "
            "Only use this if you own the target and the PoO wizard cannot reach it."
        ),
    )
    p.add_argument(
        "--no-latency-probe", action="store_true",
        help="Skip baseline latency measurement",
    )
    p.add_argument(
        "--markdown", action="store_true",
        help="Print Markdown output in addition to console output (or pipe to file)",
    )
    p.add_argument(
        "--output", metavar="FILE",
        help="Save Markdown output to this file (implies --markdown)",
    )
    p.add_argument(
        "--json-out", metavar="FILE",
        help="Save raw results as JSON to this file",
    )
    return p


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    target = args.target
    if target == DEFAULT_TARGET:
        parser.error(
            "Please replace the DEFAULT_TARGET placeholder with your own server "
            "hostname or IP, or pass --target on the command line."
        )

    print(f"Laitoxx DDoS benchmark — {platform.platform()}")
    print(f"Target: {target}   Threads: {args.threads}   "
          f"Duration: {args.duration}s/run   Runs: {args.runs}\n")

    # ── Determine which methods to run ───────────────────────────────────────
    if args.methods:
        requested = [m.strip().upper() for m in args.methods.split(",")]
        all_flat = {code: port for grp in METHOD_GROUPS.values() for code, port in grp}
        method_list = []
        for code in requested:
            if code not in all_flat:
                print(f"WARNING: unknown method '{code}', skipping.", file=sys.stderr)
                continue
            # Override port with --port or --port-http depending on category
            is_l4 = any(code == c for c, _ in METHOD_GROUPS["l4"])
            port = args.port_http if is_l4 else args.port
            method_list.append((code, port))
        run_groups = {"custom": method_list}
    else:
        categories = (
            list(METHOD_GROUPS.keys())
            if args.category == "all"
            else [args.category]
        )
        run_groups = {}
        for cat in categories:
            methods = []
            for code, default_port in METHOD_GROUPS[cat]:
                port = args.port_http if cat == "l4" else args.port
                methods.append((code, port))
            run_groups[cat] = methods

    # ── Baseline latency probe ────────────────────────────────────────────────
    lat: dict = {"connect": {}, "tls": None, "errors": 0}
    if not args.no_latency_probe:
        use_tls = args.port in (443, 8443)
        print(f"Probing baseline latency to {target}:{args.port} (TLS={use_tls}) ...")
        lat = probe_latency(target, args.port, tls=use_tls)
        c = lat["connect"]
        print(f"  TCP connect  p50={c['p50']} ms  p95={c['p95']} ms  max={c['max']} ms")
        if lat["tls"]:
            tl = lat["tls"]
            print(f"  TLS          p50={tl['p50']} ms  p95={tl['p95']} ms  max={tl['max']} ms")
        if lat["errors"]:
            print(f"  WARNING: {lat['errors']}/10 probes failed (connectivity issues?)")
        print()

    # ── Run benchmarks ────────────────────────────────────────────────────────
    all_results: dict[str, list[dict]] = {}

    for group_name, methods in run_groups.items():
        print(f"{'='*60}")
        print(f"  {group_name.upper().replace('_', ' ')}")
        print(f"{'='*60}")
        group_res = []
        for method, port in methods:
            print(f"  [{method:<14}] ", end="", flush=True)
            r = bench_method(
                method, port, target,
                args.threads, args.duration, args.interval,
                args.runs, args.unsafe,
            )
            group_res.append(r)
            if "error" in r:
                print(f"ERROR: {r['error']}")
            else:
                cpu  = f"{r['cpu_avg']}%" if r["cpu_avg"] is not None else "N/A"
                rss  = f"{r['rss_mb']} MB" if r["rss_mb"] is not None else "N/A"
                print(
                    f"avg={r['avg_pps']:>9.1f} pps  peak={r['peak_pps']:>9.1f}  "
                    f"p95={r['p95_pps']:>9.1f}  jitter={r['jitter']:>8.1f}  "
                    f"cv={r['cv_pct']:>4.1f}%  cpu={cpu:>7}  rss={rss:>8}"
                )
        all_results[group_name] = group_res
        print()

    # ── JSON output ───────────────────────────────────────────────────────────
    if args.json_out:
        payload = {"target": target, "latency": lat, "results": all_results}
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"Raw JSON saved to: {args.json_out}")

    # ── Markdown output ───────────────────────────────────────────────────────
    if args.markdown or args.output:
        md = build_markdown(
            target, args.port, args.threads,
            args.duration, args.runs, lat, all_results,
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"Markdown saved to: {args.output}")
        else:
            print("\n" + "=" * 60)
            print("  MARKDOWN OUTPUT")
            print("=" * 60)
            print(md)

    print("\nDone. Share your results in a GitHub issue — see README.md#community-benchmarks")


if __name__ == "__main__":
    main()
