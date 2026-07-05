#!/usr/bin/env python3
"""
Laitoxx benchmark harness — measures real performance metrics for every method.
Runs against laitoxx.su (author's test domain) with --unsafe.

Collected per run:
  throughput:  pps (avg, peak, p95), bytes/s (estimated)
  latency:     connect_ms, tls_ms (probe before attack)
  error_rate:  stderr lines / total intervals
  jitter:      stddev of per-interval pps
  client cost: cpu%, rss_mb, open_fd (sampled during run)
  stability:   cv (coefficient of variation across 3 runs)
"""
import json
import os
import re
import subprocess
import sys
import time
import statistics
import socket
import ssl
import platform
import psutil

ROOT     = os.path.dirname(os.path.abspath(__file__))
SCRIPT   = os.path.join(ROOT, "console_app.py")
PYTHON   = sys.executable
TARGET   = "laitoxx.su"
PORT_HTTP  = 80
PORT_HTTPS = 443
THREADS  = 8
DURATION = 20        # seconds per run
INTERVAL = 0.5       # stat interval
RUNS     = 3         # runs per method for stability CV

# Methods and their ports
L7_BASIC = [
    ("GET",        PORT_HTTPS),
    ("POST",       PORT_HTTPS),
    ("HEAD",       PORT_HTTPS),
    ("OVH",        PORT_HTTPS),
    ("RHEX",       PORT_HTTPS),
    ("STOMP",      PORT_HTTPS),
    ("STRESS",     PORT_HTTPS),
    ("DYN",        PORT_HTTPS),
    ("NULL",       PORT_HTTPS),
    ("COOKIE",     PORT_HTTPS),
    ("PPS",        PORT_HTTPS),
    ("EVEN",       PORT_HTTPS),
    ("DOWNLOADER", PORT_HTTPS),
]
L7_BYPASS = [
    ("CFB",    PORT_HTTPS),
    ("CFBUAM", PORT_HTTPS),
    ("DGB",    PORT_HTTPS),
    ("AVB",    PORT_HTTPS),
    ("BOT",    PORT_HTTPS),
    ("GSB",    PORT_HTTPS),
    ("BYPASS", PORT_HTTPS),
    ("KILLER", PORT_HTTPS),
]
L7_SPECIALIZED = [
    ("WS",         PORT_HTTPS),
    ("H2STREAM",   PORT_HTTPS),
    ("H2HPACK",    PORT_HTTPS),
    ("H2RST",      PORT_HTTPS),
    ("H2SETTINGS", PORT_HTTPS),
    ("QUIC",       PORT_HTTPS),
    ("GRAPHQL",    PORT_HTTPS),
    ("WEBDAV",     PORT_HTTPS),
]
L4_TRANSPORT = [
    ("UDP",        PORT_HTTP),
    ("CPS",        PORT_HTTP),
    ("CONNECTION", PORT_HTTP),
    ("TCP-SYN",    PORT_HTTP),
]
# Admin-only L4 skipped in automated run (raw sockets need root):
# TCP-ACK, RST, ICMP, SNMP, CHARGEN, CLDAP, RDP-AMP, NETBIOS


def probe_latency(host: str, port: int, tls: bool) -> dict:
    """Measure connect + TLS handshake latency (10 probes, return p50/p95/p99/max)."""
    connect_times = []
    tls_times = []
    errors = 0
    for _ in range(10):
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((host, port), timeout=5)
            connect_ms = (time.perf_counter() - t0) * 1000

            if tls:
                ctx = ssl.create_default_context()
                t1 = time.perf_counter()
                ssock = ctx.wrap_socket(sock, server_hostname=host)
                tls_ms = (time.perf_counter() - t1) * 1000
                ssock.close()
            else:
                sock.close()
                tls_ms = 0.0

            connect_times.append(connect_ms)
            if tls:
                tls_times.append(tls_ms)
        except Exception:
            errors += 1

    def pcts(arr):
        if not arr:
            return dict(p50=0, p95=0, p99=0, max=0, mean=0)
        s = sorted(arr)
        n = len(s)
        return dict(
            p50=round(s[int(n*0.50)], 1),
            p95=round(s[min(int(n*0.95), n-1)], 1),
            p99=round(s[min(int(n*0.99), n-1)], 1),
            max=round(s[-1], 1),
            mean=round(statistics.mean(s), 1),
        )

    return dict(
        connect=pcts(connect_times),
        tls=pcts(tls_times) if tls else None,
        probe_errors=errors,
    )


def run_once(method: str, port: int) -> dict | None:
    """Run one attack, return stats dict or None on failure."""
    cmd = [
        PYTHON, "-u", SCRIPT,
        "--method", method,
        "--target", TARGET,
        "--port", str(port),
        "--threads", str(THREADS),
        "--duration", str(DURATION),
        "--rps", "0",
        "--json",
        "--interval", str(INTERVAL),
        "--unsafe",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=ROOT,
    )

    pps_series   = []
    pkts_series  = []
    stderr_lines = 0
    cpu_samples  = []
    rss_samples  = []
    fd_samples   = []

    try:
        ps = psutil.Process(proc.pid)
    except Exception:
        ps = None

    t_start = time.time()

    # Read stdout (JSON stats) in a non-blocking poll
    import threading
    lines = []
    def reader():
        for ln in proc.stdout:
            ln = ln.strip()
            if ln:
                lines.append(ln)
    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # Sample resource usage while running
    while proc.poll() is None and (time.time() - t_start) < DURATION + 5:
        time.sleep(0.5)
        if ps:
            try:
                cpu_samples.append(ps.cpu_percent(interval=None))
                rss_samples.append(ps.memory_info().rss / 1024 / 1024)
                try:
                    fd_samples.append(ps.num_fds() if hasattr(ps, 'num_fds') else ps.num_handles())
                except Exception:
                    pass
            except Exception:
                pass

    proc.wait(timeout=10)
    t.join(timeout=2)

    stderr_out = proc.stderr.read() if proc.stderr else ""
    stderr_lines = len([l for l in stderr_out.splitlines() if l.strip()])

    # Parse JSON lines
    prev_pkts = 0
    for ln in lines:
        if not ln.startswith('{'):
            continue
        try:
            d = json.loads(ln)
            pps_series.append(d.get("pps", 0))
            pkts_series.append(d.get("packets", 0))
            prev_pkts = d.get("packets", 0)
        except Exception:
            pass

    if not pps_series:
        return None

    # Drop first 2 warm-up samples
    steady = pps_series[4:] if len(pps_series) > 6 else pps_series
    if not steady:
        steady = pps_series

    total_pkts = max(pkts_series) if pkts_series else 0

    def _p(arr, pct):
        s = sorted(arr)
        idx = min(int(len(s) * pct / 100), len(s)-1)
        return round(s[idx], 1)

    return dict(
        avg_pps   = round(statistics.mean(steady), 1),
        peak_pps  = round(max(steady), 1),
        p50_pps   = _p(steady, 50),
        p95_pps   = _p(steady, 95),
        total_pkts= total_pkts,
        jitter    = round(statistics.stdev(steady), 1) if len(steady) > 1 else 0,
        err_lines = stderr_lines,
        cpu_avg   = round(statistics.mean(cpu_samples), 1) if cpu_samples else 0,
        cpu_peak  = round(max(cpu_samples), 1) if cpu_samples else 0,
        rss_mb    = round(statistics.mean(rss_samples), 1) if rss_samples else 0,
        fds       = round(statistics.mean(fd_samples), 0) if fd_samples else 0,
    )


def bench_method(method: str, port: int) -> dict:
    """Run RUNS times, compute stability CV, return aggregate."""
    results = []
    for i in range(RUNS):
        r = run_once(method, port)
        if r:
            results.append(r)
        time.sleep(1)  # brief pause between runs

    if not results:
        return dict(method=method, port=port, error="all runs failed")

    avgs  = [r["avg_pps"]  for r in results]
    peaks = [r["peak_pps"] for r in results]

    mean_avgs = statistics.mean(avgs)
    cv = (statistics.stdev(avgs) / mean_avgs * 100) if len(avgs) > 1 and mean_avgs > 0 else 0

    def med(key):
        vals = [r[key] for r in results]
        return round(statistics.median(vals), 1)

    return dict(
        method    = method,
        port      = port,
        runs      = len(results),
        avg_pps   = med("avg_pps"),
        peak_pps  = med("peak_pps"),
        p50_pps   = med("p50_pps"),
        p95_pps   = med("p95_pps"),
        total_pkts= med("total_pkts"),
        jitter    = med("jitter"),
        cv_pct    = round(cv, 1),
        err_lines = med("err_lines"),
        cpu_avg   = med("cpu_avg"),
        cpu_peak  = med("cpu_peak"),
        rss_mb    = med("rss_mb"),
        fds       = med("fds"),
    )


def main():
    print(f"[bench] Target: {TARGET}  Threads: {THREADS}  Duration: {DURATION}s/run  Runs: {RUNS}")
    print(f"[bench] Platform: {platform.platform()}")
    print()

    # Latency probe
    print("[probe] Measuring baseline latency to laitoxx.su:443 (TLS)...")
    lat = probe_latency(TARGET, PORT_HTTPS, tls=True)
    print(f"  connect p50={lat['connect']['p50']}ms p95={lat['connect']['p95']}ms max={lat['connect']['max']}ms")
    if lat['tls']:
        print(f"  TLS    p50={lat['tls']['p50']}ms p95={lat['tls']['p95']}ms max={lat['tls']['max']}ms")
    print()

    all_results = {
        "baseline_latency": lat,
        "l7_basic": [],
        "l7_bypass": [],
        "l7_specialized": [],
        "l4_transport": [],
    }

    groups = [
        ("L7 Basic",      "l7_basic",       L7_BASIC),
        ("L7 Bypass",     "l7_bypass",      L7_BYPASS),
        ("L7 Specialized","l7_specialized", L7_SPECIALIZED),
        ("L4 Transport",  "l4_transport",   L4_TRANSPORT),
    ]

    for group_name, key, methods in groups:
        print(f"{'='*60}")
        print(f"  {group_name}")
        print(f"{'='*60}")
        for method, port in methods:
            print(f"  [{method:12}] ", end="", flush=True)
            r = bench_method(method, port)
            all_results[key].append(r)
            if "error" in r:
                print(f"ERROR: {r['error']}")
            else:
                print(f"avg={r['avg_pps']:>7.1f} pps  peak={r['peak_pps']:>7.1f}  "
                      f"p95={r['p95_pps']:>7.1f}  jitter={r['jitter']:>6.1f}  "
                      f"cv={r['cv_pct']:>4.1f}%  cpu={r['cpu_avg']:>4.1f}%  rss={r['rss_mb']:>5.1f}MB")
        print()

    # Save results
    out = os.path.join(ROOT, "_bench_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"[bench] Results saved to {out}")
    return all_results


if __name__ == "__main__":
    main()
