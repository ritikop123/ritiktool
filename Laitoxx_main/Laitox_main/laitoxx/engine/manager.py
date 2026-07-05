"""AttackManager — orchestrates all running attacks across both engines."""

import datetime
import os
import time
import threading
from collections import defaultdict
from pathlib import Path

from ..core.taxonomy import ATTACK_NAME_MAP, RAW_SOCKET_ATTACKS, L7_CATEGORIES, ATTACK_TO_CATEGORY
from ..core.validation import is_domain
from ..core.dns import resolve_domain_safe
from ..system.admin import is_admin, prompt_relaunch_as_admin
from ..poo import check_cached, unsafe_bypass, VerificationResult
from .bypass import (
    GO_BYPASS_AVAILABLE,
    GO_BYPASS_METHODS,
    GoBypassInstance,
    fn_name_for,
    set_proxy as _go_set_proxy,
    clear_proxy as _go_clear_proxy,
)
from .instance import AttackInstance

_PROJECT_ROOT = str(Path(__file__).resolve().parents[2])

# Optional C++ native engine
try:
    import laitoxx_core
    _NATIVE_AVAILABLE = True
except ImportError:
    laitoxx_core = None  # type: ignore[assignment]
    _NATIVE_AVAILABLE = False


class AttackManager:
    """Central controller: validates, routes, and tracks all attacks."""

    def __init__(
        self,
        settings: dict,
        proxies: list[dict] | None = None,
        unsafe: bool = False,
    ) -> None:
        self.settings   = settings
        self.proxies    = proxies or []
        self.unsafe     = unsafe          # True → skip PoO checks entirely
        self.attacks: dict[int, AttackInstance] = {}
        self._lock      = threading.Lock()

        self._headers_dir   = settings.get("headers_dir")  or os.path.join(_PROJECT_ROOT, "headers")
        self._ip_ranges_dir = settings.get("ip_ranges_dir") or os.path.join(_PROJECT_ROOT, "ip-ranges")

        self.logs: list[tuple[str, str, str]] = []   # (timestamp, level, message)
        self.stats: dict = {
            "total_started":  0,
            "total_finished": 0,
            "total_stopped":  0,
            "peak_pps":       0,
            "peak_bps":       0.0,
            "total_packets":  0,
            "attack_types":   defaultdict(int),
        }
        self.session_start = datetime.datetime.now()

        self._log("INFO",
                  f"Engine: {'Native C++' if _NATIVE_AVAILABLE else 'Mock fallback'}")
        self._log("INFO",
                  f"Go bypass: {'bypass.dll loaded' if GO_BYPASS_AVAILABLE else 'not available'}")

    # ── Logging ───────────────────────────────────────────────────────────

    def _log(self, level: str, msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append((ts, level, msg))
            if len(self.logs) > 5000:
                self.logs = self.logs[-3000:]

    # ── Proxy helpers ─────────────────────────────────────────────────────

    def _active_proxy(self) -> dict | None:
        """Return first enabled proxy with a host, or ``None``."""
        return next(
            (p for p in self.proxies if p.get("enabled", True) and p.get("host")),
            None,
        )

    def _proxy_list_for_cpp(self) -> list[str]:
        """Build C++ proxy strings: ``host:port[:user:pass]``."""
        result = []
        for p in self.proxies:
            if not p.get("enabled", True) or not p.get("host"):
                continue
            entry = f"{p['host']}:{p.get('port', 8080)}"
            if p.get("username"):
                entry += f":{p['username']}:{p.get('password', '')}"
            result.append(entry)
        return result

    # ── Attack lifecycle ──────────────────────────────────────────────────

    def start_attack(
        self,
        attack_type: str,
        target: str,
        port: int = 80,
        duration: int = 60,
        threads: int = 100,
        rps: int = 1000,
    ) -> AttackInstance | None:
        backend_code = ATTACK_NAME_MAP.get(attack_type, attack_type.upper())

        if backend_code in RAW_SOCKET_ATTACKS and not is_admin():
            self._log("ERROR", f"{attack_type} requires Administrator privileges")
            prompt_relaunch_as_admin(attack_type)
            return None

        # ── Proof-of-Ownership gate ──────────────────────────────────────
        if not self.unsafe:
            poo = check_cached(target)
            if poo is None:
                # Determine which method is needed
                category = ATTACK_TO_CATEGORY.get(attack_type, "")
                method   = "dns_txt" if category in L7_CATEGORIES else "reverse_connect"
                self._log("ERROR",
                          f"[PoO] {target} is not verified. "
                          f"Run the {'DNS TXT' if method == 'dns_txt' else 'reverse-connect'} "
                          f"verification first, or use --unsafe to skip.")
                return None
            if poo.cached:
                self._log("INFO", f"[PoO] {target} — ownership verified (cached)")

        # Resolve domain → IP so C++ always receives an IP
        original_target = target
        resolved_ip = self._resolve(target)
        if resolved_ip is None:
            return None

        native_inst = (
            self._start_go(backend_code, original_target, port, threads, duration, rps)
            or self._start_cpp(backend_code, resolved_ip, port, duration, threads)
        )

        attack = AttackInstance(
            attack_type_gui=attack_type, backend_code=backend_code,
            target=original_target, port=port, duration=duration,
            threads=threads, rps=rps, native_instance=native_inst,
        )
        with self._lock:
            self.attacks[attack.id] = attack
            self.stats["total_started"] += 1
            self.stats["attack_types"][attack_type] += 1

        mode = ("go-bypass" if isinstance(native_inst, GoBypassInstance)
                else "native" if native_inst else "mock")
        ip_tag = f" ({resolved_ip})" if resolved_ip != original_target else ""
        self._log("INFO",
                  f"[{mode}] {attack_type} ({backend_code}) → "
                  f"{attack.display_target}{ip_tag}  "
                  f"threads={threads} dur={duration}s")
        return attack

    def _resolve(self, target: str) -> str | None:
        if not is_domain(target):
            return target
        proxy = self._active_proxy()
        self._log("INFO", f"Resolving {target}…")
        if proxy and proxy["type"].startswith("socks"):
            self._log("INFO", f"DNS via SOCKS proxy {proxy['host']}:{proxy['port']}")
        ip = resolve_domain_safe(target, proxy)
        if ip is None:
            self._log("ERROR", f"DNS resolution failed for '{target}'")
        else:
            self._log("INFO", f"Resolved {target} → {ip}")
        return ip

    def _start_go(
        self, code: str, hostname: str, port: int,
        threads: int, duration: int, rps: int,
    ) -> GoBypassInstance | None:
        if code not in GO_BYPASS_METHODS:
            return None

        if not GO_BYPASS_AVAILABLE:
            self._log("WARNING",
                      f"{code}: Go bypass DLL not available, falling back to C++")
            return None

        proxy = self._active_proxy()
        if proxy and proxy.get("host"):
            kind = proxy.get("type", "socks5")
            addr = f"{proxy['host']}:{proxy.get('port', 9050)}"
            _go_set_proxy(kind, addr,
                          proxy.get("username", ""), proxy.get("password", ""))
            self._log("INFO", f"Go bypass proxy: {kind}://{addr}")
        else:
            _go_clear_proxy()

        scheme = "https" if port in (443, 8443) else "http"
        job_id = f"{code.lower()}-{int(time.time())}"
        inst = GoBypassInstance(
            job_id=job_id, fn_name=fn_name_for(code),
            scheme=scheme, host=hostname, port=port,
            threads=threads, duration=duration, rps=rps,
        )
        try:
            inst.start()
            self._log("INFO", f"Go bypass started: {fn_name_for(code)} (job={job_id})")
            return inst
        except Exception as exc:
            self._log("ERROR", f"Go bypass failed ({code}): {exc}")
            return None

    def _start_cpp(
        self, code: str, ip: str, port: int, duration: int, threads: int,
    ) -> object | None:
        if not _NATIVE_AVAILABLE:
            return None
        try:
            cfg = laitoxx_core.AttackConfig()
            cfg.target_ip      = ip
            cfg.port           = port
            cfg.duration_seconds = duration
            cfg.thread_count   = threads
            cfg.headers_dir    = self._headers_dir
            cfg.ip_ranges_dir  = self._ip_ranges_dir
            cfg.enable_user_agent       = True
            cfg.enable_accept           = True
            cfg.enable_accept_language  = True
            cfg.enable_accept_encoding  = True
            cfg.enable_referer          = True

            proxy_list = self._proxy_list_for_cpp()
            if proxy_list:
                cfg.use_proxy     = True
                cfg.proxy_list    = proxy_list
                active = self._active_proxy()
                cfg.proxy_type    = active["type"] if active else "http"
                cfg.proxy_retries = self.settings.get("max_retries", 3)
                self._log("INFO", f"Proxy enabled: {len(proxy_list)} proxies")

            inst = laitoxx_core.AttackInstance(code, cfg)
            inst.set_log_callback(lambda msg: self._log("DEBUG", msg))
            inst.start()
            return inst
        except Exception as exc:
            self._log("ERROR", f"C++ start failed ({code}): {exc}")
            return None

    def stop_attack(self, attack_id: int) -> None:
        with self._lock:
            attack = self.attacks.get(attack_id)
        if attack and attack.status == "Running":
            attack.stop()
            self.stats["total_stopped"] += 1
            self._log("WARNING", f"Stopped {attack.attack_type} → {attack.display_target}")

    def stop_all(self) -> None:
        with self._lock:
            ids = list(self.attacks.keys())
        for aid in ids:
            self.stop_attack(aid)

    def remove_finished(self) -> int:
        """Remove stopped/finished attacks from registry; return count removed."""
        with self._lock:
            done = [aid for aid, a in self.attacks.items()
                    if a.status in ("Stopped", "Finished")]
            for aid in done:
                del self.attacks[aid]
        return len(done)

    # ── Tick (called every second) ────────────────────────────────────────

    def tick(self) -> None:
        with self._lock:
            attacks = list(self.attacks.values())

        for attack in attacks:
            prev = attack.status
            attack.tick()
            if prev == "Running" and attack.status == "Finished":
                self.stats["total_finished"] += 1
                self._log("INFO", f"Attack #{attack.id} finished")

        total_pps = sum(a.pps for a in attacks)
        total_bps = sum(a.bps for a in attacks)
        self.stats["peak_pps"]      = max(self.stats["peak_pps"], total_pps)
        self.stats["peak_bps"]      = max(self.stats["peak_bps"], total_bps)
        self.stats["total_packets"] += total_pps

    # ── Aggregate properties ──────────────────────────────────────────────

    @property
    def total_pps(self) -> int:
        return sum(a.pps for a in self.attacks.values())

    @property
    def total_bps(self) -> float:
        return round(sum(a.bps for a in self.attacks.values()), 1)

    @property
    def total_connections(self) -> int:
        return sum(a.connections for a in self.attacks.values())

    def get_running(self) -> list[AttackInstance]:
        return [a for a in self.attacks.values() if a.status == "Running"]

    def get_all(self) -> list[AttackInstance]:
        return list(self.attacks.values())


def native_available() -> bool:
    return _NATIVE_AVAILABLE
