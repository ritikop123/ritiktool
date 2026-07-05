"""Proof-of-Ownership (PoO) — public façade.

Usage
-----
::

    from laitoxx.poo import require_ownership, VerificationResult, PoOMethod

    result = require_ownership(target, method="dns_txt")   # or "reverse_connect"
    if not result.ok:
        print(result.error)
        return

The module also exposes ``is_verified(target)`` for quick cached checks and
``unsafe_bypass()`` for the ``--unsafe`` / ``--i-know-what-im-doing`` paths.
"""

from dataclasses import dataclass, field
from typing import Literal

from .token import is_verified, mark_verified, generate, get_record, all_verified, revoke

PoOMethod = Literal["dns_txt", "reverse_connect"]


@dataclass
class VerificationResult:
    ok:      bool
    target:  str
    method:  PoOMethod | None = None
    error:   str              = ""
    cached:  bool             = False    # True when result came from stored cache
    bypassed: bool            = False    # True when --unsafe was used


# ── Quick cache check ─────────────────────────────────────────────────────

def check_cached(target: str) -> VerificationResult | None:
    """Return a cached VerificationResult if the target is already verified,
    else None.  Call this first — no network I/O involved.
    """
    rec = get_record(target)
    if rec:
        return VerificationResult(
            ok=True, target=target,
            method=rec.get("method"),
            cached=True,
        )
    return None


def unsafe_bypass(target: str) -> VerificationResult:
    """Return a VerificationResult that marks a target as allowed without
    any real ownership check.  Only used when the user explicitly passes
    ``--unsafe`` or ``--i-know-what-im-doing``.
    """
    return VerificationResult(ok=True, target=target, bypassed=True)


# ── Interactive verification (blocking) ───────────────────────────────────

def verify_dns(domain: str, token: str | None = None) -> VerificationResult:
    """Run the DNS TXT verification flow synchronously.

    Generates a token (or reuses *token*), checks the TXT record once,
    and on success persists the result to the cache.
    """
    from .dns_verify import check, txt_record_name, has_dnspython

    if not has_dnspython():
        return VerificationResult(
            ok=False, target=domain, method="dns_txt",
            error="dnspython not installed.  Run: pip install dnspython",
        )

    tok = token or generate()
    ok, reason = check(domain, tok)
    if ok:
        mark_verified(domain, tok, "dns_txt")
        return VerificationResult(ok=True, target=domain, method="dns_txt")
    return VerificationResult(ok=False, target=domain, method="dns_txt", error=reason)


def verify_reverse(
    ip: str,
    token: str | None = None,
    timeout: float = 300,
) -> tuple["VerificationResult", "ReverseVerifyServer"]:  # noqa: F821
    """Create a reverse-connection listener and return ``(result, server)``.

    The caller is responsible for showing the curl instruction and then calling
    ``server.wait(timeout)`` (which blocks).  This function is split so that
    TUI / GUI can show the prompt before blocking.

    Typical usage::

        result_placeholder, server = verify_reverse(ip, token)
        # … show instruction to user …
        with server:
            ok, src_ip = server.wait(timeout)
        if ok:
            result = VerificationResult(ok=True, target=ip, method="reverse_connect")
            token_mod.mark_verified(ip, server.token, "reverse_connect")
    """
    from .reverse_verify import ReverseVerifyServer

    tok    = token or generate()
    server = ReverseVerifyServer(token=tok, expected_ip=ip)
    # Return early — blocking happens in server.wait()
    placeholder = VerificationResult(ok=False, target=ip, method="reverse_connect",
                                     error="Waiting for connection…")
    return placeholder, server


__all__ = [
    "VerificationResult",
    "PoOMethod",
    "check_cached",
    "unsafe_bypass",
    "verify_dns",
    "verify_reverse",
    "is_verified",
    "mark_verified",
    "generate",
    "get_record",
    "all_verified",
    "revoke",
]
