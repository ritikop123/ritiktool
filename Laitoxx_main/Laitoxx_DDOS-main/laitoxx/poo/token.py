"""Cryptographically-secure token generation and verified-target persistence.

Verified targets are cached in ``<project-root>/.config/poo_verified.json``
as a map of ``"target" → {token, method, verified_at, expires_at}``.
Default TTL is 24 hours; after that re-verification is required.
"""

import json
import secrets
import time
from pathlib import Path
from typing import Literal

_CONFIG_DIR    = Path(__file__).resolve().parents[2] / ".config"
_VERIFIED_FILE = _CONFIG_DIR / "poo_verified.json"

TOKEN_TTL: int = 86_400           # 24 h in seconds
TOKEN_DNS_PREFIX = "laitoxx-poo"  # TXT record name: laitoxx-poo.<domain>

VerifyMethod = Literal["dns_txt", "reverse_connect"]


# ── Token generation ──────────────────────────────────────────────────────

def generate() -> str:
    """Return a 32-char URL-safe cryptographically-secure token string."""
    return secrets.token_urlsafe(24)   # 24 raw bytes → 32 base64url chars


# ── Persistent verified-target cache ─────────────────────────────────────

def _load_store() -> dict:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if _VERIFIED_FILE.exists():
        try:
            return json.loads(_VERIFIED_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_store(data: dict) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _VERIFIED_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def mark_verified(target: str, token: str, method: VerifyMethod) -> None:
    """Record that *target* passed PoO verification."""
    now  = time.time()
    data = _load_store()
    data[target] = {
        "token":       token,
        "method":      method,
        "verified_at": now,
        "expires_at":  now + TOKEN_TTL,
    }
    _save_store(data)


def is_verified(target: str) -> bool:
    """Return True iff *target* has a valid, non-expired PoO record."""
    data  = _load_store()
    entry = data.get(target)
    if not entry:
        return False
    if time.time() > entry.get("expires_at", 0):
        data.pop(target)
        _save_store(data)
        return False
    return True


def get_record(target: str) -> dict | None:
    """Return the full record for *target*, or None if absent/expired."""
    data  = _load_store()
    entry = data.get(target)
    if not entry:
        return None
    if time.time() > entry.get("expires_at", 0):
        data.pop(target)
        _save_store(data)
        return None
    return entry


def revoke(target: str) -> None:
    """Force re-verification by removing the cached record."""
    data = _load_store()
    if target in data:
        data.pop(target)
        _save_store(data)


def all_verified() -> dict:
    """Return all currently valid verified targets (prunes expired ones)."""
    data    = _load_store()
    now     = time.time()
    valid   = {t: e for t, e in data.items() if now <= e.get("expires_at", 0)}
    if len(valid) != len(data):
        _save_store(valid)
    return valid
