"""Proxy list persistence and parsing."""

import json
import re
from pathlib import Path

_CONFIG_DIR  = Path(__file__).resolve().parents[2] / ".config"
PROXIES_FILE = _CONFIG_DIR / "proxies.json"

DEFAULT_PROXY: dict = {
    "type":     "http",   # http | https | socks4 | socks5
    "host":     "",
    "port":     8080,
    "username": "",
    "password": "",
    "enabled":  True,
}

# Regex for optional scheme prefix
_SCHEME_RE = re.compile(r"^(https?|socks[45])://(.+)$", re.IGNORECASE)
# Regex for user:pass@rest
_AUTH_RE   = re.compile(r"^([^:]+):([^@]+)@(.+)$")


def load() -> list[dict]:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if PROXIES_FILE.exists():
        try:
            return json.loads(PROXIES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def save(proxies: list[dict]) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PROXIES_FILE.write_text(
        json.dumps(proxies, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def parse_line(line: str) -> dict | None:
    """Parse a proxy string into a proxy dict.

    Supported formats::

        host:port
        host:port:username:password
        type://host:port
        type://username:password@host:port

    Returns a proxy dict or ``None`` if the line cannot be parsed.
    """
    line = line.strip()
    if not line:
        return None

    ptype = "http"
    username = ""
    password = ""

    scheme_m = _SCHEME_RE.match(line)
    if scheme_m:
        ptype = scheme_m.group(1).lower()
        line  = scheme_m.group(2)

    auth_m = _AUTH_RE.match(line)
    if auth_m:
        username = auth_m.group(1)
        password = auth_m.group(2)
        line     = auth_m.group(3)

    parts = line.split(":")
    if len(parts) == 2:
        host, port_s = parts
    elif len(parts) == 4 and not username:
        host, port_s, username, password = parts
    else:
        return None

    try:
        port = int(port_s)
        if not 1 <= port <= 65535:
            return None
    except ValueError:
        return None

    if not host:
        return None

    return {
        "type":     ptype,
        "host":     host,
        "port":     port,
        "username": username,
        "password": password,
        "enabled":  True,
    }
