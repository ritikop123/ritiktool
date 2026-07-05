"""DNS resolution with optional SOCKS proxy routing (anti-leak)."""

import socket

from .validation import is_ip

try:
    import socks as _socks_mod
    _HAS_PYSOCKS = True
except ImportError:
    _socks_mod = None
    _HAS_PYSOCKS = False


def resolve_domain_safe(domain: str, proxy: dict | None = None) -> str | None:
    """Resolve *domain* to an IPv4 address string.

    When a SOCKS proxy is configured and PySocks is available the DNS query is
    sent through the proxy to prevent leaks.  For HTTP(S) proxies, or when
    PySocks is missing, resolution falls back to the system resolver.

    Returns an IPv4 string, or ``None`` on failure.
    """
    domain = domain.strip()

    if is_ip(domain):
        return domain

    # Proxy-routed DNS (SOCKS only — prevents leak)
    if proxy and _HAS_PYSOCKS and proxy.get("type", "").startswith("socks"):
        socks_type = _socks_mod.SOCKS5 if "5" in proxy["type"] else _socks_mod.SOCKS4
        try:
            s = _socks_mod.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(
                socks_type,
                proxy["host"],
                proxy["port"],
                username=proxy.get("username") or None,
                password=proxy.get("password") or None,
                rdns=True,
            )
            s.settimeout(10)
            s.connect((domain, 80))
            ip = s.getpeername()[0]
            s.close()
            return ip
        except Exception:
            pass  # fall through to system resolver

    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def has_pysocks() -> bool:
    """Return True if PySocks is installed."""
    return _HAS_PYSOCKS
