"""L7 Proof-of-Ownership via DNS TXT record.

Flow
----
1. Caller calls ``challenge(domain)`` → gets a token string.
2. User adds a TXT record:
       laitoxx-poo.<domain>  IN TXT  "<token>"
3. Caller calls ``check(domain, token)`` → True/False.
4. On success the caller should call ``token.mark_verified(domain, token, "dns_txt")``.

The TXT lookup is intentionally done with the system resolver (no caching
suppression) so propagation just requires waiting for DNS TTL.
"""

import socket
from typing import Iterator

from .token import TOKEN_DNS_PREFIX

# ── Optional dnspython for proper TXT resolution ─────────────────────────
try:
    import dns.resolver as _dns_resolver   # type: ignore[import]
    _HAS_DNSPYTHON = True
except ImportError:
    _dns_resolver = None                   # type: ignore[assignment]
    _HAS_DNSPYTHON = False


def txt_record_name(domain: str) -> str:
    """Return the full TXT record name the user must create."""
    return f"{TOKEN_DNS_PREFIX}.{domain.strip().lower().rstrip('.')}"


def _query_txt_dnspython(fqdn: str) -> Iterator[str]:
    """Yield TXT record strings using dnspython (preferred)."""
    try:
        answers = _dns_resolver.resolve(fqdn, "TXT", lifetime=10)
        for rdata in answers:
            for chunk in rdata.strings:
                yield chunk.decode(errors="replace")
    except Exception:
        return


def _query_txt_socket(fqdn: str) -> Iterator[str]:
    """Fallback: resolve via getaddrinfo trick won't work for TXT.

    We can't get TXT records with the standard socket library, so this
    path is a no-op.  Users should ``pip install dnspython`` for reliable
    TXT resolution.
    """
    return
    yield   # make it a generator


def query_txt(fqdn: str) -> list[str]:
    """Return all TXT record strings for *fqdn*."""
    if _HAS_DNSPYTHON:
        return list(_query_txt_dnspython(fqdn))
    return list(_query_txt_socket(fqdn))


def check(domain: str, token: str) -> tuple[bool, str]:
    """Query DNS and compare against *token*.

    Returns ``(True, "")`` on success or ``(False, reason)`` on failure.
    """
    if not _HAS_DNSPYTHON:
        return False, (
            "dnspython is not installed.  "
            "Run: pip install dnspython"
        )

    fqdn   = txt_record_name(domain)
    values = query_txt(fqdn)

    if not values:
        return False, (
            f"No TXT records found for {fqdn}\n"
            "Make sure DNS has propagated (can take up to 60 s)."
        )

    token_lower = token.strip().lower()
    for v in values:
        if v.strip().lower() == token_lower:
            return True, ""

    return False, (
        f"TXT record found but token does not match.\n"
        f"Expected: {token}\n"
        f"Got:      {', '.join(values)}"
    )


def has_dnspython() -> bool:
    return _HAS_DNSPYTHON
