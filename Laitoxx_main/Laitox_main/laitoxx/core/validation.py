"""Target validation and L7 classification helpers."""

import re

from .taxonomy import ATTACK_TO_CATEGORY, L7_CATEGORIES

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
)


def is_ip(target: str) -> bool:
    return bool(_IP_RE.match(target.strip()))


def is_domain(target: str) -> bool:
    return bool(_DOMAIN_RE.match(target.strip()))


def validate_target(target: str) -> str | None:
    """Return ``'ip'`` | ``'domain'`` | ``None`` (invalid)."""
    t = target.strip()
    if is_ip(t):
        return "ip"
    if is_domain(t):
        return "domain"
    return None


def is_l7_attack(attack_name: str) -> bool:
    return ATTACK_TO_CATEGORY.get(attack_name, "") in L7_CATEGORIES
