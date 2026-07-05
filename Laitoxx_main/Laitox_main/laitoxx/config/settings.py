"""Application settings: defaults, load, save."""

import json
from pathlib import Path

_CONFIG_DIR  = Path(__file__).resolve().parents[2] / ".config"
CONFIG_FILE  = _CONFIG_DIR / "settings.json"

DEFAULT_SETTINGS: dict = {
    "default_port":     80,
    "default_threads":  100,
    "default_duration": 60,
    "default_rps":      1000,
    "max_threads":      10000,
    "max_duration":     3600,
    "max_rps":          100000,
    "log_level":        "ALL",
    "auto_monitor":     True,
    "headers_dir":      "",
    "ip_ranges_dir":    "",
    "ssl_verify":       True,
    "connect_timeout":  10,
    "read_timeout":     30,
    "max_retries":      3,
}


def load() -> dict:
    """Return merged settings (file overrides defaults; missing keys filled in)."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        try:
            saved = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return {**DEFAULT_SETTINGS, **saved}
        except Exception:
            pass
    return dict(DEFAULT_SETTINGS)


def save(settings: dict) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(settings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
