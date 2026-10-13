"""App settings, from environment variables or a .env file.

Tool connections are NOT configured here: analysts add them from the Integrations page.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _pairs(raw: str) -> dict[str, str]:
    """Parse "a=b,c=d" into {"a": "b", "c": "d"}."""
    pairs = (p.partition("=") for p in raw.split(",") if "=" in p)
    return {k.strip(): v.strip() for k, _, v in pairs if k.strip() and v.strip()}


def _criticality(raw: str) -> dict[str, float]:
    out = {}
    for host, weight in _pairs(raw).items():
        try:
            out[host] = max(0.5, min(2.0, float(weight)))
        except ValueError:
            continue
    return out


DEFAULT_INVENTORY = (
    "10.0.1.10=web-01,10.0.2.20=db-01,10.0.0.5=dc-01,10.0.3.47=hr-laptop-07,10.0.3.12=dev-laptop-03,"
    "shop.example.com=web-01"
)


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: Path(os.getenv("CYBERUNIFY_DB", BASE_DIR / "cyberunify.db")))
    key_file: Path = field(default_factory=lambda: Path(os.getenv("CYBERUNIFY_KEY_FILE", BASE_DIR / ".cyberunify.key")))
    demo_mode: bool = field(default_factory=lambda: _bool("CYBERUNIFY_DEMO", True))
    window_hours: int = field(default_factory=lambda: _int("WINDOW_HOURS", 168))
    ingest_interval: int = field(default_factory=lambda: _int("INGEST_INTERVAL_SECONDS", 60))
    syslog_host: str = field(default_factory=lambda: os.getenv("SYSLOG_BIND", "0.0.0.0"))
    public_url: str = field(default_factory=lambda: os.getenv("PUBLIC_URL", "http://localhost:8000").rstrip("/"))
    admin_password: str = field(default_factory=lambda: os.getenv("CYBERUNIFY_ADMIN_PASSWORD", ""))
    asset_criticality: dict[str, float] = field(
        default_factory=lambda: _criticality(os.getenv("ASSET_CRITICALITY", "web-01=1.5,db-01=1.5,dc-01=1.6")))
    # IP or alias → asset name, so network/web tools link to the right host.
    asset_inventory: dict[str, str] = field(default_factory=lambda: _pairs(os.getenv("ASSET_INVENTORY", DEFAULT_INVENTORY)))


def get_settings() -> Settings:
    return Settings()
