"""Settings, read from environment variables (or a .env file)."""

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


def _asset_criticality(raw: str) -> dict[str, float]:
    """Parse "web-01=1.5,db-01=1.4" into {"web-01": 1.5, "db-01": 1.4}."""
    result: dict[str, float] = {}
    for pair in raw.split(","):
        if "=" not in pair:
            continue
        host, _, weight = pair.partition("=")
        try:
            result[host.strip()] = max(0.5, min(2.0, float(weight)))
        except ValueError:
            continue
    return result


def _inventory(raw: str) -> dict[str, str]:
    """Parse "10.0.1.10=web-01,10.0.2.20=db-01" into {"10.0.1.10": "web-01", ...}."""
    pairs = (p.partition("=") for p in raw.split(",") if "=" in p)
    return {ip.strip(): host.strip() for ip, _, host in pairs if ip.strip() and host.strip()}


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: Path(os.getenv("CYBERUNIFY_DB", BASE_DIR / "cyberunify.db")))
    demo_mode: bool = field(default_factory=lambda: _bool("CYBERUNIFY_DEMO", True))
    window_hours: int = field(default_factory=lambda: _int("WINDOW_HOURS", 168))
    ingest_interval: int = field(default_factory=lambda: _int("INGEST_INTERVAL_SECONDS", 300))
    asset_criticality: dict[str, float] = field(
        default_factory=lambda: _asset_criticality(os.getenv("ASSET_CRITICALITY", "web-01=1.5,db-01=1.5,dc-01=1.6"))
    )

    # IP → hostname, used to attach network (Suricata) alerts to the right asset.
    asset_inventory: dict[str, str] = field(
        default_factory=lambda: _inventory(
            os.getenv(
                "ASSET_INVENTORY",
                "10.0.1.10=web-01,10.0.2.20=db-01,10.0.0.5=dc-01,10.0.3.47=hr-laptop-07,10.0.3.12=dev-laptop-03",
            )
        )
    )

    # Wazuh stores alerts in the Wazuh indexer (OpenSearch), queried over its REST API.
    wazuh_url: str = field(default_factory=lambda: os.getenv("WAZUH_INDEXER_URL", ""))
    wazuh_user: str = field(default_factory=lambda: os.getenv("WAZUH_USER", "admin"))
    wazuh_password: str = field(default_factory=lambda: os.getenv("WAZUH_PASSWORD", ""))
    wazuh_index: str = field(default_factory=lambda: os.getenv("WAZUH_INDEX", "wazuh-alerts-*"))
    wazuh_verify_tls: bool = field(default_factory=lambda: _bool("WAZUH_VERIFY_TLS", True))

    elastic_url: str = field(default_factory=lambda: os.getenv("ELASTIC_URL", ""))
    elastic_api_key: str = field(default_factory=lambda: os.getenv("ELASTIC_API_KEY", ""))
    elastic_index: str = field(default_factory=lambda: os.getenv("ELASTIC_INDEX", "logs-*"))
    elastic_verify_tls: bool = field(default_factory=lambda: _bool("ELASTIC_VERIFY_TLS", True))

    suricata_eve_path: str = field(default_factory=lambda: os.getenv("SURICATA_EVE_PATH", ""))


def get_settings() -> Settings:
    return Settings()
