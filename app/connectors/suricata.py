"""Suricata connector: reads alert events from an eve.json log file."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from ..normalize import from_suricata, parse_timestamp
from .base import Connector


class SuricataConnector(Connector):
    name = "suricata"

    def __init__(self, eve_path: str, inventory: dict[str, str] | None = None):
        self.path = Path(eve_path)
        self.inventory = inventory or {}

    def fetch_raw(self, since: datetime) -> Iterable[dict[str, Any]]:
        if not self.path.exists():
            raise FileNotFoundError(f"eve.json not found at {self.path}")
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") != "alert":
                    continue
                try:
                    if parse_timestamp(event.get("timestamp")) <= since:
                        continue
                except ValueError:
                    continue
                yield event

    def normalize(self, doc: dict[str, Any]):
        return from_suricata(doc, self.inventory)
