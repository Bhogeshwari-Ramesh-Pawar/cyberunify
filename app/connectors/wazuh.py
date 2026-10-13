"""Wazuh connector.

Wazuh writes every alert to the Wazuh indexer (an OpenSearch cluster) in the
`wazuh-alerts-*` indices, so we query it through the indexer's _search API.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

import httpx

from ..normalize import from_wazuh
from .base import Connector, search_after_pages


class WazuhConnector(Connector):
    name = "wazuh"

    def __init__(self, url: str, user: str, password: str, index: str = "wazuh-alerts-*", verify_tls: bool = True):
        self.url = url.rstrip("/")
        self.auth = (user, password)
        self.index = index
        self.verify_tls = verify_tls

    def fetch_raw(self, since: datetime) -> Iterable[dict[str, Any]]:
        query = {"range": {"timestamp": {"gt": since.isoformat()}}}
        with httpx.Client(auth=self.auth, verify=self.verify_tls, timeout=20) as client:
            yield from search_after_pages(client, f"{self.url}/{self.index}/_search", query, "timestamp")

    def normalize(self, doc: dict[str, Any]):
        return from_wazuh(doc)
