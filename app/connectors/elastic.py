"""Elasticsearch / ELK connector for documents in Elastic Common Schema (ECS).

Point ELASTIC_INDEX at Elastic Security's alert index
(`.alerts-security.alerts-default`) or at any index of ECS events.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

import httpx

from ..normalize import from_elastic
from .base import Connector, search_after_pages


class ElasticConnector(Connector):
    name = "elastic"

    def __init__(self, url: str, api_key: str = "", index: str = "logs-*", verify_tls: bool = True):
        self.url = url.rstrip("/")
        self.index = index
        self.verify_tls = verify_tls
        self.headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}

    def fetch_raw(self, since: datetime) -> Iterable[dict[str, Any]]:
        query = {"bool": {"filter": [{"range": {"@timestamp": {"gt": since.isoformat()}}}]}}
        with httpx.Client(headers=self.headers, verify=self.verify_tls, timeout=20) as client:
            yield from search_after_pages(client, f"{self.url}/{self.index}/_search", query, "@timestamp")

    def normalize(self, doc: dict[str, Any]):
        return from_elastic(doc)
