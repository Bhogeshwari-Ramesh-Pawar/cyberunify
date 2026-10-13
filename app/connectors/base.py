from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

import httpx

from ..models import Alert

log = logging.getLogger("cyberunify.connectors")


class Connector(ABC):
    """Pulls alerts from one tool and returns them already normalized."""

    name: str = "base"

    @abstractmethod
    def fetch_raw(self, since: datetime) -> Iterable[dict[str, Any]]:
        """Yield the tool's native alert documents newer than `since`."""

    @abstractmethod
    def normalize(self, doc: dict[str, Any]) -> Alert:
        """Convert one native document into an Alert."""

    def fetch(self, since: datetime) -> tuple[list[Alert], int]:
        """Return (alerts, number of documents that could not be parsed)."""
        alerts: list[Alert] = []
        skipped = 0
        for doc in self.fetch_raw(since):
            try:
                alerts.append(self.normalize(doc))
            except (KeyError, ValueError, TypeError) as err:
                skipped += 1
                log.debug("%s: skipped malformed document: %s", self.name, err)
        return alerts, skipped


def search_after_pages(
    client: httpx.Client,
    url: str,
    query: dict[str, Any],
    sort_field: str,
    page_size: int = 500,
    max_docs: int = 10_000,
) -> Iterable[dict[str, Any]]:
    """Page through an Elasticsearch/OpenSearch _search with search_after (no deep-paging limit)."""
    body: dict[str, Any] = {"size": page_size, "query": query, "sort": [{sort_field: "asc"}, {"_id": "asc"}]}
    fetched = 0
    while fetched < max_docs:
        resp = client.post(url, json=body)
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        if not hits:
            return
        yield from hits
        fetched += len(hits)
        if len(hits) < page_size:
            return
        body["search_after"] = hits[-1]["sort"]


Normalizer = Callable[[dict[str, Any]], Alert]
