"""Pull collectors: fetch raw records from a tool. (Push types — webhook and syslog — live in main.py / syslog.py.)"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from .parsers import parse_payload, records_at

TIMEOUT = httpx.Timeout(20.0, connect=8.0)
MAX_RECORDS = 5000  # per pull, so one huge backlog can't stall the pipeline


class CollectorError(Exception):
    """A readable message for the Integrations page (no stack traces, no secrets)."""


def _client(cfg: dict[str, Any], transport: httpx.BaseTransport | None = None, **kwargs) -> httpx.Client:
    return httpx.Client(verify=bool(cfg.get("verify_tls", True)), timeout=TIMEOUT, transport=transport,
                        follow_redirects=False, **kwargs)


def _check(resp: httpx.Response) -> None:
    if resp.status_code in (401, 403):
        raise CollectorError(f"Authentication failed ({resp.status_code}). Check the credentials and permissions.")
    if resp.status_code == 404:
        raise CollectorError("Not found (404). Check the URL / index name.")
    if resp.status_code >= 400:
        raise CollectorError(f"The tool returned HTTP {resp.status_code}: {resp.text[:200]}")


def pull_elasticsearch(cfg: dict[str, Any], since: datetime, limit: int, transport=None) -> list[dict[str, Any]]:
    """Wazuh indexer, Elasticsearch, OpenSearch and Graylog all speak this _search API."""
    headers = {}
    auth = None
    if cfg.get("auth") == "apikey" and cfg.get("api_key"):
        headers["Authorization"] = f"ApiKey {cfg['api_key']}"
    elif cfg.get("auth") == "basic":
        auth = (cfg.get("username", ""), cfg.get("password", ""))

    time_field = cfg.get("time_field") or "@timestamp"
    filters: list[dict[str, Any]] = [{"range": {time_field: {"gt": since.isoformat()}}}]
    if cfg.get("query"):
        filters.append({"query_string": {"query": cfg["query"]}})
    page = min(500, limit)
    body: dict[str, Any] = {"size": page, "query": {"bool": {"filter": filters}},
                            "sort": [{time_field: "asc"}, {"_doc": "asc"}]}
    url = f"{cfg['url'].rstrip('/')}/{cfg['index'].strip('/')}/_search"

    records: list[dict[str, Any]] = []
    with _client(cfg, transport, headers=headers, auth=auth) as client:
        while len(records) < limit:
            resp = client.post(url, json=body)
            _check(resp)
            hits = resp.json().get("hits", {}).get("hits", [])
            records.extend(hits)
            if len(hits) < page or not hits[-1].get("sort"):
                break
            body["search_after"] = hits[-1]["sort"]
    return records[:limit]


def pull_splunk(cfg: dict[str, Any], since: datetime, limit: int, transport=None) -> list[dict[str, Any]]:
    """Splunk's export endpoint streams one JSON object per line: {"result": {...}}."""
    search = (cfg.get("search") or "search index=*").strip()
    if not search.startswith(("search ", "|")):
        search = f"search {search}"
    headers, auth = {}, None
    if cfg.get("auth") == "token":
        headers["Authorization"] = f"Bearer {cfg.get('token', '')}"
    else:
        auth = (cfg.get("username", ""), cfg.get("password", ""))
    data = {"search": f"{search} | head {limit}", "earliest_time": since.isoformat(), "latest_time": "now",
            "output_mode": "json"}
    with _client(cfg, transport, headers=headers, auth=auth) as client:
        resp = client.post(f"{cfg['url'].rstrip('/')}/services/search/jobs/export", data=data)
        _check(resp)
    records = []
    for line in resp.text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row.get("result"), dict):
            records.append(row["result"])
    return records[:limit]


def pull_rest(cfg: dict[str, Any], since: datetime, limit: int, transport=None) -> list[dict[str, Any]]:
    headers: dict[str, str] = {"Accept": "application/json"}
    auth = None
    mode = cfg.get("auth", "none")
    if mode == "bearer":
        headers["Authorization"] = f"Bearer {cfg.get('token', '')}"
    elif mode == "header":
        headers[cfg.get("header_name") or "X-API-Key"] = cfg.get("token", "")
    elif mode == "basic":
        auth = (cfg.get("username", ""), cfg.get("password", ""))
    params = {cfg["since_param"]: since.isoformat()} if cfg.get("since_param") else {}

    with _client(cfg, transport, headers=headers, auth=auth) as client:
        if cfg.get("method", "GET").upper() == "POST":
            resp = client.post(cfg["url"], params=params, json={})
        else:
            resp = client.get(cfg["url"], params=params)
        _check(resp)
    try:
        payload = resp.json()
    except ValueError:
        return parse_payload(resp.text, "auto")[:limit]
    try:
        return records_at(payload, cfg.get("records_path"))[:limit]
    except ValueError as err:
        raise CollectorError(str(err)) from err


def pull_file(cfg: dict[str, Any], state: dict[str, Any], limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read new lines since the last offset (handles rotation: a smaller file starts over)."""
    path = Path(cfg["path"])
    if not path.is_file():
        raise CollectorError(f"File not found: {path}")
    size = path.stat().st_size
    offset = int(state.get("offset", 0))
    if size < offset:
        offset = 0
    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(20 * 1024 * 1024)
    if cfg.get("format") == "csv":
        return parse_payload(chunk, "csv")[:limit], {"offset": offset + len(chunk)}
    end = chunk.rfind(b"\n") + 1  # only complete lines; a half-written last line waits for next time
    records = parse_payload(chunk[:end], cfg.get("format") or "auto")
    return records[:limit], {"offset": offset + end}


def pull(conn_type: str, cfg: dict[str, Any], since: datetime, state: dict[str, Any] | None = None,
         limit: int = MAX_RECORDS, transport=None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fetch raw records. Returns (records, new collector state)."""
    state = state or {}
    try:
        if conn_type == "elasticsearch":
            return pull_elasticsearch(cfg, since, limit, transport), state
        if conn_type == "splunk":
            return pull_splunk(cfg, since, limit, transport), state
        if conn_type == "rest":
            return pull_rest(cfg, since, limit, transport), state
        if conn_type == "file":
            return pull_file(cfg, state, limit)
    except httpx.ConnectError as err:
        raise CollectorError(f"Cannot connect to {cfg.get('url')}: {err}") from err
    except httpx.TimeoutException as err:
        raise CollectorError("The tool did not respond in time.") from err
    except httpx.HTTPError as err:
        raise CollectorError(f"HTTP error: {err}") from err
    except (KeyError, ValueError) as err:
        raise CollectorError(f"Bad response or settings: {err}") from err
    raise CollectorError(f"'{conn_type}' integrations receive data; they are not pulled.")
