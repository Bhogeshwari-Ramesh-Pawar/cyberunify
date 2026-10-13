import json
from datetime import datetime, timezone

import httpx
import pytest

from app.collectors import CollectorError, pull

SINCE = datetime(2026, 10, 13, tzinfo=timezone.utc)


def test_elasticsearch_pages_with_search_after_and_sends_api_key():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append((request.headers.get("authorization"), body))
        if "search_after" not in body:
            hits = [{"_id": str(i), "_source": {"n": i}, "sort": [i]} for i in range(2)]
        else:
            hits = [{"_id": "2", "_source": {"n": 2}, "sort": [2]}]
        return httpx.Response(200, json={"hits": {"hits": hits}})

    cfg = {"url": "https://es:9200", "index": "logs-*", "auth": "apikey", "api_key": "KEY", "time_field": "@timestamp", "query": "event.kind:alert"}
    records, _ = pull("elasticsearch", cfg, SINCE, limit=2, transport=httpx.MockTransport(handler))
    assert len(records) == 2
    auth, body = seen[0]
    assert auth == "ApiKey KEY"
    assert body["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gt"].startswith("2026-10-13")
    assert body["query"]["bool"]["filter"][1] == {"query_string": {"query": "event.kind:alert"}}


def test_elasticsearch_auth_failure_is_readable():
    transport = httpx.MockTransport(lambda r: httpx.Response(401, json={}))
    with pytest.raises(CollectorError, match="Authentication failed"):
        pull("elasticsearch", {"url": "https://es", "index": "x", "auth": "basic", "username": "u", "password": "p"}, SINCE, transport=transport)


def test_splunk_export_stream_is_parsed():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/services/search/jobs/export"
        assert request.headers["authorization"] == "Bearer TOK"
        form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
        assert form["output_mode"] == "json"
        lines = [json.dumps({"preview": False, "result": {"_time": "t", "host": "dc-01"}}), "garbage", json.dumps({"lastrow": True})]
        return httpx.Response(200, text="\n".join(lines))

    records, _ = pull("splunk", {"url": "https://splunk:8089", "auth": "token", "token": "TOK", "search": "index=main"}, SINCE,
                      transport=httpx.MockTransport(handler))
    assert records == [{"_time": "t", "host": "dc-01"}]


def test_rest_records_path_header_auth_and_since_param():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "SECRET"
        assert request.url.params["from"].startswith("2026-10-13")
        return httpx.Response(200, json={"data": {"alerts": [{"id": 1}, {"id": 2}]}})

    cfg = {"url": "https://api.vendor/alerts", "auth": "header", "header_name": "X-API-Key", "token": "SECRET",
           "records_path": "data.alerts", "since_param": "from"}
    records, _ = pull("rest", cfg, SINCE, transport=httpx.MockTransport(handler))
    assert [r["id"] for r in records] == [1, 2]


def test_file_reads_only_new_complete_lines_and_handles_rotation(tmp_path):
    f = tmp_path / "eve.json"
    f.write_text('{"a": 1}\n{"a": 2}\n{"a": 3', encoding="utf-8")  # last line still being written
    records, state = pull("file", {"path": str(f), "format": "ndjson"}, SINCE)
    assert [r["a"] for r in records] == [1, 2]
    with f.open("a", encoding="utf-8") as fh:
        fh.write('}\n{"a": 4}\n')
    records, state = pull("file", {"path": str(f), "format": "ndjson"}, SINCE, state)
    assert [r["a"] for r in records] == [3, 4]
    f.write_text('{"a": 9}\n', encoding="utf-8")  # rotated: smaller than the saved offset
    records, _ = pull("file", {"path": str(f), "format": "ndjson"}, SINCE, state)
    assert [r["a"] for r in records] == [9]


def test_missing_file_and_push_types():
    with pytest.raises(CollectorError, match="not found"):
        pull("file", {"path": "/no/such/file"}, SINCE)
    with pytest.raises(CollectorError, match="receive data"):
        pull("webhook", {}, SINCE)
