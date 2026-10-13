# CyberUnify: Unified SOC Dashboard

**Connect any SOC tool and see every log in one dashboard.**

SOC teams run many tools (SIEM, EDR, IDS, firewall, WAF, DLP, IAM, threat intel), and each has its own
console, log format and severity scale. CyberUnify gives the analyst a single **Connect a tool** option.
Any tool that has an API, a webhook, syslog output or a log file can be connected. Its logs are mapped into
one schema, and everything appears in one searchable timeline, so an attack can be followed from tool to tool.

> Example from the demo: searching `ip:185.220.101.47` shows the attacker's password spray (miniOrange),
> SQL injection (Cloudflare WAF), Nmap scan (Suricata), exploit attempt (FortiGate), SSH brute force (Wazuh),
> privilege escalation (Elastic) and data exfiltration (Elastic + FortiGate + Suricata) in time order, from 6 tools.

## Connect any tool

| Connection method | Typical tools |
|---|---|
| **Elasticsearch / OpenSearch query** | ELK, Wazuh indexer, Graylog, OpenSearch |
| **Splunk search API** | Splunk |
| **REST API** (bearer / API-key header / basic auth, records path, "since" parameter) | CloudSEK, XSOAR, EDRs, any vendor API |
| **Webhook** (the tool pushes JSON, NDJSON or text to a secret URL) | Cloudflare Logpush, miniOrange, CloudSEK, anything with HTTP output |
| **Syslog receiver** (UDP/TCP; RFC 3164, RFC 5424, CEF, key=value, JSON) | FortiGate, GTB DLP, firewalls, Linux, network gear |
| **Log file** (tails JSON lines / CSV / text, survives rotation) | Suricata `eve.json`, Wazuh `alerts.json` |

Presets fill in the connection type and field mapping for **Wazuh, Elastic, Splunk, Graylog, Suricata,
FortiGate, Cloudflare WAF, CloudSEK, GTB DLP and miniOrange**. **Custom tool** handles anything else:

1. Pick how the tool shares logs and enter its URL / credentials (or get a webhook URL / syslog port).
2. Paste a sample log or click **Test & preview**. CyberUnify shows how each record will be mapped and which
   source field each value came from.
3. Adjust the mapping if needed, then save. Pull integrations are polled automatically; push integrations
   start receiving immediately.

### Field mapping

Each integration maps the tool's fields onto the unified schema
(`timestamp, host, message, severity, category, src_ip, dst_ip, user, rule, action, tactic, technique, id`):

| Syntax | Example | Meaning |
|---|---|---|
| dotted path | `rule.level` | nested field |
| alternatives | `user.name\|username` | first one present wins |
| template | `{action} {srcip} → {dstip}` | compose a value from several fields |
| `@asset` | `@asset\|devname` | the internal host involved, found from the IPs via the asset inventory (for firewalls/IDS) |

Fields left blank are **auto-detected**: first from well-known names (`@timestamp`, `host.name`, `srcip`…),
then by name pattern anywhere in the record (`device.hostname`, `detect_name`, `severity_name`…).
So an unknown tool usually maps correctly without any setup.

Severity scales are normalized to 0–100: `0-15` (Wazuh), `1-3-inverted` (Suricata), `0-10` (CEF), `1-5`,
`syslog` (0–7 / names), `text` (critical/high/… and outcomes such as block/allow/failed), or `auto`.

## Unified log explorer

- One timeline for all tools, stacked by tool, with facet counts by tool, risk level, host and category
- **Query language**: `brute force` (words), `"exact phrase"`, `host:web-01`, `ip:1.2.3.4`, `user:`, `tool:`,
  `category:`, `level:`, `action:`, `technique:`, wildcards `host:web-*`, exclusions `-success`, `-tool:fortigate`
- Time ranges, live auto-refresh, sort by time or risk, CSV / NDJSON export
- Event detail with **one-click pivots** (same host / IP / user / technique across every tool), the original raw log,
  and analyst triage (open → acknowledged → closed / false positive)

## Also included

- **Explainable risk scoring**: severity, MITRE tactic, asset criticality, rule rarity (IDF) and per-host volume
  anomaly (z-score), with the breakdown shown for every event
- **Host risk ranking** correlated across tools
- **ISO/IEC 27001:2022 Annex A report**: 15 controls assessed from the evidence, including integration health (A.8.15)
- **Third-party risk assessment** (weighted vendor questionnaire → inherent / residual risk)
- **Demo mode**: nine simulated tools emitting their real native formats, run through the same parsers and mappings as live data

## Architecture

```
            pull (scheduled)                         push (real time)
  Elasticsearch · Splunk · REST · file        webhook URL · syslog UDP/TCP
                 │                                       │
                 └──────────► parsers (JSON, NDJSON, CSV, syslog, CEF, kv)
                                        │
                              field mapping per integration
                              (preset or custom, auto-detect)
                                        │
                                unified Event schema ──► SQLite (dedupe by stable id, triage kept)
                                        │
                     risk scoring (window rescore) ──► FastAPI ──► dashboard · explorer · ISO report
```

## Run it (Windows)

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Open http://localhost:8000. For syslog from other machines, use a port ≥ 1024 (e.g. 5514) and allow it in the firewall.

Docker:

```bash
docker build -t cyberunify .
docker run -p 8000:8000 -p 5514:5514/udp -v cyberunify-data:/data --env-file .env cyberunify
```

## Security

- Credentials are **encrypted at rest** (Fernet: AES-128 + HMAC) and never returned by the API; a blank secret on edit keeps the stored one.
- Webhooks authenticate with a random 192-bit token in the URL, stored as a SHA-256 hash; tokens can be rotated.
- Optional login for the dashboard and API (`CYBERUNIFY_ADMIN_PASSWORD`, HTTP Basic, constant-time comparison).
- Log content is attacker-controlled: the dashboard renders it as text only, the report auto-escapes it, and CSV export neutralizes spreadsheet formulas.
- Search is compiled to parameterized SQL; TLS verification is on by default for every connector.
- Use HTTPS (reverse proxy) when exposing it beyond a lab network.

## Tests

```powershell
.venv\Scripts\python -m pytest
```

96 tests: parsers for every format; field mapping, auto-discovery and every preset against its tool's native
logs; collectors against mocked Elasticsearch / Splunk / REST APIs and real files (including rotation);
scoring; compliance; and the API end to end, including a real UDP syslog packet, webhook formats, encrypted
secrets, optional login, and escaping of attacker-controlled text.

## Project structure

```
app/
  main.py          API, webhook receiver, scheduler
  integrations.py  create / validate / present integrations
  presets.py       connection types + tool presets
  collectors.py    pull: Elasticsearch, Splunk, REST, file
  syslog.py        push: UDP/TCP syslog listeners
  parsers.py       JSON, NDJSON, CSV, syslog, CEF, key=value
  mapping.py       field mapping, auto-discovery, severity normalization
  search.py        query language → SQL, facets, histogram
  scoring.py       explainable risk scoring
  compliance.py    ISO 27001 Annex A assessment
  vendors.py       third-party risk
  vault.py         credential encryption
  demo.py          nine-tool attack simulation
  static/          dashboard (HTML, CSS, JS + Chart.js)
  templates/       ISO 27001 report
tests/
```
