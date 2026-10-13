# CyberUnify — Unified SOC Dashboard with Risk Scoring

CyberUnify pulls alerts from **Wazuh**, **Elasticsearch/ELK** and **Suricata**, normalizes them into one
schema, scores each one for risk with an explainable model, and turns the result into an
**ISO/IEC 27001:2022 compliance report** and a **third-party risk register**.

It runs out of the box in **demo mode**, which replays a realistic attack (recon → SSH brute force →
privilege escalation → lateral movement → data exfiltration, plus malware on a laptop) in each tool's
native alert format, so the real normalizers are exercised end to end.

## Features

- **Connectors** for the Wazuh indexer (OpenSearch API), Elasticsearch (ECS, API-key auth) and Suricata `eve.json`, with `search_after` paging and per-connector health tracking
- **Normalization** of three severity scales, timestamp formats and MITRE ATT&CK spellings into one `Alert` schema; IP → hostname inventory links network alerts to assets
- **Explainable risk scoring**: severity + MITRE tactic + asset criticality + rule rarity (IDF) + statistical volume anomaly (per-host z-score); every alert shows its score breakdown
- **Host risk ranking** that rewards real compromise and doesn't saturate on noise
- **Analyst triage** (open → acknowledged → closed / false positive), preserved across re-ingestion and fed back into host risk and compliance
- **ISO 27001:2022 Annex A assessment** of 15 controls, with evidence and recommended actions, plus a printable report
- **Third-party risk assessment**: weighted 10-question vendor questionnaire → inherent, control and residual risk
- **Dashboard**: overview charts, filterable alert table, alert detail drawer, hosts, compliance and vendor views

## Architecture

```
 Wazuh indexer ─┐
 Elasticsearch ─┼─► connectors ─► normalize ─► SQLite ─► scoring ─► FastAPI ─► dashboard
 Suricata eve  ─┤   (fetch since       (common      (dedupe,   (window     (REST)     ISO 27001 report
 Demo scenario ─┘    last alert)        schema)      triage)    rescored)              vendor register
```

Each ingest pulls only alerts newer than the last one stored per source, upserts them by a stable
id (so re-ingesting never duplicates), then **rescores the whole window**: rarity and the per-host
baseline depend on everything seen, so scores improve as context grows. A failing connector is
recorded and skipped without stopping the others.

## Risk model

```
base   = severity × dampener                  dampener < 1 for recon/discovery or low-value assets
boost  = 1 − Π(1 − uᵢ)                        combine independent context signals
risk   = base + (100 − base) × boost × base/100
```

| Signal | Range | Meaning |
|---|---|---|
| Tactic | 0 – 0.30 | Exfiltration/impact highest, collection lowest |
| Asset | 0 – 0.50 | From `ASSET_CRITICALITY` (1.0 normal … 2.0 crown jewels) |
| Rarity | 0 – 0.20 | Inverse document frequency of the rule in the window |
| Anomaly | 0 – 0.25 | Host's alert count that hour vs. its own hourly baseline (z-score, capped at 3σ) |

Severity is the anchor: context fills part of the gap to 100 and gives low-severity alerts
proportionally less lift, so 50 routine login events never outrank one malware detection.
Host risk = worst active alert, lifted slightly by the next nine.

## ISO 27001 mapping

| Alert category | Annex A controls |
|---|---|
| authentication | A.5.17 Authentication information, A.8.5 Secure authentication |
| malware | A.8.7 Protection against malware, A.8.1 User endpoint devices |
| network intrusion / reconnaissance | A.8.20 Networks security, A.5.7 Threat intelligence |
| vulnerability | A.8.8 Management of technical vulnerabilities |
| integrity | A.8.9 Configuration management |
| privilege escalation | A.8.2 Privileged access rights |
| data exfiltration | A.8.12 Data leakage prevention, A.8.20 |
| policy | A.8.1 User endpoint devices |

A.8.15 Logging is assessed from connector health, A.8.16/A.5.26 from untriaged high-risk alerts, and
A.5.19 from the vendor register. Status: **At risk** (open critical/high), **Needs review** (open
medium), **Effective** (only low/resolved) or **No evidence** (which is not a pass).

## Run it (Windows)

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Open http://localhost:8000. On macOS/Linux use `.venv/bin/...`.

### With Docker

```bash
docker build -t cyberunify .
docker run -p 8000:8000 -v cyberunify-data:/data --env-file .env cyberunify
```

## Connect real tools

Copy `.env.example` to `.env`, set the URLs/credentials you have, and set `CYBERUNIFY_DEMO=0`.

| Tool | Settings |
|---|---|
| Wazuh | `WAZUH_INDEXER_URL`, `WAZUH_USER`, `WAZUH_PASSWORD` (a read-only indexer user is enough) |
| Elastic | `ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTIC_INDEX` |
| Suricata | `SURICATA_EVE_PATH` |

## API

| Method | Path | Description |
|---|---|---|
| GET | `/api/summary` | KPIs, 48h timeline, tactics, categories, top hosts and alerts |
| GET | `/api/alerts` | Filter by `level`, `source`, `host`, `category`, `status`, `q`; `sort=risk\|time`; paging |
| GET | `/api/alerts/{id}` | Alert with raw event and score breakdown |
| PATCH | `/api/alerts/{id}` | Triage: `{"status": "acknowledged"}` |
| GET | `/api/hosts` | Host risk ranking |
| POST | `/api/ingest` | Pull from all connectors now |
| GET | `/api/sources` | Last run per connector |
| GET | `/api/compliance` | ISO 27001 control assessment (JSON) |
| GET | `/reports/iso27001` | Printable HTML report (`?download=true` to save) |
| GET/POST/DELETE | `/api/vendors` | Third-party risk register |

Interactive API docs: http://localhost:8000/docs

## Tests

```powershell
.venv\Scripts\python -m pytest
```

49 tests cover the normalizers (all three formats, timestamp variants, category inference), the
scoring model's properties (cap, monotonicity, noise resistance, anomaly detection), compliance
status logic, vendor scoring, and the API end to end, including triage persistence and HTML escaping
of attacker-controlled alert text.

## Project structure

```
app/
  connectors/   wazuh.py · elastic.py · suricata.py · demo.py · base.py (paging, error handling)
  normalize.py  tool formats → common Alert schema
  scoring.py    alert and host risk
  compliance.py ISO 27001 Annex A assessment
  vendors.py    third-party risk model
  ingest.py     fetch → store → rescore pipeline
  db.py         SQLite storage
  main.py       FastAPI app and routes
  static/       dashboard (HTML, CSS, JS + Chart.js)
  templates/    ISO 27001 report
tests/
```

## Security notes

- Alert fields can contain attacker-controlled text, so the dashboard renders everything as text (never HTML) and the report template auto-escapes.
- Connectors verify TLS by default; credentials come from the environment, never the code. `.env` is git-ignored.
- The Docker image runs as a non-root user.
- There is no login, so run it on a trusted network or behind an authenticating reverse proxy.
