"""Demo connector: realistic alerts in each tool's native format, so CyberUnify runs
without a live Wazuh/ELK/Suricata stack and the real normalizers are exercised.

Scenario (times are relative to "now", so the dashboard always looks live):
  48h of background noise across the estate, then in the last ~4 hours:
  1. External recon of web-01 (Nmap, SSH scan)          Suricata
  2. SSH brute force against web-01, then a success     Wazuh
  3. sudo to root and a crontab change (persistence)    Wazuh + Elastic
  4. Lateral movement web-01 → db-01                    Elastic
  5. Large outbound transfer / DNS tunnelling from db-01 Elastic + Suricata
  Separately: AgentTesla malware on hr-laptop-07, Windows logon failures on
  dc-01, open CVEs on servers, and a USB policy violation.
"""

from __future__ import annotations

import random
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from ..normalize import from_elastic, from_suricata, from_wazuh
from .base import Connector

ATTACKER = "185.220.101.47"
ASSETS = {
    "web-01": "10.0.1.10",
    "db-01": "10.0.2.20",
    "dc-01": "10.0.0.5",
    "hr-laptop-07": "10.0.3.47",
    "dev-laptop-03": "10.0.3.12",
}
AGENT_IDS = {host: f"{i:03d}" for i, host in enumerate(ASSETS, start=1)}


def _wazuh_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}+0000"


def _suricata_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def _ecs_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class DemoConnector(Connector):
    name = "demo"

    def __init__(self, inventory: dict[str, str] | None = None, seed: int = 7):
        self.inventory = inventory or {ip: host for host, ip in ASSETS.items()}
        self.seed = seed

    # Each raw doc is tagged with its format so normalize() knows which parser to use.
    def normalize(self, doc: dict[str, Any]):
        fmt, payload = doc["format"], doc["doc"]
        if fmt == "wazuh":
            return from_wazuh(payload)
        if fmt == "elastic":
            return from_elastic(payload)
        alert = from_suricata(payload, self.inventory)
        alert.source_id = str(payload["flow_id"])  # demo timestamps move with "now"; keep the id stable
        return alert

    def fetch_raw(self, since: datetime) -> Iterable[dict[str, Any]]:
        # `since` is ignored: the demo always returns the full scenario with stable ids,
        # so re-ingesting refreshes the same alerts instead of piling up duplicates.
        rng = random.Random(self.seed)
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        counter = 0

        def nid() -> str:
            nonlocal counter
            counter += 1
            return f"demo-{counter:05d}"

        def wazuh(at, host, rule_id, level, desc, groups, mitre=None, data=None):
            rule = {"id": str(rule_id), "level": level, "description": desc, "groups": groups}
            if mitre:
                technique, tactic = mitre
                rule["mitre"] = {"id": [technique], "tactic": [tactic]}
            return {"format": "wazuh", "doc": {"_id": nid(), "_source": {
                "timestamp": _wazuh_ts(at),
                "rule": rule,
                "agent": {"id": AGENT_IDS[host], "name": host, "ip": ASSETS[host]},
                "manager": {"name": "wazuh-manager"},
                "data": data or {},
            }}}

        def elastic(at, host, rule_name, severity, category, tactic=None, technique=None, src=None, dst=None, user=None):
            doc: dict[str, Any] = {
                "@timestamp": _ecs_ts(at),
                "event": {"kind": "alert", "severity": severity, "category": [category]},
                "rule": {"id": rule_name.lower().replace(" ", "-")[:40], "name": rule_name},
                "host": {"name": host},
            }
            if src:
                doc["source"] = {"ip": src}
            if dst:
                doc["destination"] = {"ip": dst}
            if user:
                doc["user"] = {"name": user}
            if tactic:
                doc["threat"] = {"tactic": {"name": tactic}, "technique": {"id": technique}}
            return {"format": "elastic", "doc": {"_id": nid(), "_source": doc}}

        def suricata(at, src, dst, sid, signature, severity, category, tactic=None, technique=None, dport=22):
            meta = {}
            if tactic:
                meta = {"mitre_tactic_name": [tactic], "mitre_technique_id": [technique]}
            return {"format": "suricata", "doc": {
                "timestamp": _suricata_ts(at),
                "flow_id": nid(),
                "event_type": "alert",
                "src_ip": src, "src_port": rng.randrange(30000, 65000),
                "dest_ip": dst, "dest_port": dport, "proto": "TCP",
                "alert": {"signature_id": sid, "signature": signature, "severity": severity,
                          "category": category, "metadata": meta},
            }}

        def ago(hours: float = 0, minutes: float = 0) -> datetime:
            return now - timedelta(hours=hours, minutes=minutes)

        def jitter(base: datetime, max_minutes: int) -> datetime:
            return base + timedelta(seconds=rng.randrange(0, max_minutes * 60))

        docs: list[dict[str, Any]] = []

        # ---- background noise over the last 48 hours ----
        for _ in range(140):
            at = ago(hours=rng.uniform(4, 48))
            host = rng.choice(list(ASSETS))
            pick = rng.random()
            if pick < 0.35:
                docs.append(wazuh(at, host, 5501, 3, "PAM: Login session opened.", ["pam", "syslog", "authentication_success"]))
            elif pick < 0.55:
                docs.append(wazuh(at, host, 550, 7, "Integrity checksum changed.", ["ossec", "syscheck", "syscheck_entry_modified"],
                                  data={"path": rng.choice(["/etc/hosts", "/var/www/html/index.php", "C:\\Windows\\System32\\drivers\\etc\\hosts"])}))
            elif pick < 0.70 and host == "web-01":
                docs.append(wazuh(at, host, 31101, 5, "Web server 400 error code.", ["web", "accesslog"],
                                  data={"srcip": f"{rng.randrange(20, 200)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}"}))
            elif pick < 0.85:
                docs.append(elastic(at, host, "Unusual Process Network Connection", 21, "network"))
            else:
                docs.append(suricata(at, f"45.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}", ASSETS["web-01"],
                                     2001219, "ET SCAN Potential SSH Scan", 2, "Attempted Information Leak",
                                     "Reconnaissance", "T1595"))

        # ---- vulnerabilities found by Wazuh's vulnerability detector ----
        docs.append(wazuh(ago(hours=20), "web-01", 23505, 10, "CVE-2024-6387 affects openssh-server", ["vulnerability-detector"],
                          data={"vulnerability": {"cve": "CVE-2024-6387", "severity": "High", "package": {"name": "openssh-server"}}}))
        docs.append(wazuh(ago(hours=19), "db-01", 23504, 7, "CVE-2023-5868 affects postgresql-15", ["vulnerability-detector"],
                          data={"vulnerability": {"cve": "CVE-2023-5868", "severity": "Medium", "package": {"name": "postgresql-15"}}}))

        # ---- the attack chain on web-01 → db-01 ----
        recon = ago(hours=4)
        docs.append(suricata(recon, ATTACKER, ASSETS["web-01"], 2024364, "ET SCAN Nmap Scripting Engine User-Agent Detected",
                             2, "Web Application Attack", "Reconnaissance", "T1595.002", dport=80))
        for i in range(6):
            docs.append(suricata(jitter(recon, 20), ATTACKER, ASSETS["web-01"], 2001219, "ET SCAN Potential SSH Scan",
                                 2, "Attempted Information Leak", "Reconnaissance", "T1595"))

        brute = ago(hours=3)
        for _ in range(38):
            docs.append(wazuh(jitter(brute, 45), "web-01", 5710, 5, "sshd: Attempt to login using a non-existent user",
                              ["syslog", "sshd", "authentication_failed", "invalid_login"], ("T1110.001", "Credential Access"),
                              {"srcip": ATTACKER, "dstuser": rng.choice(["admin", "oracle", "test", "ubuntu", "postgres"])}))
        for _ in range(3):
            docs.append(wazuh(jitter(brute, 45), "web-01", 5712, 10, "sshd: brute force trying to get access to the system. Non existent user.",
                              ["syslog", "sshd", "authentication_failures"], ("T1110", "Credential Access"), {"srcip": ATTACKER}))
        docs.append(wazuh(ago(hours=2, minutes=5), "web-01", 5715, 3, "sshd: authentication success.",
                          ["syslog", "sshd", "authentication_success"], ("T1078", "Initial Access"),
                          {"srcip": ATTACKER, "dstuser": "deploy"}))
        docs.append(wazuh(ago(hours=2), "web-01", 5402, 3, "Successful sudo to ROOT executed.",
                          ["syslog", "sudo"], ("T1548.003", "Privilege Escalation"), {"srcuser": "deploy", "dstuser": "root"}))
        docs.append(elastic(ago(hours=1, minutes=58), "web-01", "Sudo to Root by Newly Logged-in User", 73, "process",
                            "Privilege Escalation", "T1548.003", src=ATTACKER, user="deploy"))
        docs.append(wazuh(ago(hours=1, minutes=50), "web-01", 550, 7, "Integrity checksum changed.",
                          ["ossec", "syscheck", "syscheck_entry_modified"], data={"path": "/etc/crontab"}))
        docs.append(elastic(ago(hours=1, minutes=49), "web-01", "Cron Job Created for Persistence", 47, "process",
                            "Persistence", "T1053.003", user="root"))
        docs.append(elastic(ago(hours=1, minutes=30), "db-01", "Lateral Movement via SSH from Web Tier", 73, "network",
                            "Lateral Movement", "T1021.004", src=ASSETS["web-01"], dst=ASSETS["db-01"], user="deploy"))
        docs.append(elastic(ago(hours=1, minutes=10), "db-01", "Database Dump Utility Executed (pg_dump)", 47, "process",
                            "Collection", "T1005", user="postgres"))
        docs.append(elastic(ago(minutes=50), "db-01", "Large Outbound Data Transfer to Rare Destination", 90, "network",
                            "Exfiltration", "T1048", src=ASSETS["db-01"], dst=ATTACKER))
        for _ in range(4):
            docs.append(suricata(jitter(ago(minutes=55), 25), ASSETS["db-01"], ATTACKER, 2027863,
                                 "ET POLICY Possible DNS Tunneling - Long Query (exfiltration)", 1, "Potentially Bad Traffic",
                                 "Exfiltration", "T1048.003", dport=53))

        # ---- malware on an HR laptop ----
        docs.append(elastic(ago(hours=6), "hr-laptop-07", "Malware Detected: Trojan.AgentTesla", 99, "malware",
                            "Execution", "T1204.002", user="priya.s"))
        docs.append(suricata(ago(hours=5, minutes=40), ASSETS["hr-laptop-07"], "103.155.80.12", 2030171,
                             "ET MALWARE AgentTesla Exfil Via SMTP", 1, "A Network Trojan was detected",
                             "Command and Control", "T1071.003", dport=587))

        # ---- Windows logon failures on the domain controller ----
        for _ in range(12):
            docs.append(wazuh(jitter(ago(hours=9), 30), "dc-01", 60122, 5, "Logon Failure - Unknown user or bad password",
                              ["windows", "authentication_failed"], ("T1110", "Credential Access"), {"dstuser": "svc_backup"}))
        docs.append(wazuh(ago(hours=8, minutes=25), "dc-01", 60204, 10, "Multiple Windows Logon Failures",
                          ["windows", "authentication_failures"], ("T1110", "Credential Access"), {"dstuser": "svc_backup"}))

        # ---- policy ----
        docs.append(elastic(ago(hours=12), "dev-laptop-03", "USB Mass Storage Device Connected (policy)", 21, "host"))

        return docs
