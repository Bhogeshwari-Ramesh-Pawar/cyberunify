"""Demo data: nine SOC tools, each producing logs in its real native format.

Text formats (FortiGate key=value syslog, GTB DLP CEF syslog) go through the real syslog
parser; JSON tools produce exactly what their API/webhook would deliver. So the demo uses the
same parse → map → score path as live integrations.

The story (relative to "now", so the dashboard always looks live):
  48h of routine logs from every tool, then in the last ~4 hours:
  Cloudflare blocks SQL injection on shop.example.com · Suricata sees an Nmap scan ·
  Wazuh: SSH brute force on web-01 → success → sudo → crontab change ·
  Elastic: lateral movement to db-01 → pg_dump → large outbound transfer ·
  Suricata + FortiGate: DNS tunnelling / big session to the attacker.
  Separately: AgentTesla on hr-laptop-07 (Elastic + Suricata), GTB DLP blocks an Aadhaar upload,
  miniOrange shows a password-spray then a login from the attacker IP, Splunk shows Windows
  logon failures and a lockout on dc-01, and CloudSEK reports leaked employee credentials.
"""

from __future__ import annotations

import random
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any

from .parsers import parse_line

ATTACKER = "185.220.101.47"
IP = {"web-01": "10.0.1.10", "db-01": "10.0.2.20", "dc-01": "10.0.0.5", "hr-laptop-07": "10.0.3.47",
      "dev-laptop-03": "10.0.3.12"}
DEMO_TOOLS = ("wazuh", "elastic", "splunk", "suricata", "fortigate", "cloudflare", "cloudsek", "gtb_dlp", "miniorange")


def _iso_ms(dt: datetime, z: bool = True) -> str:
    base = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"
    return base + ("Z" if z else "+0000")


class Simulator:
    def __init__(self, seed: int = 7):
        self.seed = seed
        self._cache: tuple[datetime, dict[str, list[dict[str, Any]]]] | None = None
        self._live = random.Random()

    def records_for(self, tool: str) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        if not self._cache or self._cache[0] != now:
            self._cache = (now, self._build(now))
        return self._cache[1].get(tool, []) + self._live_noise(tool, datetime.now(timezone.utc))

    # ---------- per-tool record builders (native formats) ----------

    @staticmethod
    def wazuh(rid, at, host, rule_id, level, desc, groups, mitre=None, data=None):
        rule = {"id": str(rule_id), "level": level, "description": desc, "groups": groups}
        if mitre:
            rule["mitre"] = {"id": [mitre[0]], "tactic": [mitre[1]]}
        return {"_index": "wazuh-alerts-4.x-demo", "_id": rid, "_source": {
            "timestamp": _iso_ms(at, z=False), "rule": rule,
            "agent": {"id": f"{list(IP).index(host) + 1:03d}", "name": host, "ip": IP[host]},
            "manager": {"name": "wazuh-manager"}, "data": data or {}}}

    @staticmethod
    def elastic(rid, at, host, name, severity, category, tactic=None, technique=None, src=None, dst=None, user=None):
        doc: dict[str, Any] = {"@timestamp": _iso_ms(at), "event": {"kind": "alert", "severity": severity, "category": [category]},
                               "rule": {"id": name.lower().replace(" ", "-")[:40], "name": name}, "host": {"name": host}}
        if src:
            doc["source"] = {"ip": src}
        if dst:
            doc["destination"] = {"ip": dst}
        if user:
            doc["user"] = {"name": user}
        if tactic:
            doc["threat"] = {"tactic": {"name": tactic}, "technique": {"id": technique}}
        return {"_index": ".alerts-security.alerts-default", "_id": rid, "_source": doc}

    @staticmethod
    def suricata(rid, at, src, dst, sid, signature, severity, category, tactic=None, technique=None, dport=22, action="allowed"):
        meta = {"mitre_tactic_name": [tactic], "mitre_technique_id": [technique]} if tactic else {}
        return {"timestamp": at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000", "flow_id": rid, "event_type": "alert",
                "src_ip": src, "src_port": 40000 + zlib.crc32(rid.encode()) % 20000, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
                "alert": {"action": action, "signature_id": sid, "signature": signature, "severity": severity,
                          "category": category, "metadata": meta}}

    @staticmethod
    def fortigate(rid, at, ftype, subtype, level, srcip, dstip, dport, action, service, msg=None, attack=None, sent=0):
        epoch_ns = int(at.timestamp() * 1e9)
        line = (f'<189>date={at:%Y-%m-%d} time={at:%H:%M:%S} devname="FGT-EDGE-01" devid="FG100FTK21000001" '
                f'eventtime={epoch_ns} logid="{rid}" type="{ftype}" subtype="{subtype}" level="{level}" vd="root" '
                f'srcip={srcip} srcport=5{zlib.crc32(rid.encode()) % 10000:04d} dstip={dstip} dstport={dport} policyid=12 '
                f'action="{action}" service="{service}" sentbyte={sent} rcvdbyte={sent // 4}')
        if msg:
            line += f' msg="{msg}"'
        if attack:
            line += f' attack="{attack}"'
        return parse_line(line)

    @staticmethod
    def gtb(rid, at, host, user, name, severity, act, fname, dst="142.250.183.14", dhost="drive.google.com"):
        line = (f"<134>{at:%b} {at.day:2d} {at:%H:%M:%S} gtb-console CEF:0|GTB Technologies|GTB Inspector|15.6|DLP-1001|"
                f"{name}|{severity}|rt={int(at.timestamp() * 1000)} src={IP[host]} shost={host} suser={user} "
                f"dst={dst} dhost={dhost} act={act} fname={fname} cs1Label=Policy cs1=Aadhaar - PII externalId={rid}")
        return parse_line(line)

    @staticmethod
    def cloudflare(rid, at, ip, action, path, description, rule_id, source="waf", method="GET", country="DE"):
        return {"RayID": rid, "Datetime": at.strftime("%Y-%m-%dT%H:%M:%SZ"), "ClientIP": ip, "ClientCountry": country,
                "ClientRequestHost": "shop.example.com", "ClientRequestMethod": method, "ClientRequestPath": path,
                "ClientRequestUserAgent": "Mozilla/5.0", "Action": action, "Source": source, "RuleID": rule_id,
                "Description": description}

    @staticmethod
    def miniorange(rid, at, user, event, status, ip, app="Office 365 SSO", location="Pune, IN"):
        return {"eventId": rid, "timestamp": _iso_ms(at), "username": user, "application": app, "eventType": event,
                "status": status, "ipAddress": ip, "location": location}

    @staticmethod
    def splunk(rid, at, host, code, signature, user, src, severity, action):
        return {"_cd": rid, "_time": _iso_ms(at), "host": host, "sourcetype": "WinEventLog:Security", "EventCode": code,
                "signature": signature, "user": user, "src": src, "severity": severity, "action": action}

    @staticmethod
    def cloudsek(rid, at, title, severity, category, asset, alert_type):
        return {"alert_id": rid, "created_at": _iso_ms(at), "title": title, "severity": severity, "category": category,
                "asset": asset, "alert_type": alert_type, "source": "XVigil"}

    # ---------- the scenario ----------

    def _build(self, now: datetime) -> dict[str, list[dict[str, Any]]]:
        rng = random.Random(self.seed)
        out: dict[str, list[dict[str, Any]]] = {t: [] for t in DEMO_TOOLS}
        n = 0

        def rid(prefix: str) -> str:
            nonlocal n
            n += 1
            return f"demo-{prefix}-{n:05d}"

        def ago(hours=0.0, minutes=0.0) -> datetime:
            return now - timedelta(hours=hours, minutes=minutes)

        def jitter(base: datetime, minutes: int) -> datetime:
            return base + timedelta(seconds=rng.randrange(0, minutes * 60))

        hosts = list(IP)
        w, e, s, f, c = out["wazuh"], out["elastic"], out["suricata"], out["fortigate"], out["cloudflare"]

        # --- routine logs over 48h ---
        for _ in range(120):
            at, host = ago(hours=rng.uniform(4, 48)), rng.choice(hosts)
            if rng.random() < 0.6:
                w.append(self.wazuh(rid("wz"), at, host, 5501, 3, "PAM: Login session opened.", ["pam", "syslog", "authentication_success"]))
            else:
                w.append(self.wazuh(rid("wz"), at, host, 550, 7, "Integrity checksum changed.", ["ossec", "syscheck"],
                                    data={"path": rng.choice(["/etc/hosts", "/var/www/html/index.php"])}))
        for _ in range(160):
            at, host = ago(hours=rng.uniform(1, 48)), rng.choice(hosts)
            dst = f"{rng.choice([8, 13, 20, 52, 142, 151])}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}"
            denied = rng.random() < 0.12
            f.append(self.fortigate(rid("fg"), at, "traffic", "forward", "notice", IP[host], dst, rng.choice([443, 80, 53]),
                                    "deny" if denied else "accept", rng.choice(["HTTPS", "HTTP", "DNS"]), sent=rng.randrange(400, 90000)))
        for _ in range(90):
            at = ago(hours=rng.uniform(1, 48))
            ip = f"{rng.randrange(20, 200)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}"
            action = rng.choices(["allow", "managed_challenge", "block"], [70, 20, 10])[0]
            c.append(self.cloudflare(rid("cf"), at, ip, action, rng.choice(["/", "/products", "/cart", "/login"]),
                                     "Bot score below threshold" if action != "allow" else "Request passed", "bic-100",
                                     source="bic", country=rng.choice(["IN", "US", "SG", "GB"])))
        for _ in range(40):
            at, host = ago(hours=rng.uniform(4, 48)), rng.choice(hosts)
            e.append(self.elastic(rid("el"), at, host, "Unusual Process Network Connection", 21, "network"))
        for _ in range(25):
            s.append(self.suricata(rid("sr"), ago(hours=rng.uniform(4, 48)),
                                   f"45.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}", IP["web-01"],
                                   2001219, "ET SCAN Potential SSH Scan", 2, "Attempted Information Leak", "Reconnaissance", "T1595"))
        for _ in range(60):
            user = rng.choice(["priya.s", "rahul.k", "anita.m", "dev.ops", "neha.j"])
            out["miniorange"].append(self.miniorange(rid("mo"), ago(hours=rng.uniform(1, 48)), user, "Login Success - SSO", "SUCCESS",
                                                     f"49.36.{rng.randrange(256)}.{rng.randrange(256)}"))
        for _ in range(30):
            out["splunk"].append(self.splunk(rid("sp"), ago(hours=rng.uniform(4, 48)), "dc-01", "4624", "An account was successfully logged on",
                                             rng.choice(["svc_backup", "admin.it", "rahul.k"]), IP[rng.choice(hosts)], "informational", "success"))

        # --- vulnerabilities ---
        w.append(self.wazuh(rid("wz"), ago(hours=20), "web-01", 23505, 10, "CVE-2024-6387 affects openssh-server", ["vulnerability-detector"],
                            data={"vulnerability": {"cve": "CVE-2024-6387", "severity": "High"}}))
        w.append(self.wazuh(rid("wz"), ago(hours=19), "db-01", 23504, 7, "CVE-2023-5868 affects postgresql-15", ["vulnerability-detector"],
                            data={"vulnerability": {"cve": "CVE-2023-5868", "severity": "Medium"}}))

        # --- web attack + recon ---
        for i in range(14):
            c.append(self.cloudflare(rid("cf"), jitter(ago(hours=4, minutes=30), 25), ATTACKER, "block",
                                     rng.choice(["/products?id=1' OR '1'='1", "/login", "/search?q=<script>"]),
                                     rng.choice(["SQLi - OR 1=1 attack", "XSS - script tag injection"]), "owasp-942100",
                                     source="waf", method=rng.choice(["GET", "POST"])))
        s.append(self.suricata(rid("sr"), ago(hours=4), ATTACKER, IP["web-01"], 2024364, "ET SCAN Nmap Scripting Engine User-Agent Detected",
                               2, "Web Application Attack", "Reconnaissance", "T1595.002", dport=80))
        for _ in range(6):
            s.append(self.suricata(rid("sr"), jitter(ago(hours=4), 20), ATTACKER, IP["web-01"], 2001219, "ET SCAN Potential SSH Scan",
                                   2, "Attempted Information Leak", "Reconnaissance", "T1595"))
        f.append(self.fortigate(rid("fg"), ago(hours=3, minutes=50), "utm", "ips", "alert", ATTACKER, IP["web-01"], 80, "dropped",
                                "HTTP", msg="web_misc: Apache.Struts.Jakarta.Multipart.Parser.Code.Execution",
                                attack="Apache.Struts.Jakarta.Multipart.Parser.Code.Execution"))

        # --- SSH brute force → foothold on web-01 ---
        brute = ago(hours=3)
        for _ in range(38):
            w.append(self.wazuh(rid("wz"), jitter(brute, 45), "web-01", 5710, 5, "sshd: Attempt to login using a non-existent user",
                                ["syslog", "sshd", "authentication_failed"], ("T1110.001", "Credential Access"),
                                {"srcip": ATTACKER, "dstuser": rng.choice(["admin", "oracle", "test", "ubuntu"])}))
        for _ in range(3):
            w.append(self.wazuh(rid("wz"), jitter(brute, 45), "web-01", 5712, 10, "sshd: brute force trying to get access to the system.",
                                ["syslog", "sshd", "authentication_failures"], ("T1110", "Credential Access"), {"srcip": ATTACKER}))
        w.append(self.wazuh(rid("wz"), ago(hours=2, minutes=5), "web-01", 5715, 3, "sshd: authentication success.",
                            ["syslog", "sshd", "authentication_success"], ("T1078", "Initial Access"), {"srcip": ATTACKER, "dstuser": "deploy"}))
        w.append(self.wazuh(rid("wz"), ago(hours=2), "web-01", 5402, 3, "Successful sudo to ROOT executed.", ["syslog", "sudo"],
                            ("T1548.003", "Privilege Escalation"), {"srcuser": "deploy", "dstuser": "root"}))
        e.append(self.elastic(rid("el"), ago(hours=1, minutes=58), "web-01", "Sudo to Root by Newly Logged-in User", 73, "process",
                              "Privilege Escalation", "T1548.003", src=ATTACKER, user="deploy"))
        w.append(self.wazuh(rid("wz"), ago(hours=1, minutes=50), "web-01", 550, 7, "Integrity checksum changed.", ["ossec", "syscheck"],
                            data={"path": "/etc/crontab"}))
        e.append(self.elastic(rid("el"), ago(hours=1, minutes=49), "web-01", "Cron Job Created for Persistence", 47, "process",
                              "Persistence", "T1053.003", user="root"))

        # --- lateral movement and exfiltration from db-01 ---
        e.append(self.elastic(rid("el"), ago(hours=1, minutes=30), "db-01", "Lateral Movement via SSH from Web Tier", 73, "network",
                              "Lateral Movement", "T1021.004", src=IP["web-01"], dst=IP["db-01"], user="deploy"))
        e.append(self.elastic(rid("el"), ago(hours=1, minutes=10), "db-01", "Database Dump Utility Executed (pg_dump)", 47, "process",
                              "Collection", "T1005", user="postgres"))
        e.append(self.elastic(rid("el"), ago(minutes=50), "db-01", "Large Outbound Data Transfer to Rare Destination", 90, "network",
                              "Exfiltration", "T1048", src=IP["db-01"], dst=ATTACKER))
        for _ in range(4):
            s.append(self.suricata(rid("sr"), jitter(ago(minutes=55), 25), IP["db-01"], ATTACKER, 2027863,
                                   "ET POLICY Possible DNS Tunneling - Long Query (exfiltration)", 1, "Potentially Bad Traffic",
                                   "Exfiltration", "T1048.003", dport=53))
        f.append(self.fortigate(rid("fg"), ago(minutes=48), "traffic", "forward", "warning", IP["db-01"], ATTACKER, 443, "accept",
                                "HTTPS", msg="Large outbound session to rare destination", sent=2_400_000_000))

        # --- malware + DLP on hr-laptop-07 ---
        e.append(self.elastic(rid("el"), ago(hours=6), "hr-laptop-07", "Malware Detected: Trojan.AgentTesla", 99, "malware",
                              "Execution", "T1204.002", user="priya.s"))
        s.append(self.suricata(rid("sr"), ago(hours=5, minutes=40), IP["hr-laptop-07"], "103.155.80.12", 2030171,
                               "ET MALWARE AgentTesla Exfil Via SMTP", 1, "A Network Trojan was detected", "Command and Control",
                               "T1071.003", dport=587))
        out["gtb_dlp"].append(self.gtb(rid("dlp"), ago(hours=5, minutes=20), "hr-laptop-07", "priya.s",
                                       "Sensitive data (Aadhaar numbers) uploaded to personal cloud storage", 8, "Blocked", "employees_kyc.xlsx"))
        for i in range(5):
            out["gtb_dlp"].append(self.gtb(rid("dlp"), ago(hours=rng.uniform(8, 40)), rng.choice(["dev-laptop-03", "hr-laptop-07"]),
                                           rng.choice(["rahul.k", "anita.m"]), "Confidential document emailed to external domain", 4,
                                           "Logged", "q3_forecast.pdf", dst="74.125.68.27", dhost="smtp.gmail.com"))

        # --- identity: password spray, then attacker login (miniOrange) ---
        spray = ago(hours=7)
        for user in ["priya.s", "rahul.k", "anita.m", "neha.j", "dev.ops", "admin.it"]:
            for _ in range(3):
                out["miniorange"].append(self.miniorange(rid("mo"), jitter(spray, 20), user, "Login Failed - Invalid Password",
                                                         "FAILED", ATTACKER, location="Frankfurt, DE"))
        out["miniorange"].append(self.miniorange(rid("mo"), ago(hours=6, minutes=35), "priya.s", "Login Success - MFA bypassed via remembered device",
                                                 "SUCCESS", ATTACKER, location="Frankfurt, DE"))

        # --- Windows logon failures and lockout on dc-01 (Splunk) ---
        for _ in range(12):
            out["splunk"].append(self.splunk(rid("sp"), jitter(ago(hours=9), 30), "dc-01", "4625", "An account failed to log on",
                                             "svc_backup", IP["dev-laptop-03"], "medium", "failure"))
        out["splunk"].append(self.splunk(rid("sp"), ago(hours=8, minutes=25), "dc-01", "4740", "A user account was locked out",
                                         "svc_backup", IP["dev-laptop-03"], "high", "locked"))

        # --- threat intel (CloudSEK) ---
        out["cloudsek"] += [
            self.cloudsek(rid("cs"), ago(hours=10), "Leaked credentials of 3 employees found on dark-web forum", "high",
                          "Leaked Credentials", "example.com", "data_leak"),
            self.cloudsek(rid("cs"), ago(hours=30), "Phishing domain impersonating example.com registered (examp1e-login.com)",
                          "medium", "Phishing domain", "example.com", "brand_monitoring"),
            self.cloudsek(rid("cs"), ago(hours=44), "Exposed admin panel detected on staging.example.com", "low",
                          "Exposed asset", "staging.example.com", "attack_surface"),
        ]
        # --- endpoint policy ---
        e.append(self.elastic(rid("el"), ago(hours=12), "dev-laptop-03", "USB Mass Storage Device Connected (policy)", 21, "host"))
        return out

    def _live_noise(self, tool: str, now: datetime) -> list[dict[str, Any]]:
        """A few fresh routine logs each cycle, so the explorer's live view keeps moving."""
        rng = self._live
        k = rng.randint(0, 3)
        out = []
        for _ in range(k):
            rid = f"live-{uuid.uuid4().hex[:12]}"
            at = now - timedelta(seconds=rng.randrange(0, 50))
            host = rng.choice(list(IP))
            if tool == "fortigate":
                out.append(self.fortigate(rid, at, "traffic", "forward", "notice", IP[host], f"142.250.{rng.randrange(256)}.{rng.randrange(256)}",
                                          443, "accept", "HTTPS", sent=rng.randrange(400, 50000)))
            elif tool == "cloudflare":
                out.append(self.cloudflare(rid, at, f"49.36.{rng.randrange(256)}.{rng.randrange(256)}", "allow", "/products",
                                           "Request passed", "bic-100", source="bic", country="IN"))
            elif tool == "wazuh":
                out.append(self.wazuh(rid, at, host, 5501, 3, "PAM: Login session opened.", ["pam", "syslog", "authentication_success"]))
            elif tool == "miniorange":
                out.append(self.miniorange(rid, at, rng.choice(["rahul.k", "anita.m", "neha.j"]), "Login Success - SSO", "SUCCESS",
                                           f"49.36.{rng.randrange(256)}.{rng.randrange(256)}"))
        return out
