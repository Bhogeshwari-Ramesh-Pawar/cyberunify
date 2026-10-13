"""Connection types and ready-made presets for common SOC tools.

A preset is only a starting point (connection type + field mapping); the analyst can edit
everything, and "Custom tool" works for any product that can be reached one of these ways.
"""

from __future__ import annotations

from typing import Any

# Fields each connection type needs. "secret" fields are encrypted at rest and never sent back to the browser.
CONNECTION_TYPES: dict[str, dict[str, Any]] = {
    "elasticsearch": {
        "label": "Elasticsearch / OpenSearch query",
        "mode": "pull",
        "fields": [
            {"key": "url", "label": "URL", "placeholder": "https://elastic.local:9200", "required": True},
            {"key": "index", "label": "Index pattern", "placeholder": "logs-*", "required": True},
            {"key": "time_field", "label": "Time field", "placeholder": "@timestamp", "default": "@timestamp"},
            {"key": "query", "label": "Filter (Lucene query, optional)", "placeholder": "event.kind:alert"},
            {"key": "auth", "label": "Authentication", "choices": ["none", "basic", "apikey"], "default": "basic"},
            {"key": "username", "label": "Username", "show_if": {"auth": "basic"}},
            {"key": "password", "label": "Password", "secret": True, "show_if": {"auth": "basic"}},
            {"key": "api_key", "label": "API key (base64 id:key)", "secret": True, "show_if": {"auth": "apikey"}},
            {"key": "verify_tls", "label": "Verify TLS certificate", "type": "bool", "default": True},
        ],
    },
    "splunk": {
        "label": "Splunk search API",
        "mode": "pull",
        "fields": [
            {"key": "url", "label": "Management URL", "placeholder": "https://splunk.local:8089", "required": True},
            {"key": "search", "label": "Search (SPL)", "placeholder": "search index=main sourcetype=*", "default": "search index=*"},
            {"key": "auth", "label": "Authentication", "choices": ["token", "basic"], "default": "token"},
            {"key": "token", "label": "Auth token", "secret": True, "show_if": {"auth": "token"}},
            {"key": "username", "label": "Username", "show_if": {"auth": "basic"}},
            {"key": "password", "label": "Password", "secret": True, "show_if": {"auth": "basic"}},
            {"key": "verify_tls", "label": "Verify TLS certificate", "type": "bool", "default": True},
        ],
    },
    "rest": {
        "label": "REST API (any tool)",
        "mode": "pull",
        "fields": [
            {"key": "url", "label": "Endpoint URL", "placeholder": "https://api.vendor.com/v1/alerts", "required": True},
            {"key": "method", "label": "Method", "choices": ["GET", "POST"], "default": "GET"},
            {"key": "auth", "label": "Authentication", "choices": ["none", "bearer", "header", "basic"], "default": "bearer"},
            {"key": "header_name", "label": "Header name", "placeholder": "X-API-Key", "show_if": {"auth": "header"}},
            {"key": "token", "label": "Token / API key", "secret": True, "show_if": {"auth": ["bearer", "header"]}},
            {"key": "username", "label": "Username", "show_if": {"auth": "basic"}},
            {"key": "password", "label": "Password", "secret": True, "show_if": {"auth": "basic"}},
            {"key": "records_path", "label": "Where the records are in the response", "placeholder": "data.alerts"},
            {"key": "since_param", "label": "Query parameter for 'since' (optional)", "placeholder": "from"},
            {"key": "verify_tls", "label": "Verify TLS certificate", "type": "bool", "default": True},
        ],
    },
    "webhook": {
        "label": "Webhook (tool pushes logs)",
        "mode": "push",
        "fields": [
            {"key": "format", "label": "Payload format", "choices": ["auto", "json", "ndjson", "text"], "default": "auto"},
            {"key": "records_path", "label": "Where the records are in the payload (optional)", "placeholder": "events"},
        ],
    },
    "syslog": {
        "label": "Syslog receiver (UDP/TCP)",
        "mode": "push",
        "fields": [
            {"key": "port", "label": "Port", "type": "int", "default": 5514, "required": True},
            {"key": "protocol", "label": "Protocol", "choices": ["udp", "tcp"], "default": "udp"},
        ],
    },
    "file": {
        "label": "Log file",
        "mode": "pull",
        "fields": [
            {"key": "path", "label": "File path", "placeholder": "/var/log/suricata/eve.json", "required": True},
            {"key": "format", "label": "Format", "choices": ["auto", "ndjson", "csv", "text"], "default": "auto"},
        ],
    },
}

PRESETS: dict[str, dict[str, Any]] = {
    "wazuh": {
        "name": "Wazuh", "kind": "SIEM / XDR", "type": "elasticsearch",
        "config": {"index": "wazuh-alerts-*", "time_field": "timestamp", "auth": "basic", "username": "admin"},
        "mapping": {"timestamp": "timestamp", "host": "agent.name|manager.name", "message": "rule.description",
                    "severity": "rule.level", "category": "rule.groups", "src_ip": "data.srcip",
                    "dst_ip": "data.dstip|agent.ip", "user": "data.dstuser|data.srcuser", "rule": "rule.id",
                    "tactic": "rule.mitre.tactic", "technique": "rule.mitre.id"},
        "severity_scale": "0-15",
        "help": "Point at the Wazuh indexer (port 9200). A read-only indexer user is enough.",
    },
    "elastic": {
        "name": "Elastic / ELK", "kind": "SIEM", "type": "elasticsearch",
        "config": {"index": ".alerts-security.alerts-default,logs-*", "time_field": "@timestamp", "auth": "apikey"},
        "mapping": {"timestamp": "@timestamp", "host": "host.name|host.hostname",
                    "message": "kibana.alert.rule.name|rule.name|message", "severity": "event.severity|kibana.alert.severity",
                    "category": "event.category", "src_ip": "source.ip", "dst_ip": "destination.ip", "user": "user.name",
                    "rule": "kibana.alert.rule.uuid|rule.id", "action": "event.action|event.outcome",
                    "tactic": "threat.tactic.name", "technique": "threat.technique.id"},
        "severity_scale": "auto",
        "help": "Create an API key in Kibana → Stack Management → API keys with read access to the indices.",
    },
    "splunk": {
        "name": "Splunk", "kind": "SIEM", "type": "splunk",
        "config": {"search": "search index=* sourcetype=*", "auth": "token"},
        "mapping": {"id": "_cd|_serial", "timestamp": "_time", "host": "host|dest", "message": "signature|_raw", "severity": "severity|urgency",
                    "category": "sourcetype", "src_ip": "src|src_ip", "dst_ip": "dest_ip|dest", "user": "user",
                    "rule": "signature_id|signature", "action": "action"},
        "severity_scale": "auto",
        "help": "Use the management port (8089). Create a token under Settings → Tokens.",
    },
    "graylog": {
        "name": "Graylog", "kind": "Log management", "type": "elasticsearch",
        "config": {"index": "graylog_*", "time_field": "timestamp", "auth": "basic"},
        "mapping": {"timestamp": "timestamp", "host": "source", "message": "message", "severity": "level",
                    "src_ip": "src_ip|source_ip", "dst_ip": "dst_ip|destination_ip", "user": "user|username",
                    "rule": "event_definition_id|facility"},
        "severity_scale": "syslog",
        "help": "Graylog stores messages in OpenSearch: query its graylog_* indices directly.",
    },
    "suricata": {
        "name": "Suricata", "kind": "Network IDS/IPS", "type": "file",
        "config": {"path": "/var/log/suricata/eve.json", "format": "ndjson"},
        "mapping": {"id": "flow_id", "timestamp": "timestamp", "host": "@asset|host", "message": "alert.signature|event_type",
                    "severity": "alert.severity", "category": "alert.category|event_type", "src_ip": "src_ip",
                    "dst_ip": "dest_ip", "rule": "alert.signature_id", "action": "alert.action",
                    "tactic": "alert.metadata.mitre_tactic_name", "technique": "alert.metadata.mitre_technique_id"},
        "severity_scale": "1-3-inverted",
        "help": "Reads eve.json. Network alerts are linked to hosts with the IP inventory in Settings.",
    },
    "fortigate": {
        "name": "Fortinet FortiGate", "kind": "Firewall", "type": "syslog",
        "config": {"port": 5514, "protocol": "udp"},
        "mapping": {"id": "logid|eventtime", "timestamp": "eventtime|date", "host": "@asset|devname", "message": "msg|attack|{type}/{subtype} {action}: {srcip}:{srcport} → {dstip}:{dstport} {service}",
                    "severity": "level", "category": "type|subtype", "src_ip": "srcip", "dst_ip": "dstip",
                    "user": "user|srcuser", "rule": "logid|policyid", "action": "action"},
        "severity_scale": "syslog", "default_category": "network_traffic",
        "help": "On the FortiGate: Log & Report → Log Settings → Send logs to syslog, using this server's IP and port.",
    },
    "cloudflare": {
        "name": "Cloudflare WAF", "kind": "WAF", "type": "webhook",
        "config": {"format": "ndjson"},
        "mapping": {"id": "RayID", "timestamp": "Datetime|EdgeStartTimestamp", "host": "ClientRequestHost",
                    "message": "{Description} on {ClientRequestPath}|{Action} {ClientRequestMethod} {ClientRequestPath}", "severity": "Action", "src_ip": "ClientIP",
                    "rule": "RuleID", "action": "Action", "category": "Source"},
        "severity_scale": "text", "default_category": "network_intrusion",
        "help": "Create a Logpush job for Firewall events with an HTTP destination set to the webhook URL below.",
    },
    "cloudsek": {
        "name": "CloudSEK", "kind": "Threat intelligence", "type": "webhook",
        "config": {"format": "json"},
        "mapping": {"id": "alert_id|id", "timestamp": "created_at", "host": "asset|affected_asset",
                    "message": "title", "severity": "severity", "category": "category", "rule": "alert_type"},
        "severity_scale": "text", "default_category": "threat_intel",
        "help": "In CloudSEK XVigil, add a webhook integration pointing to the URL below.",
    },
    "gtb_dlp": {
        "name": "GTB DLP", "kind": "Data loss prevention", "type": "syslog",
        "config": {"port": 5515, "protocol": "udp"},
        "mapping": {"id": "externalId", "timestamp": "rt", "host": "shost|@asset|dhost", "message": "name|msg",
                    "severity": "cef_severity", "src_ip": "src", "dst_ip": "dst", "user": "suser|duser",
                    "rule": "signature_id", "action": "act"},
        "severity_scale": "0-10", "default_category": "data_exfiltration",
        "help": "In the GTB Central Console, enable CEF syslog export to this server's IP and port.",
    },
    "miniorange": {
        "name": "miniOrange IAM / SSO", "kind": "Identity & access", "type": "webhook",
        "config": {"format": "json"},
        "mapping": {"id": "eventId|id", "timestamp": "timestamp|eventTime", "host": "application|appName",
                    "message": "eventType|event", "severity": "status", "src_ip": "ipAddress|ip",
                    "user": "username|userName", "action": "status"},
        "severity_scale": "text", "default_category": "authentication",
        "help": "Send audit/login events to the webhook URL below.",
    },
    "custom": {
        "name": "Custom tool", "kind": "Any tool", "type": "webhook",
        "config": {"format": "auto"},
        "mapping": {},
        "severity_scale": "auto",
        "help": "Pick how the tool can share logs. Leave the field mapping empty to auto-detect, "
                "then use Preview to check and adjust.",
    },
}

def public_catalog() -> dict[str, Any]:
    return {"types": CONNECTION_TYPES, "presets": PRESETS}


def secret_keys(conn_type: str) -> set[str]:
    return {f["key"] for f in CONNECTION_TYPES[conn_type]["fields"] if f.get("secret")}
