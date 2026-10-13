"""Creating, validating and presenting integrations (the 'Connect a tool' feature)."""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from .db import Database
from .mapping import SEVERITY_SCALES, UNIFIED_FIELDS
from .models import CATEGORIES
from .presets import CONNECTION_TYPES, PRESETS, secret_keys
from .vault import SecretBox, redact


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def clean_config(conn_type: str, config: dict[str, Any]) -> dict[str, Any]:
    """Keep only known fields, coerce types, apply defaults, enforce required ones."""
    if conn_type not in CONNECTION_TYPES:
        raise ValueError(f"unknown connection type '{conn_type}'")
    out: dict[str, Any] = {}
    for spec in CONNECTION_TYPES[conn_type]["fields"]:
        key = spec["key"]
        value = config.get(key, spec.get("default"))
        if spec.get("type") == "bool":
            value = value if isinstance(value, bool) else str(value).lower() in {"1", "true", "yes", "on"}
        elif spec.get("type") == "int" and value not in (None, ""):
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{spec['label']} must be a number") from None
        elif isinstance(value, str):
            value = value.strip()
        if "choices" in spec and value not in (None, "") and value not in spec["choices"]:
            raise ValueError(f"{spec['label']} must be one of {spec['choices']}")
        if value not in (None, ""):
            out[key] = value
    for spec in CONNECTION_TYPES[conn_type]["fields"]:
        visible = all(out.get(k) in (v if isinstance(v, list) else [v]) for k, v in spec.get("show_if", {}).items())
        if spec.get("required") and visible and out.get(spec["key"]) in (None, "") and not spec.get("secret"):
            raise ValueError(f"{spec['label']} is required")
    if conn_type == "syslog" and not 1 <= int(out.get("port", 0)) <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    if "url" in out and not str(out["url"]).lower().startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    return out


def clean_mapping(mapping: dict[str, Any] | None) -> dict[str, str]:
    mapping = mapping or {}
    return {k: str(v).strip()[:500] for k, v in mapping.items() if k in UNIFIED_FIELDS and str(v or "").strip()}


def build(payload: dict[str, Any], box: SecretBox, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate an integration form and return the DB row (secrets sealed)."""
    tool = payload.get("tool") or (existing or {}).get("tool") or "custom"
    if tool not in PRESETS:
        raise ValueError(f"unknown tool preset '{tool}'")
    conn_type = payload.get("type") or (existing or {}).get("type") or PRESETS[tool]["type"]
    name = str(payload.get("name") or "").strip() or PRESETS[tool]["name"]
    scale = payload.get("severity_scale") or PRESETS[tool].get("severity_scale", "auto")
    if scale not in SEVERITY_SCALES:
        raise ValueError(f"severity scale must be one of {list(SEVERITY_SCALES)}")
    category = payload.get("default_category") or (existing or {}).get("default_category")         or PRESETS[tool].get("default_category")
    if category and category not in CATEGORIES:
        raise ValueError(f"default category must be one of {list(CATEGORIES)}")

    config = clean_config(conn_type, payload.get("config") or {})
    previous = (existing or {}).get("config") if existing and existing.get("type") == conn_type else None
    row = {
        "name": name[:120],
        "tool": tool,
        "type": conn_type,
        "config": box.seal(config, secret_keys(conn_type), previous),
        # No mapping sent → keep the current one, or start from the tool's preset.
        "mapping": clean_mapping(payload.get("mapping")) or (existing or {}).get("mapping") or dict(PRESETS[tool]["mapping"]),
        "severity_scale": scale,
        "default_category": category,
        "enabled": bool(payload.get("enabled", True)),
    }
    for spec in CONNECTION_TYPES[conn_type]["fields"]:
        visible = all(config.get(k) in (v if isinstance(v, list) else [v]) for k, v in spec.get("show_if", {}).items())
        if spec.get("secret") and spec.get("required") and visible and not row["config"].get(spec["key"]):
            raise ValueError(f"{spec['label']} is required")
    return row


def new_webhook_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(24)
    return token, token_hash(token)


def to_public(integ: dict[str, Any], box: SecretBox, public_url: str, event_count: int = 0,
              listening: bool | None = None) -> dict[str, Any]:
    """What the browser sees: no secrets, plus the webhook URL / syslog address to configure on the tool."""
    out = {k: integ[k] for k in ("id", "name", "tool", "type", "mapping", "severity_scale", "default_category",
                                 "enabled", "demo", "last_status", "last_error", "last_run_at", "last_count", "created_at")}
    out["config"] = redact(integ["config"], secret_keys(integ["type"]))
    out["mode"] = CONNECTION_TYPES[integ["type"]]["mode"]
    out["preset_name"] = PRESETS.get(integ["tool"], {}).get("name", integ["tool"])
    out["kind"] = PRESETS.get(integ["tool"], {}).get("kind", "")
    out["events"] = event_count
    if integ["type"] == "webhook" and integ.get("webhook_token") and not integ["demo"]:
        out["webhook_url"] = f"{public_url}/api/ingest/{box.decrypt(integ['webhook_token'])}"
    if integ["type"] == "syslog":
        out["listening"] = listening
    return out


def seed_demo(db: Database, box: SecretBox, tools: tuple[str, ...]) -> None:
    """One demo integration per tool, with the real presets, so the demo uses the real mappings."""
    existing = {i["tool"] for i in db.list_integrations() if i["demo"]}
    for tool in tools:
        if tool in existing:
            continue
        preset = PRESETS[tool]
        db.add_integration({
            "name": f"{preset['name']} (demo)",
            "tool": tool,
            "type": preset["type"],
            "config": box.seal(dict(preset["config"]), secret_keys(preset["type"])),
            "mapping": preset["mapping"],
            "severity_scale": preset.get("severity_scale", "auto"),
            "default_category": preset.get("default_category"),
            "enabled": True,
            "demo": True,
        })
