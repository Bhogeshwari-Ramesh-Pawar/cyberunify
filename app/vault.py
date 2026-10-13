"""Encryption for integration credentials (passwords, API keys, tokens).

Secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before they reach SQLite.
The key comes from CYBERUNIFY_SECRET_KEY, or is generated once into a key file next to
the database. The API never returns a secret; it only says whether one is set.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:"


class SecretBox:
    def __init__(self, key: bytes):
        self._fernet = Fernet(key)

    @classmethod
    def from_env_or_file(cls, key_file: Path) -> "SecretBox":
        env_key = os.getenv("CYBERUNIFY_SECRET_KEY")
        if env_key:
            return cls(env_key.encode())
        if key_file.exists():
            return cls(key_file.read_bytes().strip())
        key = Fernet.generate_key()
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(key)
        try:
            key_file.chmod(0o600)  # owner-only on Linux/macOS; best effort on Windows
        except OSError:
            pass
        return cls(key)

    def encrypt(self, value: str) -> str:
        return PREFIX + self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, value: str) -> str:
        if not value.startswith(PREFIX):
            return value
        try:
            return self._fernet.decrypt(value[len(PREFIX):].encode()).decode()
        except InvalidToken as err:
            raise ValueError("cannot decrypt a stored credential: was the secret key changed?") from err

    # ---------- whole configs ----------

    def seal(self, config: dict[str, Any], secret_keys: set[str], previous: dict[str, Any] | None = None) -> dict[str, Any]:
        """Encrypt secret fields. A blank secret on edit means "keep the existing one"."""
        previous = previous or {}
        sealed = dict(config)
        for key in secret_keys:
            value = sealed.get(key)
            if value in (None, ""):
                if previous.get(key):
                    sealed[key] = previous[key]
                else:
                    sealed.pop(key, None)
            elif not str(value).startswith(PREFIX):
                sealed[key] = self.encrypt(str(value))
        return sealed

    def open(self, config: dict[str, Any], secret_keys: set[str]) -> dict[str, Any]:
        opened = dict(config)
        for key in secret_keys:
            if opened.get(key):
                opened[key] = self.decrypt(opened[key])
        return opened


def redact(config: dict[str, Any], secret_keys: set[str]) -> dict[str, Any]:
    """What the browser sees: secrets replaced by a flag."""
    out = {k: v for k, v in config.items() if k not in secret_keys}
    out["_secrets_set"] = sorted(k for k in secret_keys if config.get(k))
    return out
