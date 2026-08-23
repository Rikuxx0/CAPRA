from __future__ import annotations

from typing import Any


REDACTED_VALUE = "[REDACTED]"
SENSITIVE_KEY_PARTS = {
    "secret",
    "secret_value",
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "access_key",
    "secret_access_key",
    "private_key",
    "client_secret",
    "authorization",
    "credential",
    "credentials",
}


def _normalize_key(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _is_sensitive_key(value: Any) -> bool:
    key = _normalize_key(value)
    return key in SENSITIVE_KEY_PARTS or any(
        part in key for part in ("password", "secret", "token", "credential", "private_key")
    )


def redact_sensitive_data(value: Any) -> Any:
    """Recursively redact credential-bearing values while preserving structure."""
    if isinstance(value, dict):
        return {
            key: REDACTED_VALUE if _is_sensitive_key(key) else redact_sensitive_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive_data(item) for item in value]
    return value


__all__ = ["REDACTED_VALUE", "redact_sensitive_data"]
