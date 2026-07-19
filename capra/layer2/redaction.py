from __future__ import annotations

from typing import Any

REDACTED = "[REDACTED]"
SENSITIVE_KEYS = {
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


def redact_sensitive_data(value: Any) -> Any:
    """Return a recursively redacted copy without mutating the input."""
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            if str(key).strip().lower() in SENSITIVE_KEYS:
                result[key] = REDACTED
            else:
                result[key] = redact_sensitive_data(item)
        return result
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    return value
