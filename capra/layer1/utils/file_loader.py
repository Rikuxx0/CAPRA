from __future__ import annotations

import json
from typing import Any

import yaml


def load_json_or_yaml(text: str, filename: str | None = None) -> dict[str, Any]:
    name = (filename or "").lower()
    if name.endswith(".json"):
        return json.loads(text or "{}")
    if name.endswith((".yaml", ".yml")):
        return yaml.safe_load(text or "{}") or {}
    try:
        return json.loads(text or "{}")
    except json.JSONDecodeError:
        return yaml.safe_load(text or "{}") or {}
