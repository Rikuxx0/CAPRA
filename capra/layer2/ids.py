from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key).strip(): _jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, str):
        return value.strip()
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalized_text(value: str | None, *, lower: bool = False) -> str | None:
    normalized = str(value or "").strip()
    if not normalized:
        return None
    return normalized.lower() if lower else normalized


def generate_operator_id(
    *,
    operator_type: str,
    origin_kind: str,
    source_node: str | None,
    target_node: str | None,
    source_fact_ids: list[str],
    mapping_rule_id: str | None,
    provider: str = "unknown",
) -> str:
    normalized_type = _normalized_text(operator_type, lower=True) or "unknown"
    payload = {
        "operator_type": normalized_type,
        "origin_kind": _normalized_text(origin_kind, lower=True),
        "source_node": _normalized_text(source_node),
        "target_node": _normalized_text(target_node),
        "source_fact_ids": sorted({_normalized_text(item) for item in source_fact_ids if _normalized_text(item)}),
        "mapping_rule_id": _normalized_text(mapping_rule_id),
    }
    provider_name = _normalized_text(provider, lower=True) or "unknown"
    return f"attack_op:{provider_name}:{normalized_type}:{stable_hash(payload)[:12]}"


def generate_connection_id(
    source_operator_id: str,
    target_operator_id: str,
    connection_type: str,
    artifact: Any = None,
) -> str:
    payload = {
        "source_operator_id": _normalized_text(source_operator_id),
        "target_operator_id": _normalized_text(target_operator_id),
        "connection_type": _normalized_text(connection_type, lower=True),
        "artifact": _jsonable(artifact),
    }
    return f"connection:{stable_hash(payload)[:16]}"


def generate_unresolved_id(
    *,
    item_type: str,
    source_tool: str,
    source_fact_ids: list[str],
    reason: str,
    missing_conditions: list[str] | None = None,
) -> str:
    payload = {
        "type": _normalized_text(item_type, lower=True),
        "source_tool": _normalized_text(source_tool, lower=True),
        "source_fact_ids": sorted({_normalized_text(item) for item in source_fact_ids if _normalized_text(item)}),
        "reason": _normalized_text(reason),
        "missing_conditions": sorted({_normalized_text(item) for item in (missing_conditions or []) if _normalized_text(item)}),
    }
    tool = _normalized_text(source_tool, lower=True) or "unknown"
    return f"unresolved:{tool}:{stable_hash(payload)[:16]}"
