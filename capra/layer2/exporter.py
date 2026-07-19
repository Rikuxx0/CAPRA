from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from .schemas import AttackOperatorGraphModel


def export_attack_operator_graph_json(graph: AttackOperatorGraphModel) -> dict[str, Any]:
    payload = graph.model_dump(mode="json")
    payload["attack_operators"] = sorted(payload["attack_operators"], key=lambda item: item["id"])
    payload["connections"] = sorted(payload["connections"], key=lambda item: item["id"])
    payload["unresolved_items"] = sorted(payload["unresolved_items"], key=lambda item: item["id"])
    payload["layer3_candidates"] = sorted(payload["layer3_candidates"])
    return payload


def serialize_attack_operator_graph_json(graph: AttackOperatorGraphModel, *, indent: int = 2) -> str:
    return json.dumps(export_attack_operator_graph_json(graph), ensure_ascii=False, indent=indent, sort_keys=True)


def save_attack_operator_graph_json(graph: AttackOperatorGraphModel, path: str | Path) -> None:
    Path(path).write_text(serialize_attack_operator_graph_json(graph), encoding="utf-8")


def _dataframe(rows: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def export_operators_dataframe(graph: AttackOperatorGraphModel) -> pd.DataFrame:
    return _dataframe([
        {
            "id": item.id,
            "operator_type": item.operator_type,
            "origin_kind": item.origin_kind,
            "source_tool": item.source_tool,
            "source_node": item.source_node,
            "target_node": item.target_node,
            "status": item.status,
            "verification_status": item.verification_status,
            "manual_verification_required": item.manual_verification_required,
            "public_exploit_candidate": item.public_exploit_candidate,
            "missing_conditions": ", ".join(item.missing_conditions),
        }
        for item in graph.attack_operators
    ])


def export_connections_dataframe(graph: AttackOperatorGraphModel) -> pd.DataFrame:
    return _dataframe([item.model_dump(mode="json") for item in graph.connections])


def export_unresolved_dataframe(graph: AttackOperatorGraphModel) -> pd.DataFrame:
    return _dataframe([
        {
            "id": item.id,
            "type": item.type,
            "source_tool": item.source_tool,
            "source_fact_ids": ", ".join(item.source_fact_ids),
            "missing_conditions": ", ".join(item.missing_conditions),
            "reason": item.reason,
        }
        for item in graph.unresolved_items
    ])


def export_layer3_candidates_dataframe(graph: AttackOperatorGraphModel) -> pd.DataFrame:
    operators = {item.id: item for item in graph.attack_operators}
    return _dataframe([
        {
            "operator_id": operator_id,
            "operator_type": operators[operator_id].operator_type,
            "target_node": operators[operator_id].target_node,
            "status": operators[operator_id].status,
        }
        for operator_id in graph.layer3_candidates
        if operator_id in operators
    ])
