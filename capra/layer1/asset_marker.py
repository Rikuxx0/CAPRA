from __future__ import annotations

from typing import Any

from .schemas import NodeModel
from .utils.ids import generate_node_id


# 重要資産候補と侵入起点を既存ノードへ重ねて goal 候補情報を付与する。
def apply_asset_markers(
    nodes: list[NodeModel],
    asset_config: dict[str, Any] | None,
    selected_goal_ids: set[str] | None = None,
) -> list[NodeModel]:
    """Merge critical asset candidates and entry points without fixing goals by default."""
    selected_goal_ids = selected_goal_ids or set()
    # Do not mutate parser output supplied by callers; the same observations may
    # be rebuilt with a different Goal selection in the Streamlit session.
    merged: dict[str, NodeModel] = {}
    for node in nodes:
        copied = _copy_node(node)
        # is_goal is analysis-session state, never an observed input fact.
        copied.is_goal = False
        merged[copied.id] = copied

    for raw_asset in (asset_config or {}).get("assets", []) or []:
        node = _asset_to_node(raw_asset, goal_candidate=True)
        existing_id = _find_match(merged, node)
        resolved_id = existing_id or node.id
        merged[existing_id or node.id] = _merge_node(
            merged.get(resolved_id),
            node,
            # UI/configuration may refer to either the canonical graph ID or the
            # asset declaration ID that was matched by name/type/cloud.
            force_goal=resolved_id in selected_goal_ids or node.id in selected_goal_ids,
        )

    for raw_entry in (asset_config or {}).get("entry_points", []) or []:
        node = _asset_to_node(raw_entry, goal_candidate=False)
        node.is_entry = True
        existing_id = _find_match(merged, node)
        merged[existing_id or node.id] = _merge_node(merged.get(existing_id or node.id), node)

    for node_id in selected_goal_ids:
        if node_id in merged:
            data = merged[node_id]
            data.is_goal = True
            data.goal_candidate = True
            merged[node_id] = data

    return list(merged.values())


# 資産定義の生データを NodeModel に正規化する。
def _asset_to_node(raw: dict[str, Any], goal_candidate: bool) -> NodeModel:
    name = raw.get("name") or raw.get("id") or "unknown"
    node_type = raw.get("type", "unknown")
    cloud = raw.get("cloud", "unknown")
    node_id = raw.get("id") or generate_node_id(name, node_type, cloud)
    category = raw.get("asset_category") or ("critical" if goal_candidate else "unknown")
    return NodeModel(
        id=str(node_id),
        name=str(name),
        type=str(node_type),
        cloud=str(cloud),
        is_entry=bool(raw.get("is_entry", False)),
        is_goal=False,
        goal_candidate=bool(raw.get("goal_candidate", goal_candidate)),
        asset_category=str(category),
        raw_evidence=raw,
    )


# ID 優先、なければ名前・種別・クラウド一致で既存ノードを探す。
def _find_match(nodes: dict[str, NodeModel], candidate: NodeModel) -> str | None:
    if candidate.id in nodes:
        return candidate.id
    for node_id, node in nodes.items():
        if (
            node.name.lower() == candidate.name.lower()
            and node.type == candidate.type
            and node.cloud == candidate.cloud
        ):
            return node_id
    return None


# 既存ノードへ資産属性を上書き統合し、必要なら Goal 扱いにする。
def _merge_node(existing: NodeModel | None, incoming: NodeModel, force_goal: bool = False) -> NodeModel:
    if existing is None:
        incoming.is_goal = force_goal
        return incoming
    existing.is_entry = existing.is_entry or incoming.is_entry
    existing.is_goal = existing.is_goal or force_goal
    existing.goal_candidate = existing.goal_candidate or incoming.goal_candidate
    existing.asset_category = incoming.asset_category if incoming.asset_category != "unknown" else existing.asset_category
    existing.raw_evidence = {**existing.raw_evidence, "asset_marker": incoming.raw_evidence}
    return existing


def _copy_node(node: NodeModel) -> NodeModel:
    if hasattr(node, "model_copy"):
        return node.model_copy(deep=True)
    return node.copy(deep=True)  # pragma: no cover - Pydantic v1 only
