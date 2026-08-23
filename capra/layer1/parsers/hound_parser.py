from __future__ import annotations

import re
from typing import Any

from ..schemas import EdgeModel, NodeModel, normalize_source_tool
from ..utils.ids import generate_fact_id, generate_node_id

EDGE_TYPE_ALIASES = {
    "assumerole": "assume_role",
    "sts:assumerole": "assume_role",
    "getsecretvalue": "read_secret",
    "secretsmanager:getsecretvalue": "read_secret",
    "modifypolicy": "modify_policy",
    "iam:putrolepolicy": "modify_policy",
    "createaccesskey": "create_access_key",
    "iam:createaccesskey": "create_access_key",
    "passrole": "pass_role_or_act_as",
    "iam:passrole": "pass_role_or_act_as",
    "actas": "pass_role_or_act_as",
    "network": "network_access",
    "network_access": "network_access",
    "attachedpolicy": "attached_policy",
    "member_of": "member_of",
    "memberof": "member_of",
    "haspermission": "has_permission",
    "owns": "owns",
    "contains": "contains",
}

# Hound 系の汎用グラフ JSON を Node/Edge モデルへ変換する。
def parse_hound_generic(
    data: dict[str, Any],
    *,
    source_file: str | None = None,
    default_source_tool: str | None = None,
) -> tuple[list[NodeModel], list[EdgeModel]]:
    graph = _extract_graph_container(data)
    top_level_tool = data.get("source_tool") or data.get("tool") or graph.get("source_tool") or graph.get("tool")
    fallback_tool = normalize_source_tool(default_source_tool or top_level_tool or "hound_generic", default="hound_generic")
    nodes = [_parse_node(node, source_file=source_file, source_tool=fallback_tool) for node in graph.get("nodes", []) or []]
    node_ids = {node.id for node in nodes}
    edges: list[EdgeModel] = []

    for edge in graph.get("edges", []) or []:
        parsed = _parse_edge(edge, source_file=source_file, default_source_tool=fallback_tool)
        edges.append(parsed)
        for node_id in (parsed.source, parsed.target):
            if node_id not in node_ids:
                nodes.append(
                    NodeModel(
                        id=node_id,
                        name=node_id.split(":")[-1],
                        cloud=infer_provider(node_id),
                        raw_evidence={
                            "inferred_from_edge": True,
                            "source_file": source_file,
                            "source_tool": parsed.source_tool,
                        },
                    )
                )
                node_ids.add(node_id)
    return nodes, edges


# Hound ごとに揺れる権限名や関係名を CAPRA の標準エッジ種別へ寄せる。
def normalize_edge_type(value: str | None) -> str:
    compact = re.sub(r"[\s_-]+", "", str(value or "").strip().lower())
    direct = str(value or "").strip().lower()
    return EDGE_TYPE_ALIASES.get(compact) or EDGE_TYPE_ALIASES.get(direct) or direct or "unknown"


# 複数フィールドの文字列からクラウドプロバイダを推定する。
def infer_provider(*values: Any) -> str:
    text = " ".join(str(value or "") for value in values).lower()
    providers: set[str] = set()
    if "arn:aws:" in text or "aws:" in text:
        providers.add("aws")
    if (
        "gserviceaccount.com" in text
        or "iam.gserviceaccount.com" in text
        or "gcp:" in text
        or re.search(r"\bprojects/[a-z0-9][a-z0-9-]+", text)
    ):
        providers.add("gcp")
    if (
        "/subscriptions/" in text
        or "tenantid" in text
        or "tenant_id" in text
        or "microsoft." in text
        or "azure:" in text
    ):
        providers.add("azure")
    if (
        "k8s:" in text
        or "clusterrole" in text
        or "serviceaccount" in text and "gserviceaccount.com" not in text and "gcp:" not in text
        or "namespace" in text
        or "kubernetes" in text
    ):
        providers.add("k8s")
    if len(providers) == 1:
        return next(iter(providers))
    if len(providers) > 1:
        return "hybrid"
    return "unknown"


# 入力 JSON のどこに nodes/edges があるかを吸収して取り出す。
def _extract_graph_container(data: dict[str, Any]) -> dict[str, Any]:
    if "nodes" in data or "edges" in data:
        return data
    if isinstance(data.get("data"), dict):
        return data["data"]
    if isinstance(data.get("graph"), dict):
        return data["graph"]
    return {"nodes": [], "edges": []}


# 生ノード辞書から NodeModel を生成し、欠損値は推定や既定値で補う。
def _parse_node(
    node: dict[str, Any],
    *,
    source_file: str | None = None,
    source_tool: str = "hound_generic",
) -> NodeModel:
    name = node.get("name") or node.get("label") or node.get("displayName") or node.get("id") or "unknown"
    node_type = node.get("type") or node.get("kind") or node.get("labels") or "unknown"
    if isinstance(node_type, list):
        node_type = node_type[0] if node_type else "unknown"
    cloud = node.get("cloud") or node.get("provider") or infer_provider(node.get("id"), name, node)
    node_id = node.get("id") or node.get("objectid") or generate_node_id(name, str(node_type), str(cloud))
    evidence = dict(node)
    if source_file:
        evidence.setdefault("source_file", source_file)
    evidence.setdefault("source_tool", source_tool)
    return NodeModel(
        id=str(node_id),
        name=str(name),
        type=str(node_type),
        cloud=str(cloud),
        is_entry=bool(node.get("is_entry", False)),
        # Goal selection belongs to apply_asset_markers()/the analysis session.
        is_goal=False,
        goal_candidate=bool(node.get("goal_candidate", False)),
        asset_category=node.get("asset_category", "unknown"),
        raw_evidence=evidence,
    )


# 生エッジ辞書から EdgeModel を生成し、種別を正規化する。
def _parse_edge(
    edge: dict[str, Any],
    *,
    source_file: str | None = None,
    default_source_tool: str = "hound_generic",
) -> EdgeModel:
    source = _endpoint_id(edge.get("source") or edge.get("from") or edge.get("start") or edge.get("source_id"))
    target = _endpoint_id(edge.get("target") or edge.get("to") or edge.get("end") or edge.get("target_id"))
    permission = edge.get("permission") or edge.get("relationship") or edge.get("label") or edge.get("type") or ""
    edge_type = normalize_edge_type(edge.get("type") or permission)
    provider = edge.get("provider") or edge.get("cloud") or infer_provider(source, target, permission, edge)
    source_tool = normalize_source_tool(edge.get("source_tool") or edge.get("tool") or default_source_tool)
    resolved_source_file = str(edge.get("source_file") or source_file) if edge.get("source_file") or source_file else None
    original_edge_type = str(edge.get("original_edge_type") or edge.get("type") or permission or "unknown")
    source_id = str(source or "unknown-source")
    target_id = str(target or "unknown-target")
    fact_id = str(edge.get("fact_id") or edge.get("id")) if edge.get("fact_id") or edge.get("id") else generate_fact_id(
        source=source_id,
        target=target_id,
        edge_type=edge_type,
        permission=str(permission),
        source_tool=source_tool,
        source_file=resolved_source_file,
        original_edge_type=original_edge_type,
    )
    evidence = dict(edge)
    if resolved_source_file:
        evidence.setdefault("source_file", resolved_source_file)
    evidence.setdefault("source_tool", source_tool)
    return EdgeModel(
        fact_id=fact_id,
        source=source_id,
        target=target_id,
        type=edge_type,
        permission=str(permission),
        provider=str(provider),
        source_tool=source_tool,
        source_file=resolved_source_file,
        original_edge_type=original_edge_type,
        raw_evidence=evidence,
    )


def _endpoint_id(value: Any) -> Any:
    if isinstance(value, dict):
        return value.get("id") or value.get("objectid") or value.get("objectId") or value.get("name")
    return value
