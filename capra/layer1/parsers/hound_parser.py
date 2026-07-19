from __future__ import annotations

import re
from typing import Any

from ..schemas import EdgeModel, NodeModel
from ..utils.ids import generate_node_id

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
}

# Hound 系の汎用グラフ JSON を Node/Edge モデルへ変換する。
def parse_hound_generic(data: dict[str, Any]) -> tuple[list[NodeModel], list[EdgeModel]]:
    graph = _extract_graph_container(data)
    nodes = [_parse_node(node) for node in graph.get("nodes", []) or []]
    node_ids = {node.id for node in nodes}
    edges: list[EdgeModel] = []

    for edge in graph.get("edges", []) or []:
        parsed = _parse_edge(edge)
        edges.append(parsed)
        for node_id in (parsed.source, parsed.target):
            if node_id not in node_ids:
                nodes.append(
                    NodeModel(
                        id=node_id,
                        name=node_id.split(":")[-1],
                        cloud=infer_provider(node_id),
                        raw_evidence={"inferred_from_edge": True},
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
    if "arn:aws:" in text:
        return "aws"
    if "gserviceaccount.com" in text or "serviceaccount:" in text or "iam.gserviceaccount.com" in text:
        return "gcp"
    if "/subscriptions/" in text or "tenantid" in text or "microsoft." in text:
        return "azure"
    if "clusterrole" in text or "namespace" in text or "serviceaccount" in text or "kubernetes" in text:
        return "k8s"
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
def _parse_node(node: dict[str, Any]) -> NodeModel:
    name = node.get("name") or node.get("label") or node.get("displayName") or node.get("id") or "unknown"
    node_type = node.get("type") or node.get("kind") or node.get("labels") or "unknown"
    if isinstance(node_type, list):
        node_type = node_type[0] if node_type else "unknown"
    cloud = node.get("cloud") or node.get("provider") or infer_provider(node.get("id"), name, node)
    node_id = node.get("id") or node.get("objectid") or generate_node_id(name, str(node_type), str(cloud))
    return NodeModel(
        id=str(node_id),
        name=str(name),
        type=str(node_type),
        cloud=str(cloud),
        is_entry=bool(node.get("is_entry", False)),
        is_goal=bool(node.get("is_goal", False)),
        goal_candidate=bool(node.get("goal_candidate", False)),
        asset_category=node.get("asset_category", "unknown"),
        raw_evidence=node,
    )


# 生エッジ辞書から EdgeModel を生成し、種別を正規化する。
def _parse_edge(edge: dict[str, Any]) -> EdgeModel:
    source = edge.get("source") or edge.get("from") or edge.get("start") or edge.get("source_id")
    target = edge.get("target") or edge.get("to") or edge.get("end") or edge.get("target_id")
    permission = edge.get("permission") or edge.get("relationship") or edge.get("label") or edge.get("type") or ""
    edge_type = normalize_edge_type(edge.get("type") or permission)
    provider = edge.get("provider") or edge.get("cloud") or infer_provider(source, target, permission, edge)
    return EdgeModel(
        fact_id=str(edge.get("fact_id") or edge.get("id")) if edge.get("fact_id") or edge.get("id") else None,
        source=str(source or "unknown-source"),
        target=str(target or "unknown-target"),
        type=edge_type,
        permission=str(permission),
        provider=str(provider),
        source_tool=str(edge.get("source_tool") or edge.get("tool") or "unknown").strip().lower(),
        source_file=str(edge.get("source_file")) if edge.get("source_file") else None,
        original_edge_type=str(edge.get("original_edge_type") or edge.get("type") or permission or "unknown"),
        raw_evidence=edge,
    )
