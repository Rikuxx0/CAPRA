from __future__ import annotations

from typing import Any

import networkx as nx

from .asset_marker import apply_asset_markers
from .schemas import EdgeModel, NodeModel, VulnerabilityModel, model_to_dict
from .utils.ids import generate_fact_id
from .vuln_mapper import attach_vulnerabilities_to_nodes


# ノード重複や欠損端点を吸収しながら有向グラフを構築する。
def build_fact_graph(nodes: list[NodeModel], edges: list[EdgeModel]) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for node in nodes:
        if graph.has_node(node.id):
            graph.nodes[node.id].update(_merge_node_dict(graph.nodes[node.id], model_to_dict(node)))
        else:
            graph.add_node(node.id, **model_to_dict(node))

    seen_edges: set[str] = set()
    for edge in edges:
        edge_data = model_to_dict(edge)
        fact_id = edge.fact_id or generate_fact_id(
            source=edge.source,
            target=edge.target,
            edge_type=edge.type,
            permission=edge.permission,
            source_tool=edge.source_tool,
            source_file=edge.source_file,
            original_edge_type=edge.original_edge_type,
        )
        edge_data["fact_id"] = fact_id
        if fact_id in seen_edges:
            continue
        seen_edges.add(fact_id)
        for endpoint in (edge.source, edge.target):
            if not graph.has_node(endpoint):
                graph.add_node(
                    endpoint,
                    **model_to_dict(NodeModel(id=endpoint, name=endpoint.split(":")[-1], raw_evidence={"inferred": True})),
                )
        graph.add_edge(edge.source, edge.target, key=fact_id, **edge_data)
    graph.graph["unmapped_vulnerabilities"] = []
    graph.graph["schema_status"] = "provisional"
    return graph


# 資産マーク付けと脆弱性紐付けを反映した Layer 1 Fact Graph を組み立てる。
def build_layer1_fact_graph(
    nodes: list[NodeModel],
    edges: list[EdgeModel],
    vulnerabilities: list[VulnerabilityModel],
    asset_config: dict[str, Any] | None = None,
    vulnerability_mapping_config: dict[str, Any] | None = None,
    selected_goal_ids: set[str] | None = None,
    source_files: list[str] | None = None,
    input_hashes: dict[str, str] | None = None,
) -> nx.MultiDiGraph:
    marked_nodes = apply_asset_markers(nodes, asset_config, selected_goal_ids=selected_goal_ids)
    mapped_nodes, unmapped = attach_vulnerabilities_to_nodes(
        marked_nodes,
        vulnerabilities,
        mapping_config=vulnerability_mapping_config,
    )
    graph = build_fact_graph(mapped_nodes, edges)
    graph.graph["unmapped_vulnerabilities"] = [model_to_dict(item) for item in unmapped]
    graph.graph["source_files"] = source_files or []
    graph.graph["input_hashes"] = input_hashes or {}
    graph.graph["schema_status"] = "provisional"
    return graph


# 同一ノードの属性を統合し、脆弱性情報を欠落なくマージする。
def _merge_node_dict(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    merged["is_entry"] = bool(existing.get("is_entry")) or bool(incoming.get("is_entry"))
    merged["is_goal"] = bool(existing.get("is_goal")) or bool(incoming.get("is_goal"))
    merged["goal_candidate"] = bool(existing.get("goal_candidate")) or bool(incoming.get("goal_candidate"))
    merged["asset_category"] = incoming.get("asset_category") if incoming.get("asset_category") != "unknown" else existing.get("asset_category", "unknown")
    merged["vulnerabilities"] = _merge_vulnerabilities(
        existing.get("vulnerabilities", []), incoming.get("vulnerabilities", [])
    )
    merged["raw_evidence"] = _merge_evidence(
        existing.get("raw_evidence", {}), incoming.get("raw_evidence", {})
    )
    return merged


def _merge_vulnerabilities(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in [*existing, *incoming]:
        key = (
            item.get("id"), item.get("cve_id"), item.get("package_name"),
            item.get("installed_version"), item.get("source"),
        )
        if key not in seen:
            merged.append(item)
            seen.add(key)
    return merged


def _merge_evidence(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Preserve every distinct source record when duplicate nodes are merged."""
    if not existing:
        return incoming
    if not incoming or existing == incoming:
        return existing
    records: list[dict[str, Any]] = []
    for value in (existing, incoming):
        nested = value.get("records") if set(value) == {"records"} else None
        records.extend(nested if isinstance(nested, list) else [value])
    unique: list[dict[str, Any]] = []
    for record in records:
        if record not in unique:
            unique.append(record)
    return {"records": unique}
