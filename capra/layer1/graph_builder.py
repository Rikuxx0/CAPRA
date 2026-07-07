from __future__ import annotations

from typing import Any

import networkx as nx

from .asset_marker import apply_asset_markers
from .schemas import EdgeModel, NodeModel, VulnerabilityModel, model_to_dict
from .vuln_mapper import attach_vulnerabilities_to_nodes


# ノード重複や欠損端点を吸収しながら有向グラフを構築する。
def build_fact_graph(nodes: list[NodeModel], edges: list[EdgeModel]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for node in nodes:
        if graph.has_node(node.id):
            graph.nodes[node.id].update(_merge_node_dict(graph.nodes[node.id], model_to_dict(node)))
        else:
            graph.add_node(node.id, **model_to_dict(node))

    seen_edges: set[tuple[str, str, str, str]] = set()
    for edge in edges:
        key = (edge.source, edge.target, edge.type, edge.permission)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        for endpoint in (edge.source, edge.target):
            if not graph.has_node(endpoint):
                graph.add_node(
                    endpoint,
                    **model_to_dict(NodeModel(id=endpoint, name=endpoint.split(":")[-1], raw_evidence={"inferred": True})),
                )
        graph.add_edge(edge.source, edge.target, **model_to_dict(edge))
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
) -> nx.DiGraph:
    marked_nodes = apply_asset_markers(nodes, asset_config, selected_goal_ids=selected_goal_ids)
    mapped_nodes, unmapped = attach_vulnerabilities_to_nodes(
        marked_nodes,
        vulnerabilities,
        mapping_config=vulnerability_mapping_config,
    )
    graph = build_fact_graph(mapped_nodes, edges)
    graph.graph["unmapped_vulnerabilities"] = [model_to_dict(item) for item in unmapped]
    graph.graph["source_files"] = source_files or []
    graph.graph["schema_status"] = "provisional"
    return graph


# 同一ノードの属性を統合し、脆弱性情報を欠落なくマージする。
def _merge_node_dict(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    merged["is_entry"] = bool(existing.get("is_entry")) or bool(incoming.get("is_entry"))
    merged["is_goal"] = bool(existing.get("is_goal")) or bool(incoming.get("is_goal"))
    merged["goal_candidate"] = bool(existing.get("goal_candidate")) or bool(incoming.get("goal_candidate"))
    merged["asset_category"] = incoming.get("asset_category") if incoming.get("asset_category") != "unknown" else existing.get("asset_category", "unknown")
    merged["vulnerabilities"] = list(existing.get("vulnerabilities", [])) + list(incoming.get("vulnerabilities", []))
    merged["raw_evidence"] = {**existing.get("raw_evidence", {}), **incoming.get("raw_evidence", {})}
    return merged
