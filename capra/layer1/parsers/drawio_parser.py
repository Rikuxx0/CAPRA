from __future__ import annotations

import html
import re
from typing import Any
from xml.etree import ElementTree as ET

from ..schemas import EdgeModel, NodeModel
from ..utils.ids import generate_node_id


# Draw.io XML を Layer 1 のノード・エッジ構造へ変換する。
def parse_drawio_to_layer1(xml_text: str) -> tuple[list[NodeModel], list[EdgeModel]]:
    """Parse Draw.io XML into Layer 1's provisional schema."""
    graph = _parse_drawio_xml(xml_text)
    id_map: dict[str, str] = {}
    nodes: list[NodeModel] = []
    edges: list[EdgeModel] = []

    for raw_node in graph.get("nodes", []) or []:
        label = raw_node.get("label") or raw_node.get("id") or "unknown"
        node_type, goal_candidate, is_entry = _infer_node_traits(label)
        node_id = generate_node_id(label, node_type, "unknown")
        id_map[str(raw_node.get("id"))] = node_id
        nodes.append(
            NodeModel(
                id=node_id,
                name=label,
                type=node_type,
                cloud="unknown",
                is_entry=is_entry,
                goal_candidate=goal_candidate,
                asset_category="critical" if goal_candidate else "unknown",
                raw_evidence=raw_node,
            )
        )

    for raw_edge in graph.get("edges", []) or []:
        source = id_map.get(str(raw_edge.get("source")))
        target = id_map.get(str(raw_edge.get("target")))
        if source and target:
            edges.append(
                EdgeModel(
                    fact_id=str(raw_edge.get("id")) if raw_edge.get("id") else None,
                    source=source,
                    target=target,
                    type="network_access",
                    permission="drawio:connected",
                    provider="unknown",
                    source_tool="drawio",
                    original_edge_type="network_access",
                    raw_evidence=raw_edge,
                )
            )
    return nodes, edges


# Draw.io XML 内の mxCell を走査してノードとエッジの生データへ分解する。
def _parse_drawio_xml(xml_text: str) -> dict[str, list[dict[str, Any]]]:
    root = ET.fromstring(xml_text)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for mxcell in root.iter("mxCell"):
        attr = mxcell.attrib.copy()
        geometry = mxcell.find("mxGeometry")
        geometry_data = geometry.attrib.copy() if geometry is not None else {}

        if attr.get("vertex") == "1":
            nodes.append(
                {
                    "id": attr.get("id"),
                    "label": _clean_drawio_label(attr.get("value", "")),
                    "style": attr.get("style"),
                    "geometry": geometry_data,
                }
            )
        elif attr.get("edge") == "1":
            edges.append(
                {
                    "id": attr.get("id"),
                    "source": attr.get("source"),
                    "target": attr.get("target"),
                    "style": attr.get("style"),
                }
            )

    return {"nodes": nodes, "edges": edges}


# Draw.io ラベルの HTML を除去し、空白を整えて安全な文字列へ戻す。
def _clean_drawio_label(value: str) -> str:
    unescaped = html.unescape(value or "")
    value_with_spaces = re.sub(r"</p>|<br/?>|</div>", " ", unescaped, flags=re.I)
    stripped_value = re.sub(r"<[^>]+>", "", value_with_spaces)
    return html.escape(re.sub(r"\s+", " ", stripped_value).strip())


# ラベル文字列からノード種別と Goal/Entry 候補属性を推定する。
def _infer_node_traits(label: str) -> tuple[str, bool, bool]:
    text = label.lower()
    if any(keyword in text for keyword in ("db", "database", "rds", "sql")):
        return "db", False, False
    if any(keyword in text for keyword in ("secret", "secrets manager", "key vault")):
        return "secret", True, False
    if any(keyword in text for keyword in ("admin", "root", "cluster admin")):
        return "role", True, False
    if any(keyword in text for keyword in ("user", "client", "internet")):
        return "user", False, True
    if any(keyword in text for keyword in ("service", "api", "backend", "frontend")):
        return "service", False, False
    return "resource", False, False
