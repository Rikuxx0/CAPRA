from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd


def export_fact_graph_json(graph: nx.DiGraph) -> dict[str, Any]:
    nodes = [dict(data) for _, data in graph.nodes(data=True)]
    edges = [dict(data) for _, _, data in graph.edges(data=True)]
    vulnerabilities = [vuln for node in nodes for vuln in node.get("vulnerabilities", [])]
    unmapped = graph.graph.get("unmapped_vulnerabilities", [])
    return {
        "nodes": nodes,
        "edges": edges,
        "unmapped_vulnerabilities": unmapped,
        "metadata": {
            "source_files": graph.graph.get("source_files", []),
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
            "vulnerability_count": len(vulnerabilities),
            "unmapped_vulnerability_count": len(unmapped),
            "schema_status": graph.graph.get("schema_status", "provisional"),
        },
    }


def export_nodes_dataframe(graph: nx.DiGraph) -> pd.DataFrame:
    rows = []
    for _, data in graph.nodes(data=True):
        row = dict(data)
        row["vulnerability_count"] = len(row.get("vulnerabilities", []))
        row.pop("raw_evidence", None)
        row.pop("vulnerabilities", None)
        rows.append(row)
    return pd.DataFrame(rows)


def export_edges_dataframe(graph: nx.DiGraph) -> pd.DataFrame:
    rows = []
    for _, _, data in graph.edges(data=True):
        row = dict(data)
        row.pop("raw_evidence", None)
        rows.append(row)
    return pd.DataFrame(rows)


def export_vulnerabilities_dataframe(graph: nx.DiGraph) -> pd.DataFrame:
    rows = []
    for _, node in graph.nodes(data=True):
        for vulnerability in node.get("vulnerabilities", []):
            row = dict(vulnerability)
            row["node_id"] = node.get("id")
            row["node_name"] = node.get("name")
            row.pop("raw_evidence", None)
            rows.append(row)
    for vulnerability in graph.graph.get("unmapped_vulnerabilities", []):
        row = dict(vulnerability)
        row["node_id"] = None
        row["node_name"] = None
        row["unmapped"] = True
        row.pop("raw_evidence", None)
        rows.append(row)
    return pd.DataFrame(rows)


def save_fact_graph_json(graph: nx.DiGraph, path: str | Path) -> None:
    output_path = Path(path)
    output_path.write_text(json.dumps(export_fact_graph_json(graph), indent=2, ensure_ascii=False), encoding="utf-8")
