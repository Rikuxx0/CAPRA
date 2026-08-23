from __future__ import annotations

from typing import Any

from ..schemas import EdgeModel, NodeModel
from .hound_parser import parse_hound_generic


def parse_cross_cloud_dependencies(
    data: dict[str, Any],
    *,
    source_file: str | None = None,
) -> tuple[list[NodeModel], list[EdgeModel]]:
    """Normalize declared cross-cloud facts without inferring attackability."""
    dependencies = data.get("dependencies", data.get("edges", []))
    if not isinstance(dependencies, list):
        raise ValueError("cross-cloud dependencies must be a list")
    nodes = data.get("nodes", [])
    if not isinstance(nodes, list):
        raise ValueError("cross-cloud nodes must be a list")
    normalized_edges = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("each cross-cloud dependency must be an object")
        item = dict(dependency)
        item.setdefault("type", "depends_on")
        item.setdefault("permission", "")
        item.setdefault("source_tool", "manual")
        normalized_edges.append(item)
    return parse_hound_generic(
        {"nodes": nodes, "edges": normalized_edges},
        source_file=source_file,
        default_source_tool="manual",
    )


__all__ = ["parse_cross_cloud_dependencies"]
