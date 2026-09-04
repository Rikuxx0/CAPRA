from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

import networkx as nx

from .layer1.exporters import SCHEMA_VERSION as LAYER1_SCHEMA_VERSION
from .layer1.exporters import export_fact_graph_json
from .layer1.graph_builder import build_layer1_fact_graph
from .layer1.schemas import EdgeModel, NodeModel, VulnerabilityModel
from .layer2.ids import stable_hash
from .layer2.redaction import redact_sensitive_data
from .layer2.schemas import AttackOperatorGraphModel, Layer2Config
from .layer2.service import build_attack_operator_graph


class LayerHandoffError(ValueError):
    """Raised when an in-memory Layer 1 result violates the Layer 2 contract."""


@dataclass(frozen=True)
class CapraPlanResult:
    fact_graph: dict[str, Any]
    attack_operator_graph: AttackOperatorGraphModel
    handoff_hash: str


def _validate_layer1_handoff(payload: dict[str, Any]) -> None:
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise LayerHandoffError("Layer 1 handoff metadata must be an object")
    schema_version = str(metadata.get("schema_version") or "")
    if schema_version != LAYER1_SCHEMA_VERSION:
        raise LayerHandoffError(
            "Layer 1 handoff schema version must be "
            f"{LAYER1_SCHEMA_VERSION}; received {schema_version or 'missing'}"
        )

    for key in ("nodes", "edges", "unmapped_vulnerabilities"):
        if not isinstance(payload.get(key), list):
            raise LayerHandoffError(f"Layer 1 handoff {key} must be a list")

    nodes = payload["nodes"]
    edges = payload["edges"]
    node_ids = [
        str(node.get("id") or "").strip()
        for node in nodes
        if isinstance(node, dict)
    ]
    if len(node_ids) != len(nodes) or any(not node_id for node_id in node_ids):
        raise LayerHandoffError("Layer 1 handoff contains a node without an id")
    if len(set(node_ids)) != len(node_ids):
        raise LayerHandoffError("Layer 1 handoff contains duplicate node ids")

    fact_ids: list[str] = []
    known_nodes = set(node_ids)
    for edge in edges:
        if not isinstance(edge, dict):
            raise LayerHandoffError("Layer 1 handoff contains a non-object edge")
        fact_id = str(edge.get("fact_id") or "").strip()
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if not fact_id or not source or not target:
            raise LayerHandoffError(
                "Layer 1 handoff edges require fact_id, source, and target"
            )
        if source not in known_nodes or target not in known_nodes:
            raise LayerHandoffError(
                f"Layer 1 handoff edge {fact_id} references an unknown node"
            )
        fact_ids.append(fact_id)
    if len(set(fact_ids)) != len(fact_ids):
        raise LayerHandoffError("Layer 1 handoff contains duplicate fact ids")

    expected_counts = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "unmapped_vulnerability_count": len(payload["unmapped_vulnerabilities"]),
    }
    for key, actual_count in expected_counts.items():
        declared_count = metadata.get(key)
        if declared_count is not None and declared_count != actual_count:
            raise LayerHandoffError(
                f"Layer 1 handoff {key} is {declared_count}, expected {actual_count}"
            )


def prepare_layer1_handoff(
    fact_graph: nx.DiGraph | Mapping[str, Any],
) -> dict[str, Any]:
    """Create an isolated, redacted Layer 1 snapshot for Layer 2."""
    if isinstance(fact_graph, nx.DiGraph):
        payload = export_fact_graph_json(fact_graph)
    elif isinstance(fact_graph, Mapping):
        payload = redact_sensitive_data(deepcopy(dict(fact_graph)))
    else:
        raise LayerHandoffError(
            "Layer 1 handoff must be a NetworkX graph or a Fact Graph mapping"
        )
    _validate_layer1_handoff(payload)
    return payload


def build_plan_from_layer1(
    fact_graph: nx.DiGraph | Mapping[str, Any],
    config: Layer2Config | dict[str, Any] | None = None,
    *,
    nvd_client: Any | None = None,
) -> CapraPlanResult:
    """Verify the Layer 1 → Layer 2 boundary and build the Operator graph."""
    payload = prepare_layer1_handoff(fact_graph)
    handoff_hash = stable_hash(redact_sensitive_data(payload))
    operator_graph = build_attack_operator_graph(
        payload,
        config,
        nvd_client=nvd_client,
    )
    consumed_hash = operator_graph.metadata.get("input_fact_graph_hash")
    if consumed_hash != handoff_hash:
        raise RuntimeError("Layer 2 did not consume the verified Layer 1 snapshot")
    return CapraPlanResult(
        fact_graph=payload,
        attack_operator_graph=operator_graph,
        handoff_hash=handoff_hash,
    )


def build_capra_plan(
    nodes: list[NodeModel],
    edges: list[EdgeModel],
    vulnerabilities: list[VulnerabilityModel],
    layer2_config: Layer2Config | dict[str, Any] | None = None,
    *,
    asset_config: dict[str, Any] | None = None,
    vulnerability_mapping_config: dict[str, Any] | None = None,
    selected_goal_ids: set[str] | None = None,
    source_files: list[str] | None = None,
    input_hashes: dict[str, str] | None = None,
    nvd_client: Any | None = None,
) -> CapraPlanResult:
    """Build Layer 1 and pass its exact exported snapshot directly to Layer 2."""
    layer1_graph = build_layer1_fact_graph(
        nodes,
        edges,
        vulnerabilities,
        asset_config=asset_config,
        vulnerability_mapping_config=vulnerability_mapping_config,
        selected_goal_ids=selected_goal_ids,
        source_files=source_files,
        input_hashes=input_hashes,
    )
    return build_plan_from_layer1(
        layer1_graph,
        layer2_config,
        nvd_client=nvd_client,
    )
