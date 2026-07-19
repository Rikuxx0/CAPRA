from __future__ import annotations

from typing import Any

import networkx as nx

from .ids import canonical_json, generate_connection_id
from .schemas import AttackOperatorConnectionModel, AttackOperatorModel, OperatorArtifactModel

INVALID_NODE_IDS = {"", "unknown", "none", "null"}


def _valid_node_id(value: str | None) -> bool:
    return str(value or "").strip().lower() not in INVALID_NODE_IDS


def _artifact_matches(produced: OperatorArtifactModel, required: OperatorArtifactModel) -> bool:
    if produced.artifact_type != required.artifact_type:
        return False
    if not _valid_node_id(produced.subject_node_id) or not _valid_node_id(required.subject_node_id):
        return False
    if produced.subject_node_id != required.subject_node_id:
        return False
    return all(produced.properties.get(key) == value for key, value in required.properties.items())


def build_operator_connections(
    operators: list[AttackOperatorModel],
    max_connections: int,
) -> tuple[list[AttackOperatorConnectionModel], list[str]]:
    connections: dict[str, AttackOperatorConnectionModel] = {}
    warnings: list[str] = []
    ordered = sorted(operators, key=lambda operator: operator.id)

    def add(connection: AttackOperatorConnectionModel) -> bool:
        if connection.id in connections:
            return True
        if len(connections) >= max_connections:
            if not warnings:
                warnings.append(f"Connection limit reached: {max_connections}")
            return False
        connections[connection.id] = connection
        return True

    for source in ordered:
        for target in ordered:
            if source.id == target.id:
                continue
            if _valid_node_id(source.target_node) and source.target_node == target.source_node:
                connection = AttackOperatorConnectionModel(
                    id=generate_connection_id(source.id, target.id, "enables"),
                    source_operator_id=source.id,
                    target_operator_id=target.id,
                    connection_type="enables",
                    reason=f"source target_node matches target source_node: {source.target_node}",
                    metadata={"match_method": "node"},
                )
                if not add(connection):
                    return sorted(connections.values(), key=lambda item: item.id), warnings
            for produced in source.produces:
                for required in target.requires:
                    if not _artifact_matches(produced, required):
                        continue
                    enables = AttackOperatorConnectionModel(
                        id=generate_connection_id(source.id, target.id, "enables", produced),
                        source_operator_id=source.id,
                        target_operator_id=target.id,
                        connection_type="enables",
                        reason="Produced artifact satisfies target requirement",
                        artifact=produced,
                        metadata={"match_method": "artifact"},
                    )
                    requires = AttackOperatorConnectionModel(
                        id=generate_connection_id(target.id, source.id, "requires", required),
                        source_operator_id=target.id,
                        target_operator_id=source.id,
                        connection_type="requires",
                        reason="Source operator requires artifact produced by target",
                        artifact=required,
                        metadata={"match_method": "artifact"},
                    )
                    if not add(enables) or not add(requires):
                        return sorted(connections.values(), key=lambda item: item.id), warnings
    return sorted(connections.values(), key=lambda item: item.id), warnings


def build_networkx_operator_graph(
    operators: list[AttackOperatorModel],
    connections: list[AttackOperatorConnectionModel],
) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for operator in sorted(operators, key=lambda item: item.id):
        graph.add_node(operator.id, **operator.model_dump(mode="json"))
    for connection in sorted(connections, key=lambda item: item.id):
        graph.add_edge(
            connection.source_operator_id,
            connection.target_operator_id,
            key=connection.id,
            **connection.model_dump(mode="json"),
        )
    return graph


def extract_layer3_candidates(operators: list[AttackOperatorModel], max_candidates: int) -> tuple[list[str], bool]:
    candidates = []
    for operator in sorted(operators, key=lambda item: item.id):
        has_subject = _valid_node_id(operator.target_node) or any(_valid_node_id(artifact.subject_node_id) for artifact in operator.produces + operator.requires)
        if operator.status in {"complete", "partial"} and operator.verification_status == "unverified" and has_subject:
            candidates.append(operator.id)
            if len(candidates) >= max_candidates:
                return candidates, True
    return candidates, False
