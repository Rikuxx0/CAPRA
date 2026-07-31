from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from ..edge_classifier import normalize_edge_key
from ..ids import generate_operator_id, generate_unresolved_id, stable_hash
from ..schemas import (
    AdapterContext,
    AdapterResult,
    AttackOperatorModel,
    EdgeClassification,
    FactGraphInput,
    Layer2Config,
    OperatorArtifactModel,
    UnresolvedItemModel,
)


class DirectEdgeAdapter:
    source_tool = "unknown"
    rule_path: Path

    def __init__(
        self,
        rule_path: str | Path | None = None,
        *,
        rule_paths: Sequence[str | Path] | None = None,
    ):
        default_rule_path = self.rule_path
        if rule_paths:
            self.rule_paths = [default_rule_path, *(Path(path) for path in rule_paths)]
        elif rule_path:
            # Preserve the previous single-file replacement behavior for API callers.
            self.rule_paths = [Path(rule_path)]
        else:
            self.rule_paths = [default_rule_path]
        self.rule_path = self.rule_paths[0]
        self.mappings: dict[str, dict[str, Any]] = {}
        payloads: list[dict[str, Any]] = []
        versions: set[str] = set()
        mapping_sources: dict[str, Path] = {}
        rule_id_sources: dict[str, Path] = {}

        for current_path in self.rule_paths:
            raw = current_path.read_text(encoding="utf-8")
            payload = yaml.safe_load(raw) or {}
            if not isinstance(payload, dict):
                raise ValueError(f"Edge mapping YAML must be an object: {current_path}")
            mappings = payload.get("mappings") or {}
            if not isinstance(mappings, dict):
                raise ValueError(f"Invalid mappings in {current_path}")
            payloads.append(payload)
            versions.add(str(payload.get("version") or "unknown"))
            for edge_type, mapping in mappings.items():
                normalized_edge_type = normalize_edge_key(edge_type)
                if normalized_edge_type in mapping_sources:
                    raise ValueError(
                        f"Duplicate {self.source_tool} edge mapping {edge_type!r} in "
                        f"{mapping_sources[normalized_edge_type]} and {current_path}"
                    )
                if not isinstance(mapping, dict):
                    raise ValueError(f"Invalid mapping for {edge_type!r} in {current_path}")
                rule_id = str(mapping.get("rule_id") or "").strip()
                if rule_id and rule_id in rule_id_sources:
                    raise ValueError(
                        f"Duplicate {self.source_tool} rule id {rule_id!r} in "
                        f"{rule_id_sources[rule_id]} and {current_path}"
                    )
                mapping_sources[normalized_edge_type] = current_path
                if rule_id:
                    rule_id_sources[rule_id] = current_path
                self.mappings[normalized_edge_type] = mapping

        self.rule_version = ",".join(sorted(versions))
        self.rule_hash = stable_hash(sorted(payloads, key=stable_hash))

    def classify_edge(self, edge: dict, context: AdapterContext | None = None) -> EdgeClassification:
        mapping = self._mapping_for(edge)
        if not mapping:
            return EdgeClassification.UNKNOWN
        return EdgeClassification(str(mapping.get("classification") or "UNKNOWN").upper())

    def convert(self, fact_graph: FactGraphInput, config: Layer2Config) -> AdapterResult:
        result = AdapterResult(statistics={classification.value: 0 for classification in EdgeClassification})
        nodes_by_id = {
            str(node.get("id")): node
            for node in fact_graph.nodes
            if node.get("id")
        }
        for edge in sorted(fact_graph.edges, key=lambda item: str(item.get("fact_id") or "")):
            if edge.get("source_tool") != self.source_tool:
                continue
            fact_id = str(edge.get("fact_id") or "unknown-fact")
            mapping = self._mapping_for(edge)
            classification = self.classify_edge(edge)
            result.statistics[classification.value] += 1
            if not mapping:
                result.unresolved_items.append(self._unresolved(edge, "No mapping exists for this source-tool edge", "unknown_edge"))
                continue
            if classification != EdgeClassification.ATTACK_EDGE:
                continue
            operator_type = str(mapping.get("operator_type") or "").strip().lower()
            if not operator_type:
                result.unresolved_items.append(self._unresolved(edge, "ATTACK_EDGE mapping has no operator_type", "invalid_mapping"))
                continue
            missing = [str(item) for item in mapping.get("missing_conditions", []) or []]
            status = "partial" if missing else "complete"
            provider = self._provider_for_edge(edge, nodes_by_id)
            mapping_rule_id = str(mapping.get("rule_id") or f"{self.source_tool}.{normalize_edge_key(edge.get('original_edge_type'))}.v1")
            operator_id = generate_operator_id(
                operator_type=operator_type,
                origin_kind="iam_direct_edge",
                source_node=edge.get("source"),
                target_node=edge.get("target"),
                source_fact_ids=[fact_id],
                mapping_rule_id=mapping_rule_id,
                provider=provider,
            )
            result.operators.append(
                AttackOperatorModel(
                    id=operator_id,
                    operator_type=operator_type,
                    origin_kind="iam_direct_edge",
                    source_tool=self.source_tool,
                    source_fact_ids=[fact_id],
                    source_files=[str(edge["source_file"])] if edge.get("source_file") else [],
                    source_node=edge.get("source"),
                    target_node=edge.get("target"),
                    preconditions=[str(item) for item in mapping.get("preconditions", []) or []],
                    effects=[str(item) for item in mapping.get("effects", []) or []],
                    produces=self._artifacts(mapping.get("produces"), edge.get("target")),
                    requires=self._artifacts(mapping.get("requires"), edge.get("source")),
                    status=status,
                    missing_conditions=missing,
                    manual_verification_required=bool(mapping.get("manual_verification_required", False)),
                    mapping_rule_id=mapping_rule_id,
                    raw_evidence=edge,
                    metadata={
                        "provider": provider,
                        "original_edge_type": edge.get("original_edge_type"),
                        "rule_set_version": self.rule_version,
                        "rule_set_hash": self.rule_hash,
                    },
                )
            )
        return result

    def _mapping_for(self, edge: dict[str, Any]) -> dict[str, Any] | None:
        return self.mappings.get(normalize_edge_key(edge.get("original_edge_type") or edge.get("type")))

    @staticmethod
    def _provider_for_edge(
        edge: dict[str, Any],
        nodes_by_id: dict[str, dict[str, Any]],
    ) -> str:
        explicit = str(edge.get("provider") or "").strip().lower()
        if explicit and explicit != "unknown":
            return explicit
        node_clouds = {
            str((nodes_by_id.get(str(node_id)) or {}).get("cloud") or "").strip().lower()
            for node_id in (edge.get("source"), edge.get("target"))
        }
        node_clouds.discard("")
        node_clouds.discard("unknown")
        if len(node_clouds) == 1:
            return next(iter(node_clouds))
        if len(node_clouds) > 1:
            return "hybrid"
        return "unknown"

    @staticmethod
    def _artifacts(items: Any, default_subject: str | None) -> list[OperatorArtifactModel]:
        artifacts: list[OperatorArtifactModel] = []
        for item in items or []:
            if isinstance(item, str):
                artifacts.append(OperatorArtifactModel(artifact_type=item, subject_node_id=default_subject))
            elif isinstance(item, dict):
                subject = item.get("subject_node_id")
                if subject == "$target" or subject is None:
                    subject = default_subject
                artifacts.append(
                    OperatorArtifactModel(
                        artifact_type=item["artifact_type"],
                        subject_node_id=subject,
                        properties=item.get("properties") or {},
                    )
                )
        return artifacts

    def _unresolved(self, edge: dict[str, Any], reason: str, item_type: str) -> UnresolvedItemModel:
        fact_id = str(edge.get("fact_id") or "unknown-fact")
        return UnresolvedItemModel(
            id=generate_unresolved_id(item_type=item_type, source_tool=self.source_tool, source_fact_ids=[fact_id], reason=reason),
            type=item_type,
            source_tool=self.source_tool,
            source_fact_ids=[fact_id],
            reason=reason,
            raw_evidence=edge,
            metadata={"original_edge_type": edge.get("original_edge_type")},
        )
