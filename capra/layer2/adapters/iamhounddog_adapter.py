from __future__ import annotations

from pathlib import Path
from typing import Any

from ..edge_classifier import classify_edge
from ..ids import generate_operator_id, generate_unresolved_id
from ..patterns.loader import DEFAULT_PATTERN_PATH, load_pattern_rules
from ..patterns.matcher import match_rule
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


class IamHoundDogAdapter:
    source_tool = "iamhounddog"

    def __init__(self, rule_path: str | Path | None = None):
        self.rule_path = Path(rule_path) if rule_path else DEFAULT_PATTERN_PATH

    def classify_edge(self, edge: dict, context: AdapterContext | None = None) -> EdgeClassification:
        return classify_edge(edge)

    def convert(self, fact_graph: FactGraphInput, config: Layer2Config) -> AdapterResult:
        rules, rule_set_version, rule_set_hash = load_pattern_rules(config.iamhounddog_rule_path or self.rule_path)
        result = AdapterResult(statistics={classification.value: 0 for classification in EdgeClassification})
        used_fact_ids: set[str] = set()
        for edge in fact_graph.edges:
            if edge.get("source_tool") == self.source_tool:
                result.statistics[self.classify_edge(edge).value] += 1
        for rule in rules:
            if rule.source_tool != self.source_tool or not rule.enabled:
                continue
            matches, warnings = match_rule(fact_graph, rule, config)
            result.warnings.extend(warnings)
            if not matches and warnings:
                result.unresolved_items.append(self._unresolved(rule.id, [], warnings[0], ["max_hops"]))
            elif not matches and any(edge.get("source_tool") == self.source_tool for edge in fact_graph.edges):
                result.unresolved_items.append(
                    self._unresolved(
                        "unresolved_pattern",
                        [],
                        f"Required edge sequence for rule {rule.id} was not found",
                        ["complete_pattern_path"],
                    )
                )
            for match in matches:
                if len(result.operators) >= config.max_total_operators:
                    result.warnings.append("IAMHoundDog operator limit reached")
                    break
                source_fact_ids = sorted({str(edge.get("fact_id")) for edge in match.edges + match.permission_edges})
                used_fact_ids.update(source_fact_ids)
                source_node = match.bindings.get("source_principal")
                target_node = match.bindings.get("target_role")
                missing = sorted(match.missing_permissions)
                artifacts = self._artifacts(rule.operator.produces, match.bindings)
                requires = self._artifacts(rule.operator.requires, match.bindings)
                operator_id = generate_operator_id(
                    operator_type=rule.operator.type,
                    origin_kind="iam_pattern",
                    source_node=source_node,
                    target_node=target_node,
                    source_fact_ids=source_fact_ids,
                    mapping_rule_id=rule.id,
                    provider="aws",
                )
                result.operators.append(
                    AttackOperatorModel(
                        id=operator_id,
                        operator_type=rule.operator.type,
                        origin_kind="iam_pattern",
                        source_tool=self.source_tool,
                        source_fact_ids=source_fact_ids,
                        source_files=sorted({str(edge.get("source_file")) for edge in match.edges + match.permission_edges if edge.get("source_file")}),
                        source_node=source_node,
                        target_node=target_node,
                        preconditions=rule.operator.preconditions,
                        effects=rule.operator.effects,
                        produces=artifacts,
                        requires=requires,
                        status="partial" if missing else "complete",
                        missing_conditions=missing,
                        mapping_rule_id=rule.id,
                        raw_evidence={"matched_edges": match.edges, "permission_edges": match.permission_edges},
                        metadata={"rule_version": rule.version, "rule_set_version": rule_set_version, "rule_set_hash": rule_set_hash},
                    )
                )
        for edge in fact_graph.edges:
            if edge.get("source_tool") != self.source_tool or str(edge.get("fact_id")) in used_fact_ids:
                continue
            if self.classify_edge(edge) == EdgeClassification.UNKNOWN:
                result.unresolved_items.append(self._unresolved("unknown_edge", [str(edge.get("fact_id"))], "Unknown IAMHoundDog edge", [], edge))
        return result

    @staticmethod
    def _artifacts(items: list[dict[str, Any]], bindings: dict[str, str]) -> list[OperatorArtifactModel]:
        return [
            OperatorArtifactModel(
                artifact_type=item["artifact_type"],
                subject_node_id=bindings.get(str(item.get("subject_node_ref") or "")) or item.get("subject_node_id"),
                properties=item.get("properties") or {},
            )
            for item in items
        ]

    def _unresolved(
        self,
        item_type: str,
        fact_ids: list[str],
        reason: str,
        missing: list[str],
        raw: dict[str, Any] | None = None,
    ) -> UnresolvedItemModel:
        return UnresolvedItemModel(
            id=generate_unresolved_id(item_type=item_type, source_tool=self.source_tool, source_fact_ids=fact_ids, reason=reason, missing_conditions=missing),
            type=item_type,
            source_tool=self.source_tool,
            source_fact_ids=fact_ids,
            missing_conditions=missing,
            reason=reason,
            raw_evidence=raw or {},
        )
