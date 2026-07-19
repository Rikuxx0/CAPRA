from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..edge_classifier import normalize_edge_key
from ..schemas import FactGraphInput, Layer2Config
from .models import PatternRuleModel


@dataclass
class PatternMatch:
    bindings: dict[str, str]
    edges: list[dict[str, Any]]
    permission_edges: list[dict[str, Any]] = field(default_factory=list)
    missing_permissions: list[str] = field(default_factory=list)


def _node_type(node: dict[str, Any] | None) -> str:
    return normalize_edge_key((node or {}).get("type") or "unknown")


def _edge_type(edge: dict[str, Any]) -> str:
    return normalize_edge_key(edge.get("type") or edge.get("original_edge_type"))


def match_rule(fact_graph: FactGraphInput, rule: PatternRuleModel, config: Layer2Config) -> tuple[list[PatternMatch], list[str]]:
    warnings: list[str] = []
    if not rule.enabled:
        return [], warnings
    effective_hops = min(rule.max_hops, config.max_hops)
    if len(rule.pattern) > effective_hops:
        return [], [f"Rule {rule.id} exceeds max_hops={effective_hops}"]
    nodes = {str(node.get("id")): node for node in fact_graph.nodes}
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in fact_graph.edges:
        if edge.get("source_tool") == rule.source_tool:
            adjacency.setdefault(str(edge.get("source")), []).append(edge)
    for values in adjacency.values():
        values.sort(key=lambda edge: (str(edge.get("target")), str(edge.get("fact_id"))))
    matches: list[PatternMatch] = []

    def walk(step_index: int, current_node: str, bindings: dict[str, str], path: list[dict[str, Any]]) -> None:
        if len(matches) >= config.max_matches_per_rule:
            return
        if step_index == len(rule.pattern):
            permission_edges, missing = _find_permissions(fact_graph, rule.required_permissions, bindings, path)
            matches.append(PatternMatch(dict(bindings), list(path), permission_edges, missing))
            return
        step = rule.pattern[step_index]
        if _node_type(nodes.get(current_node)) != normalize_edge_key(step.from_type):
            return
        for edge in adjacency.get(current_node, []):
            target = str(edge.get("target"))
            if _edge_type(edge) != normalize_edge_key(step.edge_type):
                continue
            if _node_type(nodes.get(target)) != normalize_edge_key(step.to_type):
                continue
            next_bindings = dict(bindings)
            if step.bind_from_as:
                existing = next_bindings.get(step.bind_from_as)
                if existing and existing != current_node:
                    continue
                next_bindings[step.bind_from_as] = current_node
            if step.bind_to_as:
                existing = next_bindings.get(step.bind_to_as)
                if existing and existing != target:
                    continue
                next_bindings[step.bind_to_as] = target
            walk(step_index + 1, target, next_bindings, path + [edge])

    if rule.pattern:
        first_type = normalize_edge_key(rule.pattern[0].from_type)
        for node_id in sorted(nodes):
            if _node_type(nodes[node_id]) == first_type:
                walk(0, node_id, {}, [])
                if len(matches) >= config.max_matches_per_rule:
                    warnings.append(f"Rule {rule.id} reached max_matches_per_rule={config.max_matches_per_rule}")
                    break
    return matches, warnings


def _find_permissions(
    fact_graph: FactGraphInput,
    required: list[str],
    bindings: dict[str, str],
    path: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    allowed_sources = {str(edge.get("source")) for edge in path} | set(bindings.values())
    target_role = bindings.get("target_role")
    found_edges: list[dict[str, Any]] = []
    missing: list[str] = []
    for required_permission in required:
        normalized = required_permission.strip().lower()
        candidates = []
        for edge in fact_graph.edges:
            permission = str(edge.get("permission") or "").strip().lower()
            if permission != normalized:
                continue
            if str(edge.get("source")) not in allowed_sources:
                continue
            if normalized == "iam:passrole" and target_role and str(edge.get("target")) != target_role:
                continue
            candidates.append(edge)
        if candidates:
            found_edges.append(sorted(candidates, key=lambda edge: str(edge.get("fact_id")))[0])
        else:
            missing.append(required_permission)
    return found_edges, missing
