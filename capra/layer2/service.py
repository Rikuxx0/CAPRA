from __future__ import annotations

import logging
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .adapters.azurehound_adapter import AzureHoundAdapter
from .adapters.clusterhound_adapter import ClusterHoundAdapter
from .adapters.gcp_hound_adapter import GcpHoundAdapter
from .adapters.hound_generic_adapter import HoundGenericAdapter
from .adapters.iamhounddog_adapter import IamHoundDogAdapter
from .edge_classifier import classify_edge
from .fact_graph_loader import load_fact_graph
from .ids import generate_unresolved_id
from .nvd_adapter import DEFAULT_RULE_PATH as DEFAULT_CVE_RULE_PATH
from .nvd_adapter import convert_cves
from .operator_graph_builder import build_operator_connections, extract_layer3_candidates
from .redaction import redact_sensitive_data
from .schemas import (
    AttackOperatorGraphModel,
    AttackOperatorModel,
    EdgeClassification,
    FactGraphInput,
    Layer2Config,
    UnresolvedItemModel,
)

LOGGER = logging.getLogger(__name__)
SCHEMA_VERSION = "0.1.0"


def _failure_unresolved(source_tool: str, reason: str) -> UnresolvedItemModel:
    return UnresolvedItemModel(
        id=generate_unresolved_id(item_type="adapter_failure", source_tool=source_tool, source_fact_ids=[], reason=reason),
        type="adapter_failure",
        source_tool=source_tool,
        reason=reason,
        raw_evidence={},
    )


def _deduplicate_operators(operators: list[AttackOperatorModel]) -> list[AttackOperatorModel]:
    return sorted({operator.id: operator for operator in operators}.values(), key=lambda item: item.id)


def _unprocessed_edge_items(
    fact_graph: FactGraphInput,
    adapter_tools: set[str],
    selected_tools: set[str],
) -> list[UnresolvedItemModel]:
    """Preserve non-relationship edges for which Layer 2 has no source adapter."""
    items: list[UnresolvedItemModel] = []
    for edge in sorted(fact_graph.edges, key=lambda item: str(item.get("fact_id") or "")):
        source_tool = str(edge.get("source_tool") or "unknown")
        if source_tool in adapter_tools or source_tool == "unknown":
            continue
        if selected_tools and source_tool not in selected_tools:
            continue
        classification = classify_edge(edge)
        if classification == EdgeClassification.RELATIONSHIP:
            continue
        fact_id = str(edge.get("fact_id") or "unknown-fact")
        unsupported = source_tool == "bloodhound_kube"
        item_type = "unsupported_source_tool" if unsupported else "unknown_edge"
        missing = ["source_specific_adapter"] if unsupported else ["mapping_rule"]
        reason = (
            f"No Layer 2 source-specific adapter is available for {source_tool}"
            if unsupported
            else f"No Layer 2 mapping exists for {source_tool} edge"
        )
        items.append(
            UnresolvedItemModel(
                id=generate_unresolved_id(
                    item_type=item_type,
                    source_tool=source_tool,
                    source_fact_ids=[fact_id],
                    reason=reason,
                    missing_conditions=missing,
                ),
                type=item_type,
                source_tool=source_tool,
                source_fact_ids=[fact_id],
                missing_conditions=missing,
                reason=reason,
                raw_evidence=edge,
                metadata={
                    "classification": classification.value,
                    "original_edge_type": edge.get("original_edge_type"),
                },
            )
        )
    return items


def _execution_config(config: Layer2Config) -> dict[str, Any]:
    payload = config.model_dump(mode="json")
    # Uploaded rule temp paths are runtime-specific. Rule versions and hashes
    # below capture the effective rule content deterministically.
    for key in list(payload):
        if key.endswith("_rule_paths") or key in {
            "iamhounddog_rule_path",
            "nvd_cache_directory",
        }:
            payload.pop(key, None)
    return redact_sensitive_data(payload)


def build_attack_operator_graph(
    fact_graph: dict[str, Any],
    config: Layer2Config | dict[str, Any] | None = None,
    *,
    nvd_client: Any | None = None,
) -> AttackOperatorGraphModel:
    started = time.perf_counter()
    layer2_config = config if isinstance(config, Layer2Config) else Layer2Config.model_validate(config or {})
    normalized, unresolved, warnings = load_fact_graph(fact_graph)
    selected_tools = {item.strip().lower() for item in layer2_config.selected_source_tools if item.strip()}
    source_counts = Counter(str(edge.get("source_tool") or "unknown") for edge in normalized.edges)
    operators: list[AttackOperatorModel] = []
    adapter_results = []
    adapters = [
        HoundGenericAdapter(rule_paths=layer2_config.hound_generic_rule_paths),
        AzureHoundAdapter(rule_paths=layer2_config.azurehound_rule_paths),
        GcpHoundAdapter(rule_paths=layer2_config.gcp_hound_rule_paths),
        ClusterHoundAdapter(rule_paths=layer2_config.clusterhound_rule_paths),
        IamHoundDogAdapter(),
    ]
    adapters_by_tool = {adapter.source_tool: adapter for adapter in adapters}
    classification_counts = Counter(
        (
            adapters_by_tool[str(edge.get("source_tool"))].classify_edge(edge).value
            if str(edge.get("source_tool")) in adapters_by_tool
            else classify_edge(edge).value
        )
        for edge in normalized.edges
    )
    processed_tools: set[str] = set()
    for adapter in adapters:
        if selected_tools and adapter.source_tool not in selected_tools:
            continue
        if not any(edge.get("source_tool") == adapter.source_tool for edge in normalized.edges):
            continue
        try:
            processed_tools.add(adapter.source_tool)
            result = adapter.convert(normalized, layer2_config)
            adapter_results.append(result)
            operators.extend(result.operators)
            unresolved.extend(result.unresolved_items)
            warnings.extend(result.warnings)
        except Exception as exc:
            LOGGER.warning("Layer 2 adapter %s failed: %s", adapter.source_tool, type(exc).__name__)
            warnings.append(f"Adapter {adapter.source_tool} failed: {type(exc).__name__}")
            unresolved.append(_failure_unresolved(adapter.source_tool, f"Adapter failed: {type(exc).__name__}"))

    unresolved.extend(
        _unprocessed_edge_items(
            normalized,
            set(adapters_by_tool),
            selected_tools,
        )
    )

    nvd_statistics = {"cache_hit": 0, "cache_miss": 0, "fetch_failure": 0}
    has_vulnerabilities = bool(normalized.unmapped_vulnerabilities) or any(node.get("vulnerabilities") for node in normalized.nodes)
    if has_vulnerabilities and (not selected_tools or selected_tools & {"nvd", "grype"}):
        try:
            processed_tools.add("nvd")
            cve_rule_paths = [DEFAULT_CVE_RULE_PATH, *layer2_config.cve_operator_rule_paths]
            nvd_result = convert_cves(
                normalized,
                layer2_config,
                client=nvd_client,
                rule_path=cve_rule_paths,
            )
            adapter_results.append(nvd_result)
            operators.extend(nvd_result.operators)
            unresolved.extend(nvd_result.unresolved_items)
            warnings.extend(nvd_result.warnings)
            nvd_statistics.update(nvd_result.statistics)
        except Exception as exc:
            LOGGER.warning("Layer 2 NVD conversion failed: %s", type(exc).__name__)
            warnings.append(f"NVD conversion failed: {type(exc).__name__}")
            unresolved.append(_failure_unresolved("nvd", f"NVD conversion failed: {type(exc).__name__}"))

    operators = _deduplicate_operators(operators)
    if layer2_config.selected_operator_types:
        selected_types = {item.strip().lower() for item in layer2_config.selected_operator_types if item.strip()}
        operators = [operator for operator in operators if operator.operator_type.lower() in selected_types]
    limit_reached: dict[str, int] = {}
    if len(operators) > layer2_config.max_total_operators:
        dropped_operators = operators[layer2_config.max_total_operators :]
        limit_reached["max_total_operators"] = len(dropped_operators)
        operators = operators[: layer2_config.max_total_operators]
        warnings.append("Global operator limit reached")
        dropped_fact_ids = sorted({fact_id for operator in dropped_operators for fact_id in operator.source_fact_ids})
        reason = "Global operator limit reached before all modeled operators could be retained"
        unresolved.append(
            UnresolvedItemModel(
                id=generate_unresolved_id(
                    item_type="limit_reached",
                    source_tool="layer2",
                    source_fact_ids=dropped_fact_ids,
                    reason=reason,
                    missing_conditions=["max_total_operators"],
                ),
                type="limit_reached",
                source_tool="layer2",
                source_fact_ids=dropped_fact_ids,
                missing_conditions=["max_total_operators"],
                reason=reason,
                raw_evidence={},
                metadata={"dropped_operator_count": len(dropped_operators)},
            )
        )
    connections, connection_warnings = build_operator_connections(operators, layer2_config.max_connections)
    warnings.extend(connection_warnings)
    if connection_warnings:
        limit_reached["max_connections"] = 1
    candidates, candidates_limited = extract_layer3_candidates(operators, layer2_config.max_candidates)
    if candidates_limited and sum(1 for operator in operators if operator.status in {"complete", "partial"}) > len(candidates):
        limit_reached["max_candidates"] = 1
        warnings.append("Layer 3 candidate limit reached")

    unresolved = sorted({item.id: item for item in unresolved}.values(), key=lambda item: item.id)
    used_rule_ids = sorted({operator.mapping_rule_id for operator in operators if operator.mapping_rule_id})
    rule_versions = sorted({str(operator.metadata.get("rule_set_version") or operator.metadata.get("rule_version")) for operator in operators if operator.metadata.get("rule_set_version") or operator.metadata.get("rule_version")})
    nvd_entries = sorted({cve for operator in operators if operator.origin_kind == "cve" for cve in operator.cve_ids})
    rule_set_hashes = sorted({str(operator.metadata.get("rule_set_hash")) for operator in operators if operator.metadata.get("rule_set_hash")})
    nvd_cache_hashes = sorted({str(operator.metadata.get("nvd_cache_hash")) for operator in operators if operator.metadata.get("nvd_cache_hash")})
    iam_count = sum(operator.origin_kind != "cve" for operator in operators)
    cve_count = sum(operator.origin_kind == "cve" for operator in operators)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    metadata = {
        "layer2_schema_version": SCHEMA_VERSION,
        "input_fact_graph_schema_version": str(normalized.metadata.get("schema_version") or normalized.metadata.get("schema_status") or "unknown"),
        "input_fact_graph_hash": normalized.input_hash,
        "rule_set_version": ",".join(rule_versions) if rule_versions else "unknown",
        "rule_versions": rule_versions,
        "used_source_tools": sorted(processed_tools),
        "used_rule_ids": used_rule_ids,
        "rule_set_hashes": rule_set_hashes,
        "rule_hashes": rule_set_hashes,
        "nvd_cache_entries": nvd_entries,
        "nvd_cache_entry_count": len(nvd_entries),
        "nvd_cache_hashes": nvd_cache_hashes,
        "fact_node_count": len(normalized.nodes),
        "fact_edge_count": len(normalized.edges),
        "operator_count": len(operators),
        "complete_operator_count": sum(operator.status == "complete" for operator in operators),
        "partial_operator_count": sum(operator.status == "partial" for operator in operators),
        "unresolved_operator_count": sum(operator.status == "unresolved" for operator in operators),
        "iam_operator_count": iam_count,
        "cve_operator_count": cve_count,
        "connection_count": len(connections),
        "layer3_candidate_count": len(candidates),
        "unresolved_count": len(unresolved),
        "manual_verification_count": sum(operator.manual_verification_required for operator in operators),
        "processing_time_ms": elapsed_ms,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "execution_config": _execution_config(layer2_config),
        "source_tool_edge_counts": dict(sorted(source_counts.items())),
        "edge_classification_counts": dict(sorted(classification_counts.items())),
        "nvd_cache_hit_count": nvd_statistics.get("cache_hit", 0),
        "nvd_cache_miss_count": nvd_statistics.get("cache_miss", 0),
        "nvd_fetch_failure_count": nvd_statistics.get("fetch_failure", 0),
        "warnings": sorted(set(warnings)),
        "limit_reached": limit_reached,
    }
    LOGGER.info(
        "Layer 2 processed nodes=%s edges=%s operators=%s iam=%s cve=%s connections=%s unresolved=%s cache_hit=%s cache_miss=%s fetch_failure=%s elapsed_ms=%s",
        len(normalized.nodes), len(normalized.edges), len(operators), iam_count, cve_count, len(connections), len(unresolved),
        nvd_statistics.get("cache_hit", 0), nvd_statistics.get("cache_miss", 0), nvd_statistics.get("fetch_failure", 0), elapsed_ms,
    )
    LOGGER.info(
        "Layer 2 source_tool_edges=%s classifications=%s limits=%s manual_verification=%s",
        dict(sorted(source_counts.items())),
        dict(sorted(classification_counts.items())),
        limit_reached,
        sum(operator.manual_verification_required for operator in operators),
    )
    return AttackOperatorGraphModel(
        schema_version=SCHEMA_VERSION,
        attack_operators=operators,
        connections=connections,
        unresolved_items=unresolved,
        layer3_candidates=sorted(candidates),
        metadata=metadata,
    )
