from __future__ import annotations

import logging
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .adapters.azurehound_adapter import AzureHoundAdapter
from .adapters.clusterhound_adapter import ClusterHoundAdapter
from .adapters.gcp_hound_adapter import GcpHoundAdapter
from .adapters.iamhounddog_adapter import IamHoundDogAdapter
from .edge_classifier import classify_edge
from .fact_graph_loader import load_fact_graph
from .ids import generate_unresolved_id
from .nvd_adapter import convert_cves
from .operator_graph_builder import build_operator_connections, extract_layer3_candidates
from .redaction import redact_sensitive_data
from .schemas import AttackOperatorGraphModel, AttackOperatorModel, Layer2Config, UnresolvedItemModel

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
    adapters = [AzureHoundAdapter(), GcpHoundAdapter(), ClusterHoundAdapter(), IamHoundDogAdapter()]
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

    nvd_statistics = {"cache_hit": 0, "cache_miss": 0, "fetch_failure": 0}
    has_vulnerabilities = bool(normalized.unmapped_vulnerabilities) or any(node.get("vulnerabilities") for node in normalized.nodes)
    if has_vulnerabilities and (not selected_tools or selected_tools & {"nvd", "grype"}):
        try:
            processed_tools.add("nvd")
            nvd_result = convert_cves(normalized, layer2_config, client=nvd_client)
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
        "used_source_tools": sorted(processed_tools),
        "used_rule_ids": used_rule_ids,
        "rule_set_hashes": rule_set_hashes,
        "nvd_cache_entries": nvd_entries,
        "nvd_cache_hashes": nvd_cache_hashes,
        "fact_node_count": len(normalized.nodes),
        "fact_edge_count": len(normalized.edges),
        "operator_count": len(operators),
        "iam_operator_count": iam_count,
        "cve_operator_count": cve_count,
        "connection_count": len(connections),
        "unresolved_count": len(unresolved),
        "manual_verification_count": sum(operator.manual_verification_required for operator in operators),
        "processing_time_ms": elapsed_ms,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "execution_config": redact_sensitive_data(layer2_config.model_dump(mode="json")),
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
