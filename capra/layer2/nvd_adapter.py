from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from .ids import generate_operator_id, generate_unresolved_id, stable_hash
from .nvd.cache import NvdCache, normalize_cve_id
from .nvd.client import NvdClient
from .nvd.parser import parse_nvd_response
from .redaction import redact_sensitive_data
from .schemas import AdapterResult, AttackOperatorModel, FactGraphInput, Layer2Config, OperatorArtifactModel, UnresolvedItemModel

LOGGER = logging.getLogger(__name__)
DEFAULT_RULE_PATH = Path(__file__).parent / "rules" / "cve_operator_rules.yaml"


def load_cve_rules(path: str | Path = DEFAULT_RULE_PATH) -> tuple[list[dict[str, str]], str, str]:
    raw = Path(path).read_text(encoding="utf-8")
    payload = yaml.safe_load(raw) or {}
    rules = payload.get("rules") or []
    if not all(isinstance(rule, dict) and rule.get("id") and rule.get("phrase") and rule.get("operator_type") for rule in rules):
        raise ValueError("Invalid CVE operator rule file")
    ordered = sorted(rules, key=lambda rule: (-len(str(rule["phrase"])), str(rule["id"])))
    return ordered, str(payload.get("version") or "unknown"), stable_hash(payload)


def classify_description(description: str, rules: list[dict[str, str]]) -> tuple[str, str | None]:
    text = str(description or "").lower()
    for rule in rules:
        if str(rule["phrase"]).lower() in text:
            return str(rule["operator_type"]).strip().lower(), str(rule["id"])
    return "exploit_vulnerable_component", None


def _unresolved(cve_id: str, fact_id: str, reason: str, item_type: str, raw: dict[str, Any]) -> UnresolvedItemModel:
    missing = ["nvd_record"] if item_type.startswith("nvd_") else []
    return UnresolvedItemModel(
        id=generate_unresolved_id(item_type=item_type, source_tool="nvd", source_fact_ids=[fact_id], reason=reason, missing_conditions=missing),
        type=item_type,
        source_tool="nvd",
        source_fact_ids=[fact_id],
        missing_conditions=missing,
        reason=reason,
        raw_evidence=redact_sensitive_data(raw),
        metadata={"cve_id": cve_id},
    )


def convert_cves(
    fact_graph: FactGraphInput,
    config: Layer2Config,
    *,
    client: NvdClient | None = None,
    rule_path: str | Path = DEFAULT_RULE_PATH,
) -> AdapterResult:
    rules, rule_version, rule_hash = load_cve_rules(rule_path)
    cache = NvdCache(config.nvd_cache_directory, config.nvd_cache_ttl_seconds)
    nvd_client = client or NvdClient(
        timeout_seconds=config.nvd_timeout_seconds,
        max_retries=config.nvd_max_retries,
        rate_limit_seconds=config.nvd_rate_limit_seconds,
    )
    result = AdapterResult(statistics={"cache_hit": 0, "cache_miss": 0, "fetch_failure": 0})
    node_by_id = {str(node.get("id")): node for node in fact_graph.nodes}
    work: list[tuple[dict[str, Any], str | None]] = []
    for node in fact_graph.nodes:
        for vulnerability in node.get("vulnerabilities", []) or []:
            if isinstance(vulnerability, dict):
                work.append((vulnerability, str(node.get("id"))))
    for vulnerability in fact_graph.unmapped_vulnerabilities:
        work.append((vulnerability, None))

    seen: set[tuple[str, str | None, str]] = set()
    for vulnerability, target_node in sorted(work, key=lambda item: (str(item[0].get("cve_id") or item[0].get("id") or ""), str(item[1] or ""))):
        raw_cve = vulnerability.get("cve_id") or vulnerability.get("id")
        fact_id = str(vulnerability.get("fact_id") or vulnerability.get("id") or raw_cve or "unknown-vulnerability")
        try:
            cve_id = normalize_cve_id(str(raw_cve or ""))
        except ValueError:
            result.unresolved_items.append(_unresolved(str(raw_cve or "unknown"), fact_id, "Vulnerability does not contain a valid CVE ID", "invalid_cve_id", vulnerability))
            continue
        key = (cve_id, target_node, fact_id)
        if key in seen:
            continue
        seen.add(key)
        cache_result = cache.read(cve_id)
        payload = cache_result.response
        if payload is not None:
            result.statistics["cache_hit"] += 1
        else:
            result.statistics["cache_miss"] += 1
            if cache_result.warning:
                result.warnings.append(cache_result.warning)
            if cache_result.status == "corrupt":
                result.unresolved_items.append(_unresolved(cve_id, fact_id, cache_result.warning or "Corrupt NVD cache", "corrupt_nvd_cache", vulnerability))
            if config.nvd_mode == "cache-then-fetch":
                try:
                    payload = nvd_client.fetch(cve_id)
                    cache.write(cve_id, payload)
                    cache_result = cache.read(cve_id)
                except Exception:
                    LOGGER.warning("NVD fetch failed for %s", cve_id)
                    result.statistics["fetch_failure"] += 1
            if payload is None:
                result.unresolved_items.append(_unresolved(cve_id, fact_id, f"NVD record unavailable in {config.nvd_mode} mode", "nvd_fetch_failure", vulnerability))
                continue
        try:
            record = parse_nvd_response(payload, cve_id)
        except ValueError as exc:
            result.unresolved_items.append(_unresolved(cve_id, fact_id, str(exc), "nvd_parse_failure", vulnerability))
            continue
        operator_type, rule_id = classify_description(record.description, rules)
        missing_conditions = ["target_is_reachable"]
        if not vulnerability.get("installed_version"):
            missing_conditions.append("vulnerable_version_is_running")
        if not target_node:
            missing_conditions.append("target_node")
        status = "unresolved" if not target_node else "partial"
        provider = str((node_by_id.get(target_node or "") or {}).get("cloud") or "unknown")
        operator_id = generate_operator_id(
            operator_type=operator_type,
            origin_kind="cve",
            source_node=None,
            target_node=target_node,
            source_fact_ids=[fact_id],
            mapping_rule_id=rule_id,
            provider=provider,
        )
        metadata = {
            "cvss_score": record.cvss_score,
            "cvss_vector": record.cvss_vector,
            "attack_vector": record.attack_vector,
            "attack_complexity": record.attack_complexity,
            "privileges_required": record.privileges_required,
            "user_interaction": record.user_interaction,
            "scope": record.scope,
            "confidentiality_impact": record.confidentiality_impact,
            "integrity_impact": record.integrity_impact,
            "availability_impact": record.availability_impact,
            "products": record.products,
            "versions": record.versions,
            "references": [reference.model_dump(mode="json") for reference in record.references],
            "nvd_cache_hash": cache_result.cache_hash,
            "rule_set_version": rule_version,
            "rule_set_hash": rule_hash,
        }
        result.operators.append(
            AttackOperatorModel(
                id=operator_id,
                operator_type=operator_type,
                origin_kind="cve",
                source_tool="nvd",
                source_fact_ids=[fact_id],
                source_files=[str(vulnerability["source_file"])] if vulnerability.get("source_file") else [],
                target_node=target_node,
                preconditions=["vulnerable_version_is_running", "target_is_reachable"],
                effects=["vulnerability_exploitation_effect"],
                requires=[OperatorArtifactModel(artifact_type="network_reachability", subject_node_id=target_node)] if target_node else [],
                cve_ids=[cve_id],
                cwe_ids=record.cwe_ids,
                status=status,
                missing_conditions=sorted(set(missing_conditions)),
                manual_verification_required=record.public_exploit_candidate,
                public_exploit_candidate=record.public_exploit_candidate,
                mapping_rule_id=rule_id,
                raw_evidence=redact_sensitive_data({"vulnerability": vulnerability, "nvd": record.raw}),
                metadata=metadata,
            )
        )
    return result
