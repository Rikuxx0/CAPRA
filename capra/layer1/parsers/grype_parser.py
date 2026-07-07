from __future__ import annotations

import re
from typing import Any

from ..schemas import VulnerabilityModel
from ..utils.ids import generate_vulnerability_id

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


# Grype は id 以外の aliases / relatedVulnerabilities 側に CVE を持つことがある。
def _extract_cve_id(value: Any) -> str | None:
    if isinstance(value, str):
        match = CVE_PATTERN.search(value)
        return match.group(0).upper() if match else None
    if isinstance(value, dict):
        for item in value.values():
            cve_id = _extract_cve_id(item)
            if cve_id:
                return cve_id
    if isinstance(value, list):
        for item in value:
            cve_id = _extract_cve_id(item)
            if cve_id:
                return cve_id
    return None


# Grype の通常 JSON から脆弱性一覧を抽出してスキーマ化する。
def parse_grype_json(data: dict[str, Any]) -> list[VulnerabilityModel]:
    vulnerabilities: list[VulnerabilityModel] = []
    for index, match in enumerate(data.get("matches", []) or []):
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vuln_id = str(vuln.get("id") or generate_vulnerability_id("grype-json", index))
        fix = vuln.get("fix") or {}
        versions = fix.get("versions") or []
        fixed_version = str(versions[0]) if versions else None
        cve_id = _extract_cve_id(vuln_id) or _extract_cve_id(match)

        vulnerabilities.append(
            VulnerabilityModel(
                id=vuln_id,
                cve_id=cve_id,
                package_name=artifact.get("name"),
                installed_version=artifact.get("version"),
                fixed_version=fixed_version,
                severity=vuln.get("severity", "Unknown"),
                source="grype-json",
                raw_evidence=match,
            )
        )
    return vulnerabilities


# Grype の SARIF 形式からルール情報も参照しつつ脆弱性一覧を組み立てる。
def parse_grype_sarif(data: dict[str, Any]) -> list[VulnerabilityModel]:
    vulnerabilities: list[VulnerabilityModel] = []
    runs = data.get("runs", []) or []
    for run_index, run in enumerate(runs):
        rules_by_id = {
            rule.get("id"): rule
            for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules", []) or []
            if rule.get("id")
        }
        for result_index, result in enumerate(run.get("results", []) or []):
            rule_id = result.get("ruleId") or result.get("id")
            message = (result.get("message") or {}).get("text") or ""
            search_text = " ".join([str(rule_id or ""), message])
            generated_id = generate_vulnerability_id("grype-sarif", result_index, rule_id)
            rule = rules_by_id.get(rule_id, {})
            cve_id = _extract_cve_id(search_text) or _extract_cve_id(rule) or _extract_cve_id(result)
            vulnerabilities.append(
                VulnerabilityModel(
                    id=(cve_id if cve_id else str(rule_id or generated_id)),
                    cve_id=cve_id,
                    package_name=(rule.get("properties") or {}).get("packageName"),
                    severity=result.get("level") or (rule.get("properties") or {}).get("security-severity"),
                    source="grype-sarif",
                    raw_evidence=result,
                )
            )
    return vulnerabilities
