from __future__ import annotations

import re
from typing import Any

from ..schemas import VulnerabilityModel
from ..utils.ids import generate_vulnerability_id

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def parse_grype_json(data: dict[str, Any]) -> list[VulnerabilityModel]:
    vulnerabilities: list[VulnerabilityModel] = []
    for index, match in enumerate(data.get("matches", []) or []):
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vuln_id = str(vuln.get("id") or generate_vulnerability_id("grype-json", index))
        fix = vuln.get("fix") or {}
        versions = fix.get("versions") or []
        fixed_version = str(versions[0]) if versions else None
        cve_match = CVE_PATTERN.search(vuln_id)

        vulnerabilities.append(
            VulnerabilityModel(
                id=vuln_id,
                cve_id=cve_match.group(0).upper() if cve_match else None,
                package_name=artifact.get("name"),
                installed_version=artifact.get("version"),
                fixed_version=fixed_version,
                severity=vuln.get("severity", "Unknown"),
                source="grype-json",
                raw_evidence=match,
            )
        )
    return vulnerabilities


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
            cve_match = CVE_PATTERN.search(search_text)
            generated_id = generate_vulnerability_id("grype-sarif", result_index, rule_id)
            rule = rules_by_id.get(rule_id, {})
            vulnerabilities.append(
                VulnerabilityModel(
                    id=(cve_match.group(0).upper() if cve_match else str(rule_id or generated_id)),
                    cve_id=cve_match.group(0).upper() if cve_match else None,
                    package_name=(rule.get("properties") or {}).get("packageName"),
                    severity=result.get("level") or (rule.get("properties") or {}).get("security-severity"),
                    source="grype-sarif",
                    raw_evidence=result,
                )
            )
    return vulnerabilities
