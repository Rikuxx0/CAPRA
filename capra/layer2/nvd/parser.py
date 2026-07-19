from __future__ import annotations

import re
from typing import Any

from .cache import normalize_cve_id
from .models import NvdRecordModel, NvdReferenceModel

CPE_VERSION_PATTERN = re.compile(r"^cpe:2\.3:[aho]:[^:]*:[^:]*:([^:]*):")


def _first_english(items: list[dict[str, Any]]) -> str:
    for item in items:
        if str(item.get("lang") or "").lower() == "en":
            return str(item.get("value") or "")
    return ""


def _cvss_data(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries and isinstance(entries[0], dict):
            return entries[0].get("cvssData") or {}
    return {}


def _walk_cpe_matches(value: Any) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "cpeMatch" and isinstance(item, list):
                matches.extend(entry for entry in item if isinstance(entry, dict))
            else:
                matches.extend(_walk_cpe_matches(item))
    elif isinstance(value, list):
        for item in value:
            matches.extend(_walk_cpe_matches(item))
    return matches


def parse_nvd_response(payload: dict[str, Any], expected_cve_id: str | None = None) -> NvdRecordModel:
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities or not isinstance(vulnerabilities[0], dict):
        raise ValueError("NVD response contains no vulnerabilities")
    cve = vulnerabilities[0].get("cve") or {}
    cve_id = normalize_cve_id(cve.get("id") or expected_cve_id or "")
    if expected_cve_id and cve_id != normalize_cve_id(expected_cve_id):
        raise ValueError("NVD response CVE ID does not match request")
    cvss = _cvss_data(cve)
    cwe_ids = sorted(
        {
            str(description.get("value"))
            for weakness in cve.get("weaknesses", []) or []
            for description in weakness.get("description", []) or []
            if str(description.get("value") or "").upper().startswith("CWE-")
        }
    )
    references = [
        NvdReferenceModel(url=str(item.get("url") or ""), tags=[str(tag) for tag in item.get("tags", []) or []])
        for item in cve.get("references", []) or []
        if item.get("url")
    ]
    public_exploit = any(any("exploit" == tag.strip().lower() for tag in reference.tags) for reference in references)
    products: set[str] = set()
    versions: set[str] = set()
    for match in _walk_cpe_matches(cve.get("configurations", [])):
        criteria = str(match.get("criteria") or "")
        parts = criteria.split(":")
        if len(parts) > 5:
            products.add(":".join(parts[3:5]))
            if parts[5] not in {"", "*", "-"}:
                versions.add(parts[5])
        for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
            if match.get(key):
                versions.add(str(match[key]))
    return NvdRecordModel(
        cve_id=cve_id,
        description=_first_english(cve.get("descriptions", []) or []),
        cvss_score=cvss.get("baseScore"),
        cvss_vector=cvss.get("vectorString"),
        attack_vector=str(cvss.get("attackVector") or "").lower() or None,
        attack_complexity=str(cvss.get("attackComplexity") or "").lower() or None,
        privileges_required=str(cvss.get("privilegesRequired") or "").lower() or None,
        user_interaction=str(cvss.get("userInteraction") or "").lower() or None,
        scope=str(cvss.get("scope") or "").lower() or None,
        confidentiality_impact=str(cvss.get("confidentialityImpact") or "").lower() or None,
        integrity_impact=str(cvss.get("integrityImpact") or "").lower() or None,
        availability_impact=str(cvss.get("availabilityImpact") or "").lower() or None,
        cwe_ids=cwe_ids,
        products=sorted(products),
        versions=sorted(versions),
        references=references,
        public_exploit_candidate=public_exploit,
        raw=cve,
    )
