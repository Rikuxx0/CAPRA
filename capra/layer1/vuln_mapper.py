from __future__ import annotations

from typing import Any

from .schemas import NodeModel, VulnerabilityModel, model_to_dict


# 脆弱性をマッピング定義や推定ルールでノードへ割り当て、未割当も返す。
def attach_vulnerabilities_to_nodes(
    nodes: list[NodeModel],
    vulnerabilities: list[VulnerabilityModel],
    mapping_config: dict[str, Any] | None = None,
) -> tuple[list[NodeModel], list[VulnerabilityModel]]:
    mapping_rules = (mapping_config or {}).get("vulnerability_mappings", []) or []
    node_by_id = {node.id: node for node in nodes}
    unmapped: list[VulnerabilityModel] = []
    seen_mapped: dict[str, set[tuple[Any, ...]]] = {
        node.id: {_vulnerability_key(item) for item in node.vulnerabilities}
        for node in nodes
    }
    seen_unmapped: set[tuple[Any, ...]] = set()

    for vulnerability in vulnerabilities:
        target = _match_by_mapping(vulnerability, mapping_rules, nodes)
        if target is None:
            target = _match_by_target_hint(vulnerability, nodes)
        if target is None:
            target = _match_by_partial_name(vulnerability, nodes)

        if target is None:
            key = _vulnerability_key(model_to_dict(vulnerability))
            if key not in seen_unmapped:
                unmapped.append(vulnerability)
                seen_unmapped.add(key)
        else:
            item = model_to_dict(vulnerability)
            key = _vulnerability_key(item)
            if key not in seen_mapped[target.id]:
                node_by_id[target.id].vulnerabilities.append(item)
                seen_mapped[target.id].add(key)

    return list(node_by_id.values()), unmapped


# 明示的な CVE/package/node ルールに一致するノードを優先して探す。
def _match_by_mapping(
    vulnerability: VulnerabilityModel,
    rules: list[dict[str, Any]],
    nodes: list[NodeModel],
) -> NodeModel | None:
    for rule in rules:
        if rule.get("cve_id") and rule["cve_id"] != vulnerability.cve_id:
            continue
        if rule.get("package_name") and rule["package_name"] != vulnerability.package_name:
            continue
        if rule.get("node_id"):
            return next((node for node in nodes if node.id == rule["node_id"]), None)
        if rule.get("node_name"):
            return next((node for node in nodes if node.name == rule["node_name"]), None)
    return None


# 生データ中の対象ヒント文字列から該当ノードを推定する。
def _match_by_target_hint(vulnerability: VulnerabilityModel, nodes: list[NodeModel]) -> NodeModel | None:
    hints = _extract_target_hints(vulnerability.raw_evidence)
    for hint in hints:
        normalized_hint = hint.lower()
        for node in nodes:
            node_name = node.name.lower()
            node_id = node.id.lower()
            if normalized_hint and (
                normalized_hint in node_name
                or normalized_hint in node_id
                or node_name in normalized_hint
                or node_id in normalized_hint
            ):
                return node
    return None


# パッケージ名や成果物名の部分一致で緩やかにノードを推定する。
def _match_by_partial_name(vulnerability: VulnerabilityModel, nodes: list[NodeModel]) -> NodeModel | None:
    candidates = [vulnerability.package_name]
    artifact = vulnerability.raw_evidence.get("artifact") or {}
    candidates.extend([artifact.get("name"), artifact.get("purl")])
    for candidate in filter(None, candidates):
        text = str(candidate).lower()
        for node in nodes:
            node_text = f"{node.id} {node.name}".lower()
            if text in node_text or node.name.lower() in text:
                return node
    return None


# スキャナ出力の複数フィールドから対象ノード推定用の文字列を抽出する。
def _extract_target_hints(raw: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    for key in ("target", "image", "container", "location"):
        value = raw.get(key)
        if isinstance(value, str):
            hints.append(value)
        elif isinstance(value, dict):
            hints.extend(str(item) for item in value.values() if item)
    artifact = raw.get("artifact") or {}
    metadata = artifact.get("metadata") or {}
    for key in ("image", "container", "path", "location", "virtualPath"):
        if artifact.get(key):
            hints.append(str(artifact[key]))
        if metadata.get(key):
            hints.append(str(metadata[key]))
    return hints


def _vulnerability_key(vulnerability: dict[str, Any]) -> tuple[Any, ...]:
    """Identify the same scanner finding without collapsing distinct packages."""
    return (
        vulnerability.get("id"),
        vulnerability.get("cve_id"),
        vulnerability.get("package_name"),
        vulnerability.get("installed_version"),
        vulnerability.get("source"),
    )
