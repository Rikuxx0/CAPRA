from __future__ import annotations

from typing import Any

from .ids import generate_unresolved_id, stable_hash
from .redaction import redact_sensitive_data
from .schemas import FactGraphInput, UnresolvedItemModel

SUPPORTED_SOURCE_TOOLS = {
    "iamhounddog",
    "azurehound",
    "gcp_hound",
    "clusterhound",
    "grype",
    "nvd",
    "drawio",
    "manual",
    "unknown",
}
SOURCE_TOOL_ALIASES = {
    "azure_hound": "azurehound",
    "gcp-hound": "gcp_hound",
    "gcphound": "gcp_hound",
    "cluster_hound": "clusterhound",
    "iam_hound_dog": "iamhounddog",
    "iamhound": "iamhounddog",
}


def _unresolved(
    item_type: str,
    reason: str,
    *,
    source_tool: str = "unknown",
    source_fact_ids: list[str] | None = None,
    missing_conditions: list[str] | None = None,
    raw_evidence: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> UnresolvedItemModel:
    fact_ids = source_fact_ids or []
    missing = missing_conditions or []
    return UnresolvedItemModel(
        id=generate_unresolved_id(
            item_type=item_type,
            source_tool=source_tool,
            source_fact_ids=fact_ids,
            reason=reason,
            missing_conditions=missing,
        ),
        type=item_type,
        source_tool=source_tool,
        source_fact_ids=fact_ids,
        missing_conditions=missing,
        reason=reason,
        raw_evidence=redact_sensitive_data(raw_evidence or {}),
        metadata=metadata or {},
    )


def normalize_source_tool(value: Any) -> str:
    tool = str(value or "unknown").strip().lower().replace(" ", "_")
    tool = SOURCE_TOOL_ALIASES.get(tool, tool)
    return tool if tool in SUPPORTED_SOURCE_TOOLS else "unknown"


def _infer_source_tool(edge: dict[str, Any], original_type: str) -> str:
    raw = edge.get("raw_evidence") if isinstance(edge.get("raw_evidence"), dict) else {}
    explicit = edge.get("source_tool") or raw.get("source_tool") or raw.get("tool")
    if explicit:
        normalized_explicit = normalize_source_tool(explicit)
        if normalized_explicit != "unknown":
            return normalized_explicit
    edge_type = original_type.strip().lower()
    if edge_type.startswith("az"):
        return "azurehound"
    if edge_type in {
        "cancreatekeys", "canreadsecretsinproject", "cansignblob", "cansignjwt",
        "canmodifybucketpoliciesinproject", "containsserviceaccount", "hasgoogleownedsa",
    }:
        return "gcp_hound"
    if edge_type in {
        "canbind", "canescalate", "cancreatetoken", "fullaccess", "canassumeserviceaccount",
        "mountsserviceaccount", "canexec", "canattach", "canportforward", "cancreateworkload",
        "cancreateephemeral", "secretsread", "secretscreate", "podprivileged", "podhostpid",
        "podhostnetwork", "podhostipc", "nodesproxyrce", "entrypoint", "unauthapiaccess",
        "unauthkubeletaccess", "accessimds",
    }:
        return "clusterhound"
    permission = str(edge.get("permission") or raw.get("permission") or "").lower()
    if permission == "drawio:connected":
        return "drawio"
    return "unknown"


def load_fact_graph(data: dict[str, Any]) -> tuple[FactGraphInput, list[UnresolvedItemModel], list[str]]:
    if not isinstance(data, dict):
        raise ValueError("Fact Graph JSON root must be an object")
    redacted = redact_sensitive_data(data)
    unresolved: list[UnresolvedItemModel] = []
    warnings: list[str] = []
    metadata = redacted.get("metadata") if isinstance(redacted.get("metadata"), dict) else {}
    global_files = metadata.get("source_files") if isinstance(metadata.get("source_files"), list) else []

    raw_nodes = redacted.get("nodes", [])
    if not isinstance(raw_nodes, list):
        warnings.append("nodes must be a list; treated as empty")
        raw_nodes = []
    nodes: list[dict[str, Any]] = []
    for index, raw_node in enumerate(raw_nodes):
        if not isinstance(raw_node, dict) or not str(raw_node.get("id") or "").strip():
            unresolved.append(_unresolved("invalid_fact_node", "Node is not an object with a non-empty id", raw_evidence={"index": index, "value": raw_node}))
            continue
        node = dict(raw_node)
        node["id"] = str(node["id"]).strip()
        node.setdefault("type", "unknown")
        node.setdefault("vulnerabilities", [])
        if not isinstance(node["vulnerabilities"], list):
            unresolved.append(_unresolved("invalid_vulnerabilities", "Node vulnerabilities must be a list", raw_evidence=node))
            node["vulnerabilities"] = []
        node["raw_evidence"] = redact_sensitive_data(node.get("raw_evidence") or {})
        nodes.append(node)

    raw_edges = redacted.get("edges", [])
    if not isinstance(raw_edges, list):
        warnings.append("edges must be a list; treated as empty")
        raw_edges = []
    edges: list[dict[str, Any]] = []
    for index, raw_edge in enumerate(raw_edges):
        if not isinstance(raw_edge, dict):
            unresolved.append(_unresolved("invalid_fact_edge", "Edge is not an object", raw_evidence={"index": index, "value": raw_edge}))
            continue
        edge = dict(raw_edge)
        raw_evidence = edge.get("raw_evidence") if isinstance(edge.get("raw_evidence"), dict) else {}
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        original_type = str(edge.get("original_edge_type") or raw_evidence.get("type") or edge.get("type") or "unknown").strip() or "unknown"
        source_tool = _infer_source_tool(edge, original_type)
        fact_id = str(edge.get("fact_id") or edge.get("id") or "").strip()
        if not fact_id:
            fact_id = f"fact:{stable_hash({'source': source, 'target': target, 'type': original_type, 'permission': edge.get('permission')})[:16]}"
        if not source or not target:
            unresolved.append(
                _unresolved(
                    "invalid_fact_edge", "Edge source and target are required", source_tool=source_tool,
                    source_fact_ids=[fact_id], missing_conditions=[name for name, value in (("source", source), ("target", target)) if not value], raw_evidence=edge,
                )
            )
            continue
        source_file = edge.get("source_file") or raw_evidence.get("source_file")
        if not source_file and len(global_files) == 1:
            source_file = global_files[0]
        edge.update(
            {
                "fact_id": fact_id,
                "source": source,
                "target": target,
                "type": str(edge.get("type") or original_type or "unknown").strip().lower() or "unknown",
                "permission": str(edge.get("permission") or "").strip(),
                "provider": str(edge.get("provider") or "unknown").strip().lower() or "unknown",
                "source_tool": source_tool,
                "source_file": str(source_file).strip() if source_file else None,
                "original_edge_type": original_type,
                "raw_evidence": redact_sensitive_data(raw_evidence or edge),
            }
        )
        edges.append(edge)
        if source_tool == "unknown":
            unresolved.append(
                _unresolved(
                    "unknown_source_tool", "Edge source_tool could not be determined", source_tool="unknown",
                    source_fact_ids=[fact_id], missing_conditions=["source_tool"], raw_evidence=edge,
                )
            )

    unmapped = redacted.get("unmapped_vulnerabilities", [])
    if not isinstance(unmapped, list):
        warnings.append("unmapped_vulnerabilities must be a list; treated as empty")
        unmapped = []
    graph = FactGraphInput(
        nodes=nodes,
        edges=edges,
        unmapped_vulnerabilities=[item for item in unmapped if isinstance(item, dict)],
        metadata=metadata,
        input_hash=stable_hash(redacted),
    )
    return graph, unresolved, warnings
