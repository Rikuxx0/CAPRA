from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .redaction import redact_sensitive_data


class EdgeClassification(str, Enum):
    RELATIONSHIP = "RELATIONSHIP"
    PERMISSION = "PERMISSION"
    ATTACK_EDGE = "ATTACK_EDGE"
    UNKNOWN = "UNKNOWN"


class OperatorArtifactModel(BaseModel):
    artifact_type: Literal[
        "credential",
        "identity",
        "permission",
        "resource_control",
        "network_reachability",
        "data_access",
    ]
    subject_node_id: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_validator("properties", mode="before")
    @classmethod
    def redact_properties(cls, value: Any) -> dict[str, Any]:
        return redact_sensitive_data(value) if isinstance(value, dict) else {}


class AttackOperatorModel(BaseModel):
    id: str
    operator_type: str
    origin_kind: Literal["cve", "iam_direct_edge", "iam_pattern"]
    source_tool: str
    source_fact_ids: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    source_node: str | None = None
    target_node: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    effects: list[str] = Field(default_factory=list)
    produces: list[OperatorArtifactModel] = Field(default_factory=list)
    requires: list[OperatorArtifactModel] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    status: Literal["complete", "partial", "unresolved"]
    verification_status: Literal["unverified", "verified", "failed"] = "unverified"
    missing_conditions: list[str] = Field(default_factory=list)
    manual_verification_required: bool = False
    public_exploit_candidate: bool = False
    mapping_rule_id: str | None = None
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("raw_evidence", mode="before")
    @classmethod
    def redact_raw_evidence(cls, value: Any) -> dict[str, Any]:
        return redact_sensitive_data(value) if isinstance(value, dict) else {}


class AttackOperatorConnectionModel(BaseModel):
    id: str
    source_operator_id: str
    target_operator_id: str
    # "requires" remains readable for compatibility with older exports. New
    # Layer 2 graphs only generate forward "enables" causal connections.
    connection_type: Literal["enables", "requires"]
    reason: str
    artifact: OperatorArtifactModel | None = None
    condition: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UnresolvedItemModel(BaseModel):
    id: str
    type: str
    source_tool: str
    source_fact_ids: list[str] = Field(default_factory=list)
    missing_conditions: list[str] = Field(default_factory=list)
    reason: str
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("raw_evidence", mode="before")
    @classmethod
    def redact_raw_evidence(cls, value: Any) -> dict[str, Any]:
        return redact_sensitive_data(value) if isinstance(value, dict) else {}


class AttackOperatorGraphModel(BaseModel):
    schema_version: str = "0.1.0"
    attack_operators: list[AttackOperatorModel] = Field(default_factory=list)
    connections: list[AttackOperatorConnectionModel] = Field(default_factory=list)
    unresolved_items: list[UnresolvedItemModel] = Field(default_factory=list)
    layer3_candidates: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Layer2Config(BaseModel):
    nvd_mode: Literal["cache-only", "cache-then-fetch"] = "cache-only"
    nvd_cache_directory: Path = Path("cache/nvd")
    nvd_cache_ttl_seconds: int = 86400 * 7
    nvd_timeout_seconds: float = 10.0
    nvd_max_retries: int = 2
    nvd_rate_limit_seconds: float = 0.7
    max_hops: int = Field(default=6, ge=1, le=20)
    max_matches_per_rule: int = Field(default=100, ge=1)
    max_total_operators: int = Field(default=1000, ge=1)
    max_connections: int = Field(default=5000, ge=1)
    max_candidates: int = Field(default=500, ge=1)
    max_uploaded_file_size: int = Field(default=10 * 1024 * 1024, ge=1)
    selected_source_tools: list[str] = Field(default_factory=list)
    selected_operator_types: list[str] = Field(default_factory=list)
    hound_generic_rule_paths: list[Path] = Field(default_factory=list)
    azurehound_rule_paths: list[Path] = Field(default_factory=list)
    gcp_hound_rule_paths: list[Path] = Field(default_factory=list)
    clusterhound_rule_paths: list[Path] = Field(default_factory=list)
    iamhounddog_rule_paths: list[Path] = Field(default_factory=list)
    cve_operator_rule_paths: list[Path] = Field(default_factory=list)
    # Kept for callers that still provide a single replacement rule file.
    iamhounddog_rule_path: Path | None = None


class FactGraphInput(BaseModel):
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    unmapped_vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    input_hash: str = ""


class AdapterContext(BaseModel):
    nodes_by_id: dict[str, dict[str, Any]] = Field(default_factory=dict)


class AdapterResult(BaseModel):
    operators: list[AttackOperatorModel] = Field(default_factory=list)
    unresolved_items: list[UnresolvedItemModel] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    statistics: dict[str, int] = Field(default_factory=dict)
