from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

try:
    from pydantic import field_validator, model_validator

    PYDANTIC_V2 = True
except ImportError:  # pragma: no cover - exercised only on Pydantic v1
    from pydantic import root_validator, validator

    PYDANTIC_V2 = False

from .severity import normalize_severity

SUPPORTED_CLOUDS = {"aws", "gcp", "azure", "k8s", "hybrid", "unknown"}


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    """Return a dict for Pydantic v1 and v2 models."""
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


def _normalize_cloud(value: Any) -> str:
    cloud = str(value or "unknown").strip().lower()
    return cloud if cloud in SUPPORTED_CLOUDS else "unknown"


if PYDANTIC_V2:

    def before_field_validator(*fields: str):
        return field_validator(*fields, mode="before")

    def before_model_validator():
        return model_validator(mode="before")

else:  # pragma: no cover - exercised only on Pydantic v1

    def before_field_validator(*fields: str):
        return validator(*fields, pre=True, always=True)

    def before_model_validator():
        return root_validator(pre=True)


class NodeModel(BaseModel):
    id: str
    name: str
    type: str = "unknown"
    cloud: str = "unknown"
    importance: float = Field(default=0.0, ge=0.0, le=1.0)
    is_entry: bool = False
    is_goal: bool = False
    goal_candidate: bool = False
    asset_category: str = "unknown"
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    raw_evidence: dict[str, Any] = Field(default_factory=dict)

    @before_field_validator("cloud")
    @classmethod
    def normalize_cloud(cls, value: Any) -> str:
        return _normalize_cloud(value)

    @before_field_validator("type", "asset_category")
    @classmethod
    def normalize_text_field(cls, value: Any) -> str:
        return str(value or "unknown").strip().lower() or "unknown"


class EdgeModel(BaseModel):
    source: str
    target: str
    type: str = "unknown"
    permission: str = ""
    provider: str = "unknown"
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    strength: float = Field(default=0.1, ge=0.0, le=1.0)

    @before_field_validator("provider")
    @classmethod
    def normalize_provider(cls, value: Any) -> str:
        return _normalize_cloud(value)

    @before_field_validator("type")
    @classmethod
    def normalize_type(cls, value: Any) -> str:
        return str(value or "unknown").strip().lower() or "unknown"


class VulnerabilityModel(BaseModel):
    id: str
    cve_id: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "Unknown"
    severity_score: float = 0.0
    source: str = "manual"
    raw_evidence: dict[str, Any] = Field(default_factory=dict)

    @before_model_validator()
    @classmethod
    def populate_severity_score(cls, values: dict[str, Any]) -> dict[str, Any]:
        severity, score = normalize_severity(values.get("severity"))
        values["severity"] = severity
        values["severity_score"] = score
        return values


class FactGraphModel(BaseModel):
    nodes: list[NodeModel] = Field(default_factory=list)
    edges: list[EdgeModel] = Field(default_factory=list)
    unmapped_vulnerabilities: list[VulnerabilityModel] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
