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


# Pydantic v1/v2 の差異を吸収してモデルを辞書へ変換する。
def model_to_dict(model: BaseModel) -> dict[str, Any]:
    """Return a dict for Pydantic v1 and v2 models."""
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


# サポート対象外のクラウド値を unknown に正規化する。
def _normalize_cloud(value: Any) -> str:
    cloud = str(value or "unknown").strip().lower()
    return cloud if cloud in SUPPORTED_CLOUDS else "unknown"


if PYDANTIC_V2:

    # Pydantic v2 用の before validator を共通インターフェースで返す。
    def before_field_validator(*fields: str):
        return field_validator(*fields, mode="before")

    # Pydantic v2 用の model before validator を返す。
    def before_model_validator():
        return model_validator(mode="before")

else:  # pragma: no cover - exercised only on Pydantic v1

    # Pydantic v1 用の before validator を共通インターフェースで返す。
    def before_field_validator(*fields: str):
        return validator(*fields, pre=True, always=True)

    # Pydantic v1 用の model before validator を返す。
    def before_model_validator():
        return root_validator(pre=True)


class NodeModel(BaseModel):
    id: str
    name: str
    type: str = "unknown"
    cloud: str = "unknown"
    is_entry: bool = False
    is_goal: bool = False
    goal_candidate: bool = False
    asset_category: str = "unknown"
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    raw_evidence: dict[str, Any] = Field(default_factory=dict)

    @before_field_validator("cloud")
    @classmethod
    # クラウド名の揺れをスキーマ投入前に正規化する。
    def normalize_cloud(cls, value: Any) -> str:
        return _normalize_cloud(value)

    @before_field_validator("type", "asset_category")
    @classmethod
    # 種別や資産カテゴリを lower-case の文字列へそろえる。
    def normalize_text_field(cls, value: Any) -> str:
        return str(value or "unknown").strip().lower() or "unknown"


class EdgeModel(BaseModel):
    source: str
    target: str
    type: str = "unknown"
    permission: str = ""
    provider: str = "unknown"
    raw_evidence: dict[str, Any] = Field(default_factory=dict)

    @before_field_validator("provider")
    @classmethod
    # プロバイダ名をサポート対象の値へ正規化する。
    def normalize_provider(cls, value: Any) -> str:
        return _normalize_cloud(value)

    @before_field_validator("type")
    @classmethod
    # エッジ種別を lower-case の文字列へそろえる。
    def normalize_type(cls, value: Any) -> str:
        return str(value or "unknown").strip().lower() or "unknown"


class VulnerabilityModel(BaseModel):
    id: str
    cve_id: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "Unknown"
    source: str = "manual"
    raw_evidence: dict[str, Any] = Field(default_factory=dict)

    @before_model_validator()
    @classmethod
    # severity 表記を正規化する。
    def normalize_severity_label(cls, values: dict[str, Any]) -> dict[str, Any]:
        values["severity"] = normalize_severity(values.get("severity"))
        return values


class FactGraphModel(BaseModel):
    nodes: list[NodeModel] = Field(default_factory=list)
    edges: list[EdgeModel] = Field(default_factory=list)
    unmapped_vulnerabilities: list[VulnerabilityModel] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
