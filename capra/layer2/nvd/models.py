from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class NvdReferenceModel(BaseModel):
    url: str
    tags: list[str] = Field(default_factory=list)


class NvdRecordModel(BaseModel):
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)
    references: list[NvdReferenceModel] = Field(default_factory=list)
    public_exploit_candidate: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)
