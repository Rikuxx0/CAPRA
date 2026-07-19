from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PatternStepModel(BaseModel):
    from_type: str
    edge_type: str
    to_type: str
    bind_from_as: str | None = None
    bind_to_as: str | None = None


class PatternOperatorModel(BaseModel):
    type: str
    preconditions: list[str] = Field(default_factory=list)
    effects: list[str] = Field(default_factory=list)
    produces: list[dict[str, Any]] = Field(default_factory=list)
    requires: list[dict[str, Any]] = Field(default_factory=list)


class PatternRuleModel(BaseModel):
    id: str
    version: str
    enabled: bool = True
    source_tool: str = "iamhounddog"
    max_hops: int = 6
    pattern: list[PatternStepModel]
    required_permissions: list[str] = Field(default_factory=list)
    operator: PatternOperatorModel
