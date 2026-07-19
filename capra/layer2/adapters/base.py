from __future__ import annotations

from typing import Protocol

from ..schemas import AdapterContext, AdapterResult, EdgeClassification, FactGraphInput, Layer2Config


class Layer2Adapter(Protocol):
    source_tool: str

    def classify_edge(self, edge: dict, context: AdapterContext) -> EdgeClassification:
        ...

    def convert(self, fact_graph: FactGraphInput, config: Layer2Config) -> AdapterResult:
        ...
