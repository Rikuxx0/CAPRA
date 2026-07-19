from pathlib import Path

from .direct_base import DirectEdgeAdapter


class AzureHoundAdapter(DirectEdgeAdapter):
    source_tool = "azurehound"
    rule_path = Path(__file__).parents[1] / "rules" / "azurehound_edges.yaml"
