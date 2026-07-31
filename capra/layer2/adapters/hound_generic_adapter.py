from pathlib import Path

from .direct_base import DirectEdgeAdapter


class HoundGenericAdapter(DirectEdgeAdapter):
    source_tool = "hound_generic"
    rule_path = Path(__file__).parents[1] / "rules" / "hound_generic_edges.yaml"
