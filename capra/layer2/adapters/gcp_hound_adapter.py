from pathlib import Path

from .direct_base import DirectEdgeAdapter


class GcpHoundAdapter(DirectEdgeAdapter):
    source_tool = "gcp_hound"
    rule_path = Path(__file__).parents[1] / "rules" / "gcp_hound_edges.yaml"
