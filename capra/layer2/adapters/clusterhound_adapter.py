from pathlib import Path

from .direct_base import DirectEdgeAdapter


class ClusterHoundAdapter(DirectEdgeAdapter):
    source_tool = "clusterhound"
    rule_path = Path(__file__).parents[1] / "rules" / "clusterhound_edges.yaml"
