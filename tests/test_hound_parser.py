import json
from pathlib import Path

from capra.layer1.parsers.hound_parser import parse_hound_generic


# サンプル Hound JSON が期待どおりのノード数・エッジ属性へ変換されることを確認する。
def test_parse_hound_generic_nodes_edges():
    data = json.loads(Path("examples/layer1/hound_generic_sample.json").read_text())
    nodes, edges = parse_hound_generic(data)

    assert {node.id for node in nodes} >= {
        "aws:user:developer",
        "aws:role:EKSNodeRole",
        "k8s:pod:checkout-api",
        "gcp:serviceaccount:analytics-exporter",
        "azure:application:deployment-bot",
    }
    assert len(edges) == 21
    iam_edge = next(edge for edge in edges if edge.fact_id == "iam-01")
    hybrid_edge = next(edge for edge in edges if edge.fact_id == "generic-01")
    assert iam_edge.type == "assume_role"
    assert iam_edge.provider == "aws"
    assert iam_edge.source_tool == "iamhounddog"
    assert hybrid_edge.type == "network_access"
    assert hybrid_edge.provider == "hybrid"
    assert hybrid_edge.source_tool == "hound_generic"
