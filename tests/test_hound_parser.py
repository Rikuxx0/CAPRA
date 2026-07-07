import json
from pathlib import Path

from capra.layer1.parsers.hound_parser import parse_hound_generic


# サンプル Hound JSON が期待どおりのノード数・エッジ属性へ変換されることを確認する。
def test_parse_hound_generic_nodes_edges():
    data = json.loads(Path("examples/layer1/hound_generic_sample.json").read_text())
    nodes, edges = parse_hound_generic(data)

    assert {node.id for node in nodes} >= {"aws:user:low-priv-user", "aws:role:AdminRole"}
    assert len(edges) == 2
    assert edges[0].type == "assume_role"
    assert edges[0].provider == "unknown"
