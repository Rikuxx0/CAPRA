import json
from pathlib import Path

import yaml

from capra.layer1.asset_marker import apply_asset_markers
from capra.layer1.exporters import export_fact_graph_json
from capra.layer1.graph_builder import build_fact_graph, build_layer1_fact_graph
from capra.layer1.parsers.grype_parser import parse_grype_json
from capra.layer1.parsers.hound_parser import parse_hound_generic


def test_asset_marker_sets_goal_candidate_not_fixed_goal():
    hound = json.loads(Path("examples/layer1/hound_generic_sample.json").read_text())
    assets = yaml.safe_load(Path("examples/layer1/important_assets.yaml").read_text())
    nodes, _ = parse_hound_generic(hound)

    marked = apply_asset_markers(nodes, assets)
    admin = next(node for node in marked if node.id == "aws:role:AdminRole")

    assert admin.goal_candidate is True
    assert admin.is_goal is False
    assert admin.importance == 1.0


def test_build_fact_graph():
    hound = json.loads(Path("examples/layer1/hound_generic_sample.json").read_text())
    nodes, edges = parse_hound_generic(hound)
    graph = build_fact_graph(nodes, edges)

    assert graph.number_of_nodes() == 3
    assert graph.number_of_edges() == 2
    assert graph.nodes["aws:user:low-priv-user"]["name"] == "low-priv-user"


def test_export_fact_graph_json():
    hound = json.loads(Path("examples/layer1/hound_generic_sample.json").read_text())
    grype = json.loads(Path("examples/layer1/grype_sample.json").read_text())
    assets = yaml.safe_load(Path("examples/layer1/important_assets.yaml").read_text())
    mapping = yaml.safe_load(Path("examples/layer1/vulnerability_mapping.yaml").read_text())
    nodes, edges = parse_hound_generic(hound)
    vulnerabilities = parse_grype_json(grype)

    graph = build_layer1_fact_graph(
        nodes,
        edges,
        vulnerabilities,
        asset_config=assets,
        vulnerability_mapping_config=mapping,
    )
    exported = export_fact_graph_json(graph)

    assert exported["metadata"]["node_count"] == 5
    assert exported["metadata"]["edge_count"] == 2
    assert exported["metadata"]["vulnerability_count"] == 1
    assert exported["metadata"]["unmapped_vulnerability_count"] == 0
    backend = next(node for node in exported["nodes"] if node["id"] == "k8s:pod:backend-api")
    assert backend["vulnerabilities"][0]["cve_id"] == "CVE-2023-1234"
