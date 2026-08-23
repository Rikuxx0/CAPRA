import json

from capra.layer1.asset_marker import apply_asset_markers
from capra.layer1.exporters import export_fact_graph_json
from capra.layer1.graph_builder import build_fact_graph, build_layer1_fact_graph
from capra.layer1.parsers.dependency_parser import parse_cross_cloud_dependencies
from capra.layer1.parsers.drawio_parser import parse_drawio_to_layer1
from capra.layer1.parsers.hound_parser import infer_provider, parse_hound_generic
from capra.layer1.schemas import EdgeModel, NodeModel, VulnerabilityModel
from capra.layer1.utils.ids import generate_node_id
from capra.layer2.fact_graph_loader import load_fact_graph


def test_hound_preserves_provenance_and_infers_providers():
    data = {
        "source_tool": "GCP-Hound",
        "edges": [
            {
                "source": "user:one",
                "target": "projects/demo/serviceAccounts/app@demo.iam.gserviceaccount.com",
                "type": "canSignJwt",
            }
        ],
    }
    _, edges = parse_hound_generic(data, source_file="gcp.json")

    assert edges[0].source_tool == "gcp_hound"
    assert edges[0].source_file == "gcp.json"
    assert edges[0].original_edge_type == "canSignJwt"
    assert edges[0].provider == "gcp"
    assert infer_provider("custom-resource") == "unknown"


def test_selected_goal_and_entry_point_are_explicit():
    nodes = [NodeModel(id="canonical-id", name="Admin", type="role", cloud="aws", is_goal=True)]
    config = {
        "assets": [{"id": "declared-id", "name": "Admin", "type": "role", "cloud": "aws"}],
        "entry_points": [{"id": "entry", "name": "Internet API", "type": "service", "cloud": "azure"}],
    }

    unselected = apply_asset_markers(nodes, config)
    selected = apply_asset_markers(nodes, config, selected_goal_ids={"declared-id"})

    assert next(node for node in unselected if node.id == "canonical-id").goal_candidate is True
    assert next(node for node in unselected if node.id == "canonical-id").is_goal is False
    assert next(node for node in selected if node.id == "canonical-id").is_goal is True
    assert next(node for node in selected if node.id == "entry").is_entry is True


def test_cve_mapping_priority_target_hint_and_unmapped_retention():
    nodes = [
        NodeModel(id="pod-a", name="unrelated", type="pod", cloud="k8s"),
        NodeModel(id="pod-b", name="checkout-api", type="pod", cloud="k8s"),
    ]
    vulnerabilities = [
        VulnerabilityModel(id="v1", cve_id="CVE-2024-0001", package_name="checkout", raw_evidence={"target": "checkout-api"}),
        VulnerabilityModel(id="v2", cve_id="CVE-2024-0002", package_name="missing"),
    ]
    graph = build_layer1_fact_graph(
        nodes,
        [],
        vulnerabilities,
        vulnerability_mapping_config={"vulnerability_mappings": [{"cve_id": "CVE-2024-0001", "node_id": "pod-a"}]},
    )

    assert graph.nodes["pod-a"]["vulnerabilities"][0]["id"] == "v1"
    assert graph.nodes["pod-b"]["vulnerabilities"] == []
    assert graph.graph["unmapped_vulnerabilities"][0]["id"] == "v2"


def test_target_hint_maps_without_explicit_rule():
    graph = build_layer1_fact_graph(
        [NodeModel(id="pod", name="checkout-api")],
        [],
        [VulnerabilityModel(id="v1", raw_evidence={"image": "registry/checkout-api:1"})],
    )
    assert graph.nodes["pod"]["vulnerabilities"][0]["id"] == "v1"


def test_node_merge_preserves_evidence_and_deduplicates_vulnerabilities():
    vulnerability = {"id": "v1", "cve_id": "CVE-2024-0001", "source": "grype"}
    graph = build_fact_graph(
        [
            NodeModel(id="n1", name="node", raw_evidence={"source_file": "one.json"}, vulnerabilities=[vulnerability]),
            NodeModel(id="n1", name="node", raw_evidence={"source_file": "two.json"}, vulnerabilities=[vulnerability]),
        ],
        [],
    )

    assert len(graph.nodes["n1"]["vulnerabilities"]) == 1
    assert graph.nodes["n1"]["raw_evidence"] == {
        "records": [{"source_file": "one.json"}, {"source_file": "two.json"}]
    }


def test_recursive_raw_evidence_redaction():
    node = NodeModel(
        id="n1",
        name="node",
        raw_evidence={
            "password": "p",
            "nested": [{"client_secret": "s"}, {"safe": "kept"}],
            "authorization": "Bearer value",
        },
    )

    assert node.raw_evidence["password"] == "[REDACTED]"
    assert node.raw_evidence["nested"][0]["client_secret"] == "[REDACTED]"
    assert node.raw_evidence["nested"][1]["safe"] == "kept"
    assert node.raw_evidence["authorization"] == "[REDACTED]"


def test_stable_generated_node_and_fact_ids():
    node_id_1 = generate_node_id("Checkout API", "Pod", "K8s")
    node_id_2 = generate_node_id("Checkout API", "Pod", "K8s")
    data = {"edges": [{"source": "a", "target": "b", "type": "owns"}]}
    _, edges_1 = parse_hound_generic(data, source_file="facts.json")
    _, edges_2 = parse_hound_generic(data, source_file="facts.json")

    assert node_id_1 == node_id_2 == "k8s:pod:checkout-api"
    assert edges_1[0].fact_id == edges_2[0].fact_id
    assert edges_1[0].fact_id.startswith("fact:")


def test_drawio_is_optional_and_parses_nodes_and_edges():
    empty_graph = build_layer1_fact_graph([], [], [])
    assert empty_graph.number_of_nodes() == 0

    xml = """<mxfile><diagram><mxGraphModel><root>
      <mxCell id="0"/><mxCell id="1" parent="0"/>
      <mxCell id="2" value="Internet" vertex="1" parent="1"/>
      <mxCell id="3" value="Checkout API" vertex="1" parent="1"/>
      <mxCell id="4" edge="1" source="2" target="3" parent="1"/>
    </root></mxGraphModel></diagram></mxfile>"""
    nodes, edges = parse_drawio_to_layer1(xml, source_file="architecture.drawio")

    assert len(nodes) == 2
    assert len(edges) == 1
    assert edges[0].type == "network_access"
    assert edges[0].source_tool == "drawio"


def test_cross_cloud_dependencies_are_facts_not_attack_inferences():
    nodes, edges = parse_cross_cloud_dependencies(
        {
            "dependencies": [
                {
                    "source": "aws:secret:gcp-key-reference",
                    "target": "gcp:serviceaccount:analytics",
                    "type": "stores_reference_to",
                }
            ]
        },
        source_file="cross_cloud_edges.yaml",
    )

    assert {node.cloud for node in nodes} == {"aws", "gcp"}
    assert edges[0].type == "stores_reference_to"
    assert edges[0].source_tool == "manual"
    assert edges[0].source_file == "cross_cloud_edges.yaml"


def test_export_is_serializable_deterministic_and_has_provenance_metadata():
    nodes, edges = parse_hound_generic(
        {
            "source_tool": "azurehound",
            "nodes": [{"id": "azure:application:app", "name": "app", "cloud": "azure"}],
            "edges": [{"source": "azure:application:app", "target": "k8s:serviceaccount:api", "type": "owns"}],
        },
        source_file="hound.json",
    )
    kwargs = {
        "source_files": ["hound.json"],
        "input_hashes": {"hound.json": "abc123"},
    }
    first = export_fact_graph_json(build_layer1_fact_graph(nodes, edges, [], **kwargs))
    second = export_fact_graph_json(build_layer1_fact_graph(nodes, edges, [], **kwargs))

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["metadata"]["source_tools"] == ["azurehound"]
    assert first["metadata"]["cloud_providers"] == ["azure", "hybrid", "k8s"]
    assert first["metadata"]["input_hashes"] == {"hound.json": "abc123"}


def test_export_remains_loadable_by_layer2_and_preserves_future_tool():
    nodes, edges = parse_hound_generic(
        {"source_tool": "bloodhound-kube", "edges": [{"source": "k8s:user:a", "target": "k8s:role:b", "type": "canBind"}]}
    )
    payload = export_fact_graph_json(build_layer1_fact_graph(nodes, edges, []))
    loaded, unresolved, warnings = load_fact_graph(payload)

    assert loaded.edges[0]["source_tool"] == "bloodhound_kube"
    assert unresolved == []
    assert warnings == []


def test_parallel_facts_from_different_sources_are_not_collapsed():
    edges = [
        EdgeModel(source="a", target="b", type="owns", source_tool="manual", source_file="one.yaml"),
        EdgeModel(source="a", target="b", type="owns", source_tool="manual", source_file="two.yaml"),
    ]
    assert build_fact_graph([], edges).number_of_edges() == 2
