import pytest

from capra.layer1.schemas import EdgeModel, NodeModel
from capra.layer2.schemas import Layer2Config
from capra.planner import (
    LayerHandoffError,
    build_capra_plan,
    build_plan_from_layer1,
    prepare_layer1_handoff,
)


def _gcp_plan():
    nodes = [
        NodeModel(id="gcp:user:analyst", name="analyst", type="user", cloud="gcp"),
        NodeModel(
            id="gcp:serviceaccount:reporter",
            name="reporter",
            type="serviceaccount",
            cloud="gcp",
        ),
        NodeModel(
            id="gcp:secret:reporting-key",
            name="reporting-key",
            type="secret",
            cloud="gcp",
        ),
    ]
    edges = [
        EdgeModel(
            source="gcp:user:analyst",
            target="gcp:serviceaccount:reporter",
            type="CanCreateKeys",
            source_tool="gcp_hound",
            provider="gcp",
            source_file="gcp.json",
            original_edge_type="CanCreateKeys",
        ),
        EdgeModel(
            source="gcp:serviceaccount:reporter",
            target="gcp:secret:reporting-key",
            type="CanReadSecretsInProject",
            source_tool="gcp_hound",
            provider="gcp",
            source_file="gcp.json",
            original_edge_type="CanReadSecretsInProject",
        ),
    ]
    return build_capra_plan(
        nodes,
        edges,
        [],
        Layer2Config(nvd_mode="cache-only"),
        source_files=["gcp.json"],
        input_hashes={"gcp.json": "source-hash"},
    )


def test_build_capra_plan_preserves_provenance_and_verifies_handoff():
    result = _gcp_plan()
    operators = result.attack_operator_graph.attack_operators
    fact_ids = {edge["fact_id"] for edge in result.fact_graph["edges"]}

    assert result.fact_graph["metadata"]["schema_version"] == "0.1.0"
    assert result.fact_graph["metadata"]["input_hashes"] == {
        "gcp.json": "source-hash"
    }
    assert result.attack_operator_graph.metadata["input_fact_graph_hash"] == (
        result.handoff_hash
    )
    assert {fact_id for operator in operators for fact_id in operator.source_fact_ids} <= fact_ids
    assert all(
        connection.connection_type == "enables"
        for connection in result.attack_operator_graph.connections
    )
    assert any(
        connection.metadata.get("match_method") == "artifact"
        for connection in result.attack_operator_graph.connections
    )


def test_handoff_is_an_isolated_redacted_snapshot():
    source = {
        "nodes": [
            {
                "id": "node-a",
                "raw_evidence": {"token": "do-not-copy"},
            }
        ],
        "edges": [],
        "unmapped_vulnerabilities": [],
        "metadata": {
            "schema_version": "0.1.0",
            "node_count": 1,
            "edge_count": 0,
            "unmapped_vulnerability_count": 0,
        },
    }

    snapshot = prepare_layer1_handoff(source)
    snapshot["nodes"][0]["id"] = "changed"

    assert source["nodes"][0]["id"] == "node-a"
    assert source["nodes"][0]["raw_evidence"]["token"] == "do-not-copy"
    assert snapshot["nodes"][0]["raw_evidence"]["token"] == "[REDACTED]"


@pytest.mark.parametrize(
    "payload",
    [
        {
            "nodes": [],
            "edges": [],
            "unmapped_vulnerabilities": [],
            "metadata": {"schema_version": "9.0.0"},
        },
        {
            "nodes": [{"id": "node-a"}],
            "edges": [
                {
                    "fact_id": "fact-1",
                    "source": "node-a",
                    "target": "missing-node",
                }
            ],
            "unmapped_vulnerabilities": [],
            "metadata": {"schema_version": "0.1.0"},
        },
    ],
)
def test_in_memory_handoff_rejects_incompatible_layer1_payload(payload):
    with pytest.raises(LayerHandoffError):
        build_plan_from_layer1(payload, Layer2Config(nvd_mode="cache-only"))
