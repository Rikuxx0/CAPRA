from capra.layer2.ids import generate_connection_id, generate_operator_id, generate_unresolved_id
from capra.layer2.schemas import OperatorArtifactModel


def test_deterministic_operator_id_normalizes_order_and_case():
    first = generate_operator_id(
        operator_type=" Read_Secret ", origin_kind="IAM_DIRECT_EDGE", source_node="a", target_node="b",
        source_fact_ids=["f2", "f1"], mapping_rule_id="gcp.read", provider="GCP",
    )
    second = generate_operator_id(
        operator_type="read_secret", origin_kind="iam_direct_edge", source_node="a", target_node="b",
        source_fact_ids=["f1", "f2"], mapping_rule_id="gcp.read", provider="gcp",
    )
    assert first == second


def test_deterministic_connection_and_unresolved_ids():
    artifact = OperatorArtifactModel(artifact_type="identity", subject_node_id="role")
    assert generate_connection_id("a", "b", "enables", artifact) == generate_connection_id("a", "b", "enables", artifact)
    assert generate_unresolved_id(item_type="edge", source_tool="x", source_fact_ids=["2", "1"], reason="missing") == generate_unresolved_id(
        item_type="edge", source_tool="x", source_fact_ids=["1", "2"], reason="missing"
    )
