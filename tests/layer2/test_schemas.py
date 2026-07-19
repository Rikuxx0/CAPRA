import pytest
from pydantic import ValidationError

from capra.layer2.schemas import (
    AttackOperatorConnectionModel,
    AttackOperatorModel,
    OperatorArtifactModel,
    UnresolvedItemModel,
)


def test_operator_artifact_model_validation():
    artifact = OperatorArtifactModel(artifact_type="identity", subject_node_id="role-1")
    assert artifact.properties == {}
    with pytest.raises(ValidationError):
        OperatorArtifactModel(artifact_type="shell")


def test_attack_operator_model_uses_isolated_defaults():
    first = AttackOperatorModel(
        id="a", operator_type="read_secret", origin_kind="iam_direct_edge", source_tool="gcp_hound", status="complete"
    )
    second = AttackOperatorModel(
        id="b", operator_type="read_secret", origin_kind="iam_direct_edge", source_tool="gcp_hound", status="complete"
    )
    first.effects.append("data_read")
    assert second.effects == []
    assert second.verification_status == "unverified"


def test_connection_and_unresolved_validation():
    connection = AttackOperatorConnectionModel(
        id="c", source_operator_id="a", target_operator_id="b", connection_type="enables", reason="node match"
    )
    assert connection.metadata == {}
    unresolved = UnresolvedItemModel(id="u", type="unknown_edge", source_tool="unknown", reason="unknown")
    assert unresolved.source_fact_ids == []
