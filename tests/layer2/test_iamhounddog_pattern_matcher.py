import pytest

from capra.layer2.adapters.iamhounddog_adapter import IamHoundDogAdapter
from capra.layer2.patterns.loader import DEFAULT_PATTERN_PATH, load_pattern_rules
from capra.layer2.schemas import FactGraphInput, Layer2Config


def graph(include_passrole=True):
    nodes = [
        {"id": "p", "type": "principal"}, {"id": "r1", "type": "role"}, {"id": "policy", "type": "policy"},
        {"id": "ec2", "type": "ec2"}, {"id": "r2", "type": "role"},
    ]
    edges = [
        {"fact_id": "f1", "source": "p", "target": "r1", "type": "assume_role", "original_edge_type": "assume_role", "permission": "sts:AssumeRole", "source_tool": "iamhounddog"},
        {"fact_id": "f2", "source": "r1", "target": "policy", "type": "attached_policy", "original_edge_type": "attached_policy", "permission": "", "source_tool": "iamhounddog"},
        {"fact_id": "f3", "source": "policy", "target": "ec2", "type": "ec2_run_instances", "original_edge_type": "ec2_run_instances", "permission": "ec2:RunInstances", "source_tool": "iamhounddog"},
        {"fact_id": "f4", "source": "ec2", "target": "r2", "type": "instance_role", "original_edge_type": "instance_role", "permission": "", "source_tool": "iamhounddog"},
    ]
    if include_passrole:
        edges.append({"fact_id": "f5", "source": "p", "target": "r2", "type": "has_permission", "original_edge_type": "has_permission", "permission": "iam:PassRole", "source_tool": "iamhounddog"})
    return FactGraphInput(nodes=nodes, edges=edges)


def test_iamhounddog_complete_pattern():
    result = IamHoundDogAdapter().convert(graph(), Layer2Config())
    operator = result.operators[0]
    assert operator.status == "complete"
    assert operator.source_node == "p"
    assert operator.target_node == "r2"
    assert operator.source_fact_ids == ["f1", "f2", "f3", "f4", "f5"]
    assert operator.produces[0].subject_node_id == "r2"


def test_iamhounddog_partial_pattern_records_missing_permission():
    result = IamHoundDogAdapter().convert(graph(include_passrole=False), Layer2Config())
    assert result.operators[0].status == "partial"
    assert result.operators[0].missing_conditions == ["iam:PassRole"]


def test_iamhounddog_hop_and_match_limits_are_bounded():
    hop_result = IamHoundDogAdapter().convert(graph(), Layer2Config(max_hops=3))
    assert not hop_result.operators
    assert hop_result.unresolved_items[0].type == "aws.ec2.passrole.v1"
    match_result = IamHoundDogAdapter().convert(graph(), Layer2Config(max_matches_per_rule=1))
    assert len(match_result.operators) == 1


def test_iamhounddog_adds_rules_from_multiple_files(tmp_path):
    first_rule = tmp_path / "first.yaml"
    first_rule.write_text(
        """
version: "1.0"
rules:
  - id: custom.assume_role.v1
    version: "1"
    source_tool: iamhounddog
    pattern:
      - from_type: principal
        edge_type: assume_role
        to_type: role
        bind_from_as: source_principal
        bind_to_as: target_role
    operator:
      type: assume_role_identity
      produces:
        - artifact_type: identity
          subject_node_ref: target_role
""",
        encoding="utf-8",
    )
    second_rule = tmp_path / "second.yaml"
    second_rule.write_text(
        """
id: custom.attached_policy.v1
version: "1"
source_tool: iamhounddog
pattern:
  - from_type: role
    edge_type: attached_policy
    to_type: policy
    bind_from_as: source_principal
    bind_to_as: target_role
operator:
  type: inspect_attached_policy
""",
        encoding="utf-8",
    )

    result = IamHoundDogAdapter().convert(
        graph(),
        Layer2Config(iamhounddog_rule_paths=[first_rule, second_rule]),
    )

    assert {operator.operator_type for operator in result.operators} == {
        "assume_role_identity",
        "inspect_attached_policy",
        "launch_instance_with_role",
    }
    assert all(operator.metadata["rule_set_hash"] for operator in result.operators)


def test_pattern_loader_rejects_duplicate_rule_ids(tmp_path):
    duplicate_rule = tmp_path / "duplicate.yaml"
    duplicate_rule.write_text(
        """
id: aws.ec2.passrole.v1
version: "2"
source_tool: iamhounddog
pattern: []
operator:
  type: duplicate
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate IAMHoundDog rule id"):
        load_pattern_rules([DEFAULT_PATTERN_PATH, duplicate_rule])


def test_iamhounddog_required_permissions_do_not_mix_source_tools():
    mixed = graph(include_passrole=False)
    mixed.edges.append(
        {
            "fact_id": "foreign",
            "source": "p",
            "target": "r2",
            "type": "has_permission",
            "permission": "iam:PassRole",
            "source_tool": "gcp_hound",
        }
    )

    result = IamHoundDogAdapter().convert(mixed, Layer2Config())

    assert result.operators[0].status == "partial"
    assert result.operators[0].missing_conditions == ["iam:PassRole"]
    assert "foreign" not in result.operators[0].source_fact_ids
