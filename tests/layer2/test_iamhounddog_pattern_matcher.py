from capra.layer2.adapters.iamhounddog_adapter import IamHoundDogAdapter
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
