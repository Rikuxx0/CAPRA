from capra.layer2.operator_graph_builder import extract_layer3_candidates
from capra.layer2.schemas import AttackOperatorModel


def make(identifier, status, target):
    return AttackOperatorModel(id=identifier, operator_type="x", origin_kind="iam_direct_edge", source_tool="x", status=status, target_node=target)


def test_layer3_candidates_include_complete_partial_and_exclude_unresolved_or_unknown_target():
    candidates, limited = extract_layer3_candidates(
        [make("complete", "complete", "node"), make("partial", "partial", "node"), make("unresolved", "unresolved", "node"), make("unknown", "complete", "unknown")],
        10,
    )
    assert candidates == ["complete", "partial"]
    assert limited is False
