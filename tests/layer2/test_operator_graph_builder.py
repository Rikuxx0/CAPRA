from capra.layer2.operator_graph_builder import build_networkx_operator_graph, build_operator_connections
from capra.layer2.schemas import AttackOperatorModel, OperatorArtifactModel


def operator(identifier, source=None, target=None, produces=None, requires=None):
    return AttackOperatorModel(
        id=identifier, operator_type="test", origin_kind="iam_direct_edge", source_tool="test", status="complete",
        source_node=source, target_node=target, produces=produces or [], requires=requires or [],
    )


def test_node_and_artifact_connections_and_deduplication():
    identity = OperatorArtifactModel(artifact_type="identity", subject_node_id="role")
    operators = [operator("a", target="middle", produces=[identity]), operator("b", source="middle", requires=[identity])]
    connections, warnings = build_operator_connections(operators, 10)
    assert not warnings
    assert {(item.connection_type, item.metadata["match_method"]) for item in connections} == {
        ("enables", "node"), ("enables", "artifact"), ("requires", "artifact")
    }
    graph = build_networkx_operator_graph(operators, connections)
    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 3


def test_unknown_artifact_subject_does_not_connect_and_limit_is_safe():
    unknown = OperatorArtifactModel(artifact_type="identity")
    operators = [operator("a", produces=[unknown]), operator("b", requires=[unknown])]
    connections, _ = build_operator_connections(operators, 1)
    assert connections == []
