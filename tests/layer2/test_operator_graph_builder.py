from capra.layer2.operator_graph_builder import build_networkx_operator_graph, build_operator_connections
from capra.layer2.schemas import AttackOperatorModel, OperatorArtifactModel


def operator(identifier, source=None, target=None, produces=None, requires=None, effects=None, preconditions=None, operator_type="test"):
    return AttackOperatorModel(
        id=identifier, operator_type=operator_type, origin_kind="iam_direct_edge", source_tool="test", status="complete",
        source_node=source, target_node=target, produces=produces or [], requires=requires or [],
        effects=effects or [], preconditions=preconditions or [],
    )


def test_node_match_alone_does_not_create_connection():
    connections, warnings = build_operator_connections(
        [operator("a", target="middle"), operator("b", source="middle")],
        10,
    )
    assert connections == []
    assert warnings == []


def test_produced_identity_enables_identity_required_operator_and_deduplicates():
    identity = OperatorArtifactModel(artifact_type="identity", subject_node_id="role")
    operators = [operator("a", produces=[identity, identity]), operator("b", requires=[identity, identity])]
    connections, warnings = build_operator_connections(operators, 10)
    assert not warnings
    assert [(item.connection_type, item.metadata["match_method"]) for item in connections] == [
        ("enables", "artifact")
    ]
    graph = build_networkx_operator_graph(operators, connections)
    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1


def test_produced_credential_and_network_reachability_match_requirements():
    credential = OperatorArtifactModel(artifact_type="credential", subject_node_id="identity")
    reachability = OperatorArtifactModel(artifact_type="network_reachability", subject_node_id="service")
    operators = [
        operator("credential-source", produces=[credential]),
        operator("credential-target", requires=[credential]),
        operator("network-source", produces=[reachability]),
        operator("network-target", requires=[reachability]),
    ]
    connections, _ = build_operator_connections(operators, 10)
    enabled_pairs = {
        (item.source_operator_id, item.target_operator_id)
        for item in connections
        if item.connection_type == "enables"
    }
    assert enabled_pairs == {
        ("credential-source", "credential-target"),
        ("network-source", "network-target"),
    }


def test_effect_satisfies_matching_precondition():
    connections, _ = build_operator_connections(
        [
            operator("a", effects=["target_role_identity_obtained"]),
            operator("b", preconditions=["TARGET_ROLE_IDENTITY_OBTAINED"]),
        ],
        10,
    )
    assert len(connections) == 1
    assert connections[0].condition == "TARGET_ROLE_IDENTITY_OBTAINED"
    assert connections[0].metadata["match_method"] == "condition"


def test_dos_does_not_enable_credential_acquisition_from_node_context():
    connections, _ = build_operator_connections(
        [
            operator("dos", target="pod", effects=["service_unavailable"], operator_type="denial_of_service"),
            operator("credential", source="pod", preconditions=["workload_controlled"], operator_type="obtain_credential"),
        ],
        10,
    )
    assert connections == []


def test_mismatched_artifact_subject_does_not_connect():
    produced = OperatorArtifactModel(artifact_type="identity", subject_node_id="role-a")
    required = OperatorArtifactModel(artifact_type="identity", subject_node_id="role-b")
    connections, _ = build_operator_connections(
        [operator("a", produces=[produced]), operator("b", requires=[required])],
        10,
    )
    assert connections == []


def test_unknown_artifact_subject_does_not_connect_and_limit_is_safe():
    unknown = OperatorArtifactModel(artifact_type="identity")
    operators = [operator("a", produces=[unknown]), operator("b", requires=[unknown])]
    connections, _ = build_operator_connections(operators, 1)
    assert connections == []
