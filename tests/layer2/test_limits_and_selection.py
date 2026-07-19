from capra.layer2.schemas import Layer2Config
from capra.layer2.service import build_attack_operator_graph


def test_source_tool_operator_type_and_operator_limits(tmp_path):
    fact_graph = {
        "nodes": [{"id": "p"}, {"id": "a"}, {"id": "b"}],
        "edges": [
            {"id": "g1", "source": "p", "target": "a", "type": "CanCreateKeys", "source_tool": "gcp_hound", "provider": "gcp"},
            {"id": "g2", "source": "p", "target": "b", "type": "CanImpersonate", "source_tool": "gcp_hound", "provider": "gcp"},
            {"id": "a1", "source": "p", "target": "b", "type": "AZAddSecret", "source_tool": "azurehound", "provider": "azure"},
        ],
    }
    selected = build_attack_operator_graph(
        fact_graph,
        Layer2Config(nvd_cache_directory=tmp_path, selected_source_tools=["gcp_hound"], selected_operator_types=["create_service_account_key"]),
    )
    assert [operator.operator_type for operator in selected.attack_operators] == ["create_service_account_key"]

    limited = build_attack_operator_graph(
        fact_graph,
        Layer2Config(nvd_cache_directory=tmp_path, selected_source_tools=["gcp_hound"], max_total_operators=1),
    )
    assert len(limited.attack_operators) == 1
    assert limited.metadata["limit_reached"].get("max_total_operators") == 1


def test_connection_and_candidate_limits_are_recorded(tmp_path):
    fact_graph = {
        "nodes": [{"id": "p"}, {"id": "middle"}, {"id": "target"}],
        "edges": [
            {"id": "g1", "source": "p", "target": "middle", "type": "CanImpersonate", "source_tool": "gcp_hound", "provider": "gcp"},
            {"id": "g2", "source": "middle", "target": "target", "type": "CanCreateKeys", "source_tool": "gcp_hound", "provider": "gcp"},
            {"id": "g3", "source": "middle", "target": "target", "type": "CanImpersonate", "source_tool": "gcp_hound", "provider": "gcp"},
        ],
    }
    graph = build_attack_operator_graph(
        fact_graph,
        Layer2Config(nvd_cache_directory=tmp_path, selected_source_tools=["gcp_hound"], max_connections=1, max_candidates=1),
    )
    assert len(graph.connections) == 1
    assert len(graph.layer3_candidates) == 1
    assert graph.metadata["limit_reached"]["max_connections"] == 1
    assert graph.metadata["limit_reached"]["max_candidates"] == 1
