from capra.layer2.exporter import export_attack_operator_graph_json, serialize_attack_operator_graph_json
from capra.layer2.schemas import AttackOperatorGraphModel, Layer2Config
from capra.layer2.service import build_attack_operator_graph


def test_nvd_failure_does_not_stop_iam_processing(tmp_path):
    fact_graph = {
        "nodes": [{"id": "p", "type": "principal"}, {"id": "sa", "type": "serviceaccount", "vulnerabilities": [{"id": "CVE-2024-9999", "cve_id": "CVE-2024-9999"}]}],
        "edges": [{"id": "g1", "source": "p", "target": "sa", "type": "CanCreateKeys", "source_tool": "gcp_hound", "provider": "gcp"}],
        "metadata": {"schema_version": "0.1"},
    }
    graph = build_attack_operator_graph(fact_graph, Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"))
    assert any(operator.operator_type == "create_service_account_key" for operator in graph.attack_operators)
    assert any(item.type == "nvd_fetch_failure" for item in graph.unresolved_items)
    assert graph.metadata["nvd_cache_miss_count"] == 1
    AttackOperatorGraphModel.model_validate(export_attack_operator_graph_json(graph))
    assert "NVD_API_KEY" not in serialize_attack_operator_graph_json(graph)


def test_same_input_produces_same_stable_content(tmp_path):
    fact_graph = {
        "nodes": [{"id": "p"}, {"id": "sa"}],
        "edges": [{"id": "g1", "source": "p", "target": "sa", "type": "CanImpersonate", "source_tool": "gcp_hound", "provider": "gcp"}],
    }
    config = Layer2Config(nvd_cache_directory=tmp_path)
    first = export_attack_operator_graph_json(build_attack_operator_graph(fact_graph, config))
    second = export_attack_operator_graph_json(build_attack_operator_graph(fact_graph, config))
    for payload in (first, second):
        payload["metadata"].pop("generated_at")
        payload["metadata"].pop("processing_time_ms")
    assert first == second
