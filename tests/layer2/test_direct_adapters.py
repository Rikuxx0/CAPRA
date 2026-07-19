from capra.layer2.adapters.azurehound_adapter import AzureHoundAdapter
from capra.layer2.adapters.clusterhound_adapter import ClusterHoundAdapter
from capra.layer2.adapters.gcp_hound_adapter import GcpHoundAdapter
from capra.layer2.schemas import EdgeClassification, FactGraphInput, Layer2Config


def edge(tool, edge_type, fact_id="f1"):
    return {
        "source": "principal", "target": "target", "type": edge_type.lower(), "original_edge_type": edge_type,
        "provider": "unknown", "source_tool": tool, "fact_id": fact_id, "raw_evidence": {"type": edge_type},
    }


def test_azure_direct_relationship_and_unknown():
    adapter = AzureHoundAdapter()
    graph = FactGraphInput(edges=[edge("azurehound", "AZAddSecret"), edge("azurehound", "AZContains", "f2"), edge("azurehound", "AZMystery", "f3")])
    result = adapter.convert(graph, Layer2Config())
    assert result.operators[0].operator_type == "add_application_secret"
    assert result.operators[0].mapping_rule_id == "azurehound.azaddsecret.v1"
    assert result.operators[0].metadata["original_edge_type"] == "AZAddSecret"
    assert adapter.classify_edge(graph.edges[1]) == EdgeClassification.RELATIONSHIP
    assert result.unresolved_items[0].type == "unknown_edge"


def test_gcp_direct_and_relationship_and_can_list_keys_permission():
    adapter = GcpHoundAdapter()
    graph = FactGraphInput(edges=[edge("gcp_hound", "CanCreateKeys"), edge("gcp_hound", "BelongsTo", "f2"), edge("gcp_hound", "CanListKeys", "f3")])
    result = adapter.convert(graph, Layer2Config())
    assert [operator.operator_type for operator in result.operators] == ["create_service_account_key"]
    assert {artifact.artifact_type for artifact in result.operators[0].produces} == {"credential", "identity"}
    assert adapter.classify_edge(graph.edges[1]) == EdgeClassification.RELATIONSHIP
    assert adapter.classify_edge(graph.edges[2]) == EdgeClassification.PERMISSION


def test_cluster_direct_manual_verification_and_entry_point():
    adapter = ClusterHoundAdapter()
    graph = FactGraphInput(edges=[edge("clusterhound", "canExec"), edge("clusterhound", "unauthAPIAccess", "f2"), edge("clusterhound", "entryPoint", "f3")])
    result = adapter.convert(graph, Layer2Config())
    assert {operator.operator_type for operator in result.operators} == {"exec_in_workload", "access_unauthenticated_kubernetes_api"}
    manual = next(operator for operator in result.operators if operator.manual_verification_required)
    assert manual.status == "partial"
    assert "anonymous_authentication_is_enabled" in manual.missing_conditions
    assert adapter.classify_edge(graph.edges[2]) == EdgeClassification.RELATIONSHIP
