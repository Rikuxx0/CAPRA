import pytest

from capra.layer2.adapters.azurehound_adapter import AzureHoundAdapter
from capra.layer2.adapters.clusterhound_adapter import ClusterHoundAdapter
from capra.layer2.adapters.gcp_hound_adapter import GcpHoundAdapter
from capra.layer2.adapters.hound_generic_adapter import HoundGenericAdapter
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


def test_direct_adapter_adds_mappings_from_multiple_files(tmp_path):
    attack_rules = tmp_path / "attack_rules.yaml"
    attack_rules.write_text(
        """
version: "1.0"
mappings:
  CanDisableAuditLogs:
    rule_id: gcp_hound.candisableauditlogs.v1
    classification: ATTACK_EDGE
    operator_type: disable_audit_logs
    effects: [audit_logging_disabled]
    produces: [resource_control]
""",
        encoding="utf-8",
    )
    relationship_rules = tmp_path / "relationship_rules.yaml"
    relationship_rules.write_text(
        """
version: "1.1"
mappings:
  CustomContains:
    rule_id: gcp_hound.customcontains.v1
    classification: RELATIONSHIP
""",
        encoding="utf-8",
    )
    adapter = GcpHoundAdapter(rule_paths=[attack_rules, relationship_rules])
    graph = FactGraphInput(
        edges=[
            edge("gcp_hound", "CanCreateKeys"),
            edge("gcp_hound", "CanDisableAuditLogs", "f2"),
            edge("gcp_hound", "CustomContains", "f3"),
        ]
    )

    result = adapter.convert(graph, Layer2Config())

    assert {operator.operator_type for operator in result.operators} == {
        "create_service_account_key",
        "disable_audit_logs",
    }
    assert adapter.classify_edge(graph.edges[2]) == EdgeClassification.RELATIONSHIP
    assert result.operators[0].metadata["rule_set_version"] == "0.1.0,1.0,1.1"


def test_direct_adapter_rejects_duplicate_edge_mapping(tmp_path):
    duplicate_rules = tmp_path / "duplicate_rules.yaml"
    duplicate_rules.write_text(
        """
version: "2.0"
mappings:
  CanCreateKeys:
    rule_id: custom.duplicate.v1
    classification: ATTACK_EDGE
    operator_type: duplicate
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate gcp_hound edge mapping"):
        GcpHoundAdapter(rule_paths=[duplicate_rules])


def test_generic_hound_rules_produce_identity_and_network_reachability():
    adapter = HoundGenericAdapter()
    graph = FactGraphInput(
        nodes=[
            {"id": "principal", "cloud": "aws"},
            {"id": "target", "cloud": "aws"},
        ],
        edges=[
            edge("hound_generic", "sts:AssumeRole"),
            edge("hound_generic", "network", "f2"),
        ]
    )

    result = adapter.convert(graph, Layer2Config())
    operators = {operator.operator_type: operator for operator in result.operators}

    assume_role = operators["assume_aws_role"]
    assert assume_role.status == "partial"
    assert assume_role.manual_verification_required is True
    assert assume_role.produces[0].artifact_type == "identity"
    assert assume_role.metadata["provider"] == "aws"
    network = operators["reach_network_target"]
    assert network.status == "partial"
    assert network.requires[0].artifact_type == "identity"
    assert network.produces[0].artifact_type == "network_reachability"
