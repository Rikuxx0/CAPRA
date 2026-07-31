import json
from datetime import datetime, timezone
from pathlib import Path

from capra.layer2.exporter import export_attack_operator_graph_json, serialize_attack_operator_graph_json
from capra.layer2.nvd.cache import NvdCache
from capra.layer2.schemas import AttackOperatorGraphModel, Layer2Config
from capra.layer2.service import build_attack_operator_graph
from examples.regenerate import _build_layer1_payload, _build_layer2_payload
from tests.layer2.test_nvd_parser import sample_payload


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


def test_service_uses_additional_direct_edge_rules(tmp_path):
    rule_path = tmp_path / "gcp_rules.yaml"
    rule_path.write_text(
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
    fact_graph = {
        "nodes": [{"id": "p"}, {"id": "project"}],
        "edges": [
            {
                "id": "g1",
                "source": "p",
                "target": "project",
                "type": "CanDisableAuditLogs",
                "source_tool": "gcp_hound",
                "provider": "gcp",
            }
        ],
    }

    graph = build_attack_operator_graph(
        fact_graph,
        Layer2Config(gcp_hound_rule_paths=[rule_path]),
    )

    assert [operator.operator_type for operator in graph.attack_operators] == [
        "disable_audit_logs"
    ]
    assert graph.metadata["edge_classification_counts"]["ATTACK_EDGE"] == 1


def test_service_connects_generic_hound_path_to_cve(tmp_path):
    NvdCache(tmp_path).write(
        "CVE-2024-1234",
        sample_payload(),
        datetime.now(timezone.utc),
    )
    fact_graph = {
        "nodes": [
            {"id": "aws:user:reader", "type": "user", "cloud": "aws"},
            {"id": "aws:role:admin", "type": "role", "cloud": "aws"},
            {
                "id": "k8s:pod:backend",
                "type": "container",
                "cloud": "k8s",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1234",
                        "cve_id": "CVE-2024-1234",
                        "package_name": "product",
                        "installed_version": "1.2",
                    }
                ],
            },
        ],
        "edges": [
            {
                "source": "aws:user:reader",
                "target": "aws:role:admin",
                "type": "assume_role",
                "original_edge_type": "sts:AssumeRole",
                "permission": "sts:AssumeRole",
                "source_tool": "unknown",
            },
            {
                "source": "aws:role:admin",
                "target": "k8s:pod:backend",
                "type": "network_access",
                "original_edge_type": "network",
                "permission": "network",
                "source_tool": "unknown",
            },
        ],
    }

    graph = build_attack_operator_graph(
        fact_graph,
        Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"),
    )

    assert {operator.operator_type for operator in graph.attack_operators} == {
        "assume_aws_role",
        "reach_network_target",
        "command_injection",
    }
    assert len(graph.connections) == 5
    assert graph.metadata["used_source_tools"] == ["hound_generic", "nvd"]
    assert not graph.unresolved_items


def test_layer2_examples_form_a_consistent_attack_path(tmp_path):
    example_directory = Path("examples/layer2")
    for cve_id in ("CVE-2022-0778", "CVE-2021-44228"):
        response = json.loads(
            (example_directory / f"nvd/{cve_id}.json").read_text()
        )
        NvdCache(tmp_path).write(
            cve_id,
            response,
            datetime.now(timezone.utc),
        )
    fact_graph = json.loads(
        (example_directory / "fact_graph_sample.json").read_text()
    )

    graph = build_attack_operator_graph(
        fact_graph,
        Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"),
    )
    saved_graph = AttackOperatorGraphModel.model_validate_json(
        (example_directory / "attack_operator_graph_sample.json").read_text()
    )

    operator_types = {
        operator.operator_type for operator in graph.attack_operators
    }
    assert len(graph.attack_operators) == 17
    assert {
        "launch_instance_with_role",
        "reach_network_target",
        "obtain_mounted_service_account",
        "read_kubernetes_secret",
        "impersonate_service_account",
        "add_application_secret",
        "denial_of_service",
        "remote_code_execution",
    } <= operator_types
    cve_operators = {
        operator.cve_ids[0]: operator
        for operator in graph.attack_operators
        if operator.origin_kind == "cve"
    }
    assert set(cve_operators) == {"CVE-2022-0778", "CVE-2021-44228"}
    assert all(
        operator.metadata["package_matches_nvd_product"] is True
        for operator in cve_operators.values()
    )
    assert len(graph.connections) == 24
    assert graph.metadata["used_source_tools"] == [
        "azurehound",
        "clusterhound",
        "gcp_hound",
        "hound_generic",
        "iamhounddog",
        "nvd",
    ]
    assert not graph.unresolved_items
    assert len(saved_graph.attack_operators) == 17
    assert len(saved_graph.connections) == 24


def test_generated_example_outputs_are_up_to_date():
    layer1_payload = _build_layer1_payload()
    saved_layer1 = json.loads(
        Path("examples/layer1/fact_graph_sample.json").read_text()
    )
    saved_layer2_input = json.loads(
        Path("examples/layer2/fact_graph_sample.json").read_text()
    )
    saved_layer2_output = json.loads(
        Path("examples/layer2/attack_operator_graph_sample.json").read_text()
    )

    assert layer1_payload == saved_layer1 == saved_layer2_input
    assert _build_layer2_payload(layer1_payload) == saved_layer2_output
