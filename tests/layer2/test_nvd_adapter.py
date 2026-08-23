from datetime import datetime, timezone

import pytest

from capra.layer2.nvd.cache import NvdCache
from capra.layer2.nvd_adapter import (
    DEFAULT_RULE_PATH,
    classify_description,
    convert_cves,
    load_cve_rules,
)
from capra.layer2.schemas import FactGraphInput, Layer2Config
from tests.layer2.test_nvd_parser import sample_payload


def test_description_rules_are_specific_deterministic_and_fallback():
    rules, _, _ = load_cve_rules()
    assert classify_description("COMMAND INJECTION can cause denial of service", rules)[0] == "command_injection"
    assert classify_description("An attacker can execute arbitrary code", rules)[0] == "remote_code_execution"
    assert classify_description("unclassified weakness", rules) == ("exploit_vulnerable_component", None)


def test_cache_only_cve_operator_is_partial_and_never_fetches(tmp_path):
    NvdCache(tmp_path).write("CVE-2024-1234", sample_payload(), datetime.now(timezone.utc))
    graph = FactGraphInput(nodes=[{
        "id": "gcp:service:web", "cloud": "gcp", "vulnerabilities": [{"id": "CVE-2024-1234", "cve_id": "CVE-2024-1234", "installed_version": "1.2"}]
    }])
    result = convert_cves(graph, Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"))
    operator = result.operators[0]
    assert operator.operator_type == "command_injection"
    assert operator.status == "partial"
    assert operator.verification_status == "unverified"
    assert operator.public_exploit_candidate is True
    assert operator.manual_verification_required is True
    assert operator.missing_conditions == ["target_is_reachable", "vulnerable_version_is_running"]
    assert result.statistics["cache_hit"] == 1


def test_cache_only_miss_is_unresolved(tmp_path):
    graph = FactGraphInput(unmapped_vulnerabilities=[{"id": "CVE-2024-1234", "cve_id": "CVE-2024-1234"}])
    result = convert_cves(graph, Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"))
    assert not result.operators
    assert result.unresolved_items[0].type == "nvd_fetch_failure"


def test_unmapped_cve_with_cache_is_preserved_as_unresolved_operator_and_item(tmp_path):
    NvdCache(tmp_path).write(
        "CVE-2024-1234",
        sample_payload(),
        datetime.now(timezone.utc),
    )
    graph = FactGraphInput(
        unmapped_vulnerabilities=[
            {"id": "CVE-2024-1234", "cve_id": "CVE-2024-1234"}
        ]
    )

    result = convert_cves(
        graph,
        Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"),
    )

    assert result.operators[0].status == "unresolved"
    assert result.operators[0].target_node is None
    assert "target_node" in result.operators[0].missing_conditions
    assert {item.type for item in result.unresolved_items} == {"unmapped_cve_target"}


def test_cache_then_fetch_uses_injected_client_and_populates_cache(tmp_path):
    class FakeClient:
        calls = []

        def fetch(self, cve_id):
            self.calls.append(cve_id)
            return sample_payload()

    client = FakeClient()
    graph = FactGraphInput(nodes=[{"id": "target", "vulnerabilities": [{"id": "CVE-2024-1234", "cve_id": "CVE-2024-1234"}]}])
    result = convert_cves(
        graph,
        Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-then-fetch"),
        client=client,
    )
    assert client.calls == ["CVE-2024-1234"]
    assert result.operators
    assert NvdCache(tmp_path).read("CVE-2024-1234").status == "hit"


def test_cve_loader_adds_rules_from_multiple_files(tmp_path):
    first_rules = tmp_path / "first.yaml"
    first_rules.write_text(
        """
version: "1.0"
rules:
  - id: cve.server_side_request_forgery.v1
    phrase: server-side request forgery
    operator_type: server_side_request_forgery
""",
        encoding="utf-8",
    )
    second_rules = tmp_path / "second.yaml"
    second_rules.write_text(
        """
version: "1.1"
rules:
  - id: cve.xml_external_entity.v1
    phrase: XML external entity
    operator_type: xml_external_entity
""",
        encoding="utf-8",
    )

    rules, version, rule_hash = load_cve_rules(
        [DEFAULT_RULE_PATH, first_rules, second_rules]
    )

    assert classify_description("A server-side request forgery issue", rules) == (
        "server_side_request_forgery",
        "cve.server_side_request_forgery.v1",
    )
    assert classify_description("An XML EXTERNAL ENTITY issue", rules) == (
        "xml_external_entity",
        "cve.xml_external_entity.v1",
    )
    assert version == "0.1.0,1.0,1.1"
    assert rule_hash


def test_cve_loader_rejects_duplicate_rule_id(tmp_path):
    duplicate_rules = tmp_path / "duplicate.yaml"
    duplicate_rules.write_text(
        """
version: "2.0"
rules:
  - id: cve.command_injection.v1
    phrase: custom command execution
    operator_type: custom_command_execution
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate CVE operator rule id"):
        load_cve_rules([DEFAULT_RULE_PATH, duplicate_rules])


def test_cve_package_mismatch_requires_manual_verification(tmp_path):
    NvdCache(tmp_path).write(
        "CVE-2024-1234",
        sample_payload(),
        datetime.now(timezone.utc),
    )
    graph = FactGraphInput(
        nodes=[
            {
                "id": "k8s:pod:backend",
                "cloud": "k8s",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1234",
                        "cve_id": "CVE-2024-1234",
                        "package_name": "openssl",
                        "installed_version": "1.2",
                    }
                ],
            }
        ]
    )

    result = convert_cves(
        graph,
        Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"),
    )

    operator = result.operators[0]
    assert "package_matches_nvd_product" in operator.missing_conditions
    assert operator.manual_verification_required is True
    assert operator.metadata["package_matches_nvd_product"] is False
    assert result.unresolved_items[0].type == "cve_package_mismatch"
    assert result.warnings
