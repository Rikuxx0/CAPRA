from datetime import datetime, timezone

from capra.layer2.nvd.cache import NvdCache
from capra.layer2.nvd_adapter import classify_description, convert_cves, load_cve_rules
from capra.layer2.schemas import FactGraphInput, Layer2Config
from tests.layer2.test_nvd_parser import sample_payload


def test_description_rules_are_specific_deterministic_and_fallback():
    rules, _, _ = load_cve_rules()
    assert classify_description("COMMAND INJECTION can cause denial of service", rules)[0] == "command_injection"
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
    assert operator.missing_conditions == ["target_is_reachable"]
    assert result.statistics["cache_hit"] == 1


def test_cache_only_miss_is_unresolved(tmp_path):
    graph = FactGraphInput(unmapped_vulnerabilities=[{"id": "CVE-2024-1234", "cve_id": "CVE-2024-1234"}])
    result = convert_cves(graph, Layer2Config(nvd_cache_directory=tmp_path, nvd_mode="cache-only"))
    assert not result.operators
    assert result.unresolved_items[0].type == "nvd_fetch_failure"


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
