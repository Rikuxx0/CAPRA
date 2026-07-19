import requests

from capra.layer2.nvd.client import NVD_ENDPOINT, NvdClient
from tests.layer2.test_nvd_parser import sample_payload


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return sample_payload()


class FakeSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


def test_nvd_client_sets_timeout_and_never_visits_reference_links(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "test-placeholder-not-a-real-key")
    session = FakeSession()
    payload = NvdClient(timeout_seconds=3.5, max_retries=0, rate_limit_seconds=0, session=session).fetch("CVE-2024-1234")
    assert payload["vulnerabilities"]
    assert len(session.calls) == 1
    assert session.calls[0][0] == NVD_ENDPOINT
    assert session.calls[0][1]["timeout"] == 3.5
    assert session.calls[0][1]["params"] == {"cveId": "CVE-2024-1234"}
    assert "example.invalid" not in session.calls[0][0]
