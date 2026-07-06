import json
from pathlib import Path

from capra.layer1.parsers.grype_parser import parse_grype_json


def test_parse_grype_json():
    data = json.loads(Path("examples/layer1/grype_sample.json").read_text())
    vulnerabilities = parse_grype_json(data)

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].cve_id == "CVE-2023-1234"
    assert vulnerabilities[0].package_name == "openssl"
    assert vulnerabilities[0].installed_version == "1.1.1"
    assert vulnerabilities[0].fixed_version == "1.2.3"
    assert vulnerabilities[0].severity_score == 0.8
