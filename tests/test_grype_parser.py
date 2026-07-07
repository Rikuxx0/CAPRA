import json
from pathlib import Path

from capra.layer1.parsers.grype_parser import parse_grype_json


# サンプルの Grype JSON から主要な脆弱性属性が正しく抽出されることを確認する。
def test_parse_grype_json():
    data = json.loads(Path("examples/layer1/grype_sample.json").read_text())
    vulnerabilities = parse_grype_json(data)

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].cve_id == "CVE-2023-1234"
    assert vulnerabilities[0].package_name == "openssl"
    assert vulnerabilities[0].installed_version == "1.1.1"
    assert vulnerabilities[0].fixed_version == "1.2.3"
    assert vulnerabilities[0].severity == "High"


# vulnerability.id が GHSA でも aliases 側の CVE を抽出できることを確認する。
def test_parse_grype_json_extracts_cve_from_aliases():
    data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-abcd-efgh-ijkl",
                    "severity": "High",
                    "aliases": ["CVE-2024-12345"],
                },
                "artifact": {"name": "openssl"},
            }
        ]
    }

    vulnerabilities = parse_grype_json(data)

    assert vulnerabilities[0].id == "GHSA-abcd-efgh-ijkl"
    assert vulnerabilities[0].cve_id == "CVE-2024-12345"
