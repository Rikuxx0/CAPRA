import json
from pathlib import Path

from capra.layer1.parsers.grype_parser import parse_grype_json, parse_grype_sarif


# サンプルの Grype JSON から主要な脆弱性属性が正しく抽出されることを確認する。
def test_parse_grype_json():
    data = json.loads(Path("examples/layer1/grype_sample.json").read_text())
    vulnerabilities = parse_grype_json(data)

    assert len(vulnerabilities) == 2
    by_cve = {vulnerability.cve_id: vulnerability for vulnerability in vulnerabilities}
    assert by_cve["CVE-2022-0778"].package_name == "openssl"
    assert by_cve["CVE-2022-0778"].installed_version == "1.1.1m"
    assert by_cve["CVE-2022-0778"].fixed_version == "1.1.1n"
    assert by_cve["CVE-2022-0778"].severity == "High"
    assert by_cve["CVE-2021-44228"].package_name == "log4j-core"
    assert by_cve["CVE-2021-44228"].installed_version == "2.14.1"
    assert by_cve["CVE-2021-44228"].fixed_version == "2.15.0"
    assert by_cve["CVE-2021-44228"].severity == "Critical"


def test_parse_grype_sarif_sample_is_consistent_with_json_sample():
    data = json.loads(Path("examples/layer1/grype_sample.sarif").read_text())
    vulnerabilities = parse_grype_sarif(data)

    assert len(vulnerabilities) == 2
    by_cve = {vulnerability.cve_id: vulnerability for vulnerability in vulnerabilities}
    assert by_cve["CVE-2022-0778"].package_name == "openssl"
    assert by_cve["CVE-2022-0778"].installed_version == "1.1.1m"
    assert by_cve["CVE-2022-0778"].fixed_version == "1.1.1n"
    assert by_cve["CVE-2022-0778"].severity == "High"
    assert by_cve["CVE-2021-44228"].package_name == "log4j-core"
    assert by_cve["CVE-2021-44228"].installed_version == "2.14.1"
    assert by_cve["CVE-2021-44228"].fixed_version == "2.15.0"
    assert by_cve["CVE-2021-44228"].severity == "Critical"


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
