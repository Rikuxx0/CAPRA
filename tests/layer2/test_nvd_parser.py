from capra.layer2.nvd.parser import parse_nvd_response


def sample_payload():
    return {
        "vulnerabilities": [{"cve": {
            "id": "CVE-2024-1234",
            "descriptions": [{"lang": "en", "value": "A command injection and denial of service issue."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "NONE",
                "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH", "availabilityImpact": "HIGH",
            }}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
            "references": [{"url": "https://example.invalid/advisory", "tags": ["Exploit"]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.2:*:*:*:*:*:*:*"}]}]}],
        }}]
    }


def test_nvd_response_parse_cvss_cwe_reference_and_cpe():
    record = parse_nvd_response(sample_payload(), "CVE-2024-1234")
    assert record.cvss_score == 9.8
    assert record.attack_vector == "network"
    assert record.cwe_ids == ["CWE-78"]
    assert record.public_exploit_candidate is True
    assert record.products == ["vendor:product"]
    assert record.versions == ["1.2"]
