from capra.layer1.schemas import EdgeModel, NodeModel, VulnerabilityModel
from capra.layer1.severity import normalize_severity


# severity の別名や未知値が期待する正規化結果になることを確認する。
def test_severity_normalization():
    assert normalize_severity("Critical") == "Critical"
    assert normalize_severity("moderate") == "Medium"
    assert normalize_severity("unexpected") == "Unknown"


# NodeModel がクラウド正規化を行うことを確認する。
def test_node_schema_validation():
    node = NodeModel(id="n1", name="node", cloud="not-a-cloud")
    assert node.cloud == "unknown"


# EdgeModel が provider 正規化を行うことを確認する。
def test_edge_schema_validation():
    edge = EdgeModel(source="a", target="b", provider="not-a-cloud")
    assert edge.provider == "unknown"


# VulnerabilityModel が severity を正規化することを確認する。
def test_vulnerability_schema_normalizes_severity():
    vulnerability = VulnerabilityModel(id="CVE-2023-1234", severity="High")
    assert vulnerability.severity == "High"
