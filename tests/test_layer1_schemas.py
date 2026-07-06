from pydantic import ValidationError

from capra.layer1.schemas import EdgeModel, NodeModel, VulnerabilityModel
from capra.layer1.severity import normalize_severity


def test_severity_normalization():
    assert normalize_severity("Critical") == ("Critical", 1.0)
    assert normalize_severity("moderate") == ("Medium", 0.5)
    assert normalize_severity("unexpected") == ("Unknown", 0.0)


def test_node_schema_validation():
    node = NodeModel(id="n1", name="node", cloud="not-a-cloud", importance=0.5)
    assert node.cloud == "unknown"

    try:
        NodeModel(id="n2", name="node", importance=1.5)
    except ValidationError:
        pass
    else:
        raise AssertionError("importance > 1.0 should fail")


def test_edge_schema_validation():
    edge = EdgeModel(source="a", target="b", provider="not-a-cloud", strength=0.7)
    assert edge.provider == "unknown"

    try:
        EdgeModel(source="a", target="b", strength=2.0)
    except ValidationError:
        pass
    else:
        raise AssertionError("strength > 1.0 should fail")


def test_vulnerability_schema_sets_score():
    vulnerability = VulnerabilityModel(id="CVE-2023-1234", severity="High")
    assert vulnerability.severity == "High"
    assert vulnerability.severity_score == 0.8
