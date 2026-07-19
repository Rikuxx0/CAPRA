from capra.layer2.edge_classifier import classify_edge
from capra.layer2.schemas import EdgeClassification


def test_edge_classification_categories():
    assert classify_edge({"type": "AZContains"}) == EdgeClassification.RELATIONSHIP
    assert classify_edge({"type": "CanCreateKeys"}) == EdgeClassification.ATTACK_EDGE
    assert classify_edge({"type": "has_permission", "permission": "iam:PassRole"}) == EdgeClassification.PERMISSION
    assert classify_edge({"type": "mystery"}) == EdgeClassification.UNKNOWN


def test_unknown_edge_is_not_guessed_from_free_text():
    assert classify_edge({"type": "something", "permission": "probably admin access"}) == EdgeClassification.UNKNOWN
