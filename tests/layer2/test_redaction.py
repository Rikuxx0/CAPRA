from capra.layer2.redaction import REDACTED, redact_sensitive_data


def test_raw_evidence_recursive_masking_without_mutation():
    raw = {"Token": "value", "nested": [{"password": "pw"}, {"safe": "ok"}], "credential": {"id": "x"}}
    redacted = redact_sensitive_data(raw)
    assert redacted["Token"] == REDACTED
    assert redacted["nested"][0]["password"] == REDACTED
    assert redacted["credential"] == REDACTED
    assert raw["Token"] == "value"
