from agentperms.recorder.redactor import REDACTED, redact, redact_text


def test_redacts_api_keys_and_emails():
    out = redact_text("key sk-abcdefghijklmnopqrstuvwx mail me at a@b.com")
    assert "sk-abcdef" not in out
    assert "a@b.com" not in out
    assert REDACTED in out


def test_redacts_bearer_and_pem():
    assert "topsecret" not in redact_text("Authorization: Bearer topsecret123")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIabc" not in redact_text(pem)


def test_redact_recurses_into_structures():
    data = {"to": "user@example.com", "nested": ["ghp_" + "a" * 30]}
    out = redact(data)
    assert out["to"] == REDACTED
    assert out["nested"][0] == REDACTED


def test_benign_text_untouched():
    assert redact_text("just reading ./src/app.py") == "just reading ./src/app.py"
