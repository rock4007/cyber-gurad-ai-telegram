from app.services.fraud_scanner import FraudScannerService


def test_should_use_ai_rules():
    assert FraudScannerService._should_use_ai(channel="email", email_mode="normal", social_mode="ai", voice_mode="ai") is False
    assert FraudScannerService._should_use_ai(channel="social", email_mode="ai", social_mode="normal", voice_mode="ai") is False
    assert FraudScannerService._should_use_ai(channel="text", email_mode="normal", social_mode="normal", voice_mode="normal") is True


def test_build_analysis_content_contains_channel_and_content():
    built = FraudScannerService._build_analysis_content(
        content="Suspicious OTP message",
        channel="text",
        email_address=None,
        social_handle=None,
        voice_mode="ai",
    )
    assert "channel=text" in built
    assert "content=Suspicious OTP message" in built


def test_parse_model_json_fallback(monkeypatch):
    service = FraudScannerService.__new__(FraudScannerService)
    parsed = FraudScannerService._parse_model_json(service, "not json")
    assert parsed["risk_level"] == "medium"
    assert parsed["score"] == 55
