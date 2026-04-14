"""Tests for app/services/fraud_scanner.py — FraudScannerService."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.fraud_scanner import FraudScannerService, _geolocate_ip, _resolve_origin_from_content


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_scanner(*, ai_response: str | None = None, cache_hit: dict | None = None) -> FraudScannerService:
    """Build a FraudScannerService with mocked AI client."""
    ai_client = MagicMock()
    if ai_response is not None:
        ai_client.analyze_text = AsyncMock(return_value=ai_response)
    else:
        ai_client.analyze_text = AsyncMock(return_value=json.dumps({
            "risk_level": "low",
            "score": 15,
            "summary": "Looks safe.",
            "explanation": "No indicators.",
            "recommended_actions": ["Stay alert."],
            "flagged_indicators": [],
        }))
    scanner = FraudScannerService(ai_client=ai_client)
    return scanner


# ── _risk_level_from_score ──────────────────────────────────────────────────

def test_risk_level_from_score_high():
    assert FraudScannerService._risk_level_from_score(70) == "high"
    assert FraudScannerService._risk_level_from_score(100) == "high"


def test_risk_level_from_score_medium():
    assert FraudScannerService._risk_level_from_score(40) == "medium"
    assert FraudScannerService._risk_level_from_score(69) == "medium"


def test_risk_level_from_score_low():
    assert FraudScannerService._risk_level_from_score(0) == "low"
    assert FraudScannerService._risk_level_from_score(39) == "low"


# ── _should_use_ai ──────────────────────────────────────────────────────────

def test_should_use_ai_default_text():
    assert FraudScannerService._should_use_ai(channel="text", email_mode="ai", social_mode="ai", voice_mode="ai") is True


def test_should_use_ai_email_normal():
    assert FraudScannerService._should_use_ai(channel="email", email_mode="normal", social_mode="ai", voice_mode="ai") is False


def test_should_use_ai_social_normal():
    assert FraudScannerService._should_use_ai(channel="social", email_mode="ai", social_mode="normal", voice_mode="ai") is False


def test_should_use_ai_voice_normal():
    assert FraudScannerService._should_use_ai(channel="voice", email_mode="ai", social_mode="ai", voice_mode="normal") is False


def test_should_use_ai_voice_ai():
    assert FraudScannerService._should_use_ai(channel="voice", email_mode="ai", social_mode="ai", voice_mode="ai") is True


# ── _basic_rule_result ──────────────────────────────────────────────────────

def test_basic_rule_result_detects_tokens():
    scanner = _make_scanner()
    result = scanner._basic_rule_result("urgent: verify your account now or lose access!", "email")
    assert result["score"] > 15
    assert any("urgent" in f for f in result["flagged_indicators"])


def test_basic_rule_result_clean_content():
    scanner = _make_scanner()
    result = scanner._basic_rule_result("Hello, how are you doing today?", "text")
    assert result["score"] == 15
    assert "No high-confidence token match" in result["flagged_indicators"][0]


def test_basic_rule_result_channel_hint_email():
    scanner = _make_scanner()
    result = scanner._basic_rule_result("test content", "email")
    assert "Email mode" in result["explanation"]


def test_basic_rule_result_channel_hint_social():
    scanner = _make_scanner()
    result = scanner._basic_rule_result("test content", "social")
    assert "Social mode" in result["explanation"]


def test_basic_rule_result_score_capped_at_95():
    scanner = _make_scanner()
    content = "urgent verify your account otp password bank click limited time gift card crypto wire transfer"
    result = scanner._basic_rule_result(content, "text")
    assert result["score"] <= 95


# ── _parse_model_json ───────────────────────────────────────────────────────

def test_parse_model_json_valid():
    scanner = _make_scanner()
    raw = json.dumps({"risk_level": "high", "score": 90, "summary": "Alert!", "explanation": "", "recommended_actions": [], "flagged_indicators": []})
    result = scanner._parse_model_json(raw)
    assert result["risk_level"] == "high"
    assert result["score"] == 90


def test_parse_model_json_malformed_returns_fallback():
    scanner = _make_scanner()
    result = scanner._parse_model_json("this is not json!!")
    assert result["risk_level"] == "medium"
    assert result["score"] == 55


# ── _build_analysis_content ─────────────────────────────────────────────────

def test_build_analysis_content_text():
    content = FraudScannerService._build_analysis_content(
        content="suspicious text",
        channel="text",
        email_address=None,
        social_handle=None,
        voice_mode="ai",
    )
    assert "channel=text" in content
    assert "suspicious text" in content


def test_build_analysis_content_email():
    content = FraudScannerService._build_analysis_content(
        content="check this",
        channel="email",
        email_address="test@evil.com",
        social_handle=None,
        voice_mode="ai",
    )
    assert "email=test@evil.com" in content


def test_build_analysis_content_voice_mode():
    content = FraudScannerService._build_analysis_content(
        content="transcript",
        channel="voice",
        email_address=None,
        social_handle=None,
        voice_mode="normal",
    )
    assert "voice_recognition_mode=normal" in content


# ── _merge_threat_intel ─────────────────────────────────────────────────────

def test_merge_threat_intel_adds_score():
    scanner = _make_scanner()

    class FakeIntel:
        score_boost = 15
        indicators = ["HIBP: email in breach"]
        actions = ["Reset password"]
        explanations = ["Breach detected."]

    parsed = {"risk_level": "low", "score": 30, "summary": "Some risk.", "flagged_indicators": [], "recommended_actions": []}
    result = scanner._merge_threat_intel(parsed, FakeIntel())
    assert result["score"] == 45
    assert result["risk_level"] == "medium"
    assert "HIBP: email in breach" in result["flagged_indicators"]


def test_merge_threat_intel_caps_score():
    scanner = _make_scanner()

    class FakeIntel:
        score_boost = 35
        indicators = []
        actions = []
        explanations = []

    parsed = {"risk_level": "low", "score": 80, "summary": "", "flagged_indicators": [], "recommended_actions": []}
    result = scanner._merge_threat_intel(parsed, FakeIntel())
    assert result["score"] == 100


# ── analyze (async) ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_ai_mode():
    scanner = _make_scanner(ai_response=json.dumps({
        "risk_level": "high",
        "score": 85,
        "summary": "Fraud detected.",
        "explanation": "Suspicious patterns.",
        "recommended_actions": ["Block sender."],
        "flagged_indicators": ["Impersonation"],
    }))

    with patch("app.services.fraud_scanner.get_cached_scan", new_callable=AsyncMock, return_value=None), \
         patch("app.services.fraud_scanner.set_cached_scan", new_callable=AsyncMock), \
         patch("app.services.fraud_scanner._resolve_origin_from_content", new_callable=AsyncMock, return_value=None), \
         patch.object(scanner.threat_intel, "analyze", new_callable=AsyncMock) as mock_intel:
        mock_intel.return_value = MagicMock(score_boost=0, indicators=[], actions=[], explanations=[])
        mock_intel.return_value.__bool__ = lambda self: False

        result = await scanner.analyze("Your account has been compromised! Click to verify.")
        assert result.risk_level == "high"
        assert result.score == 85


@pytest.mark.asyncio
async def test_analyze_normal_email_mode():
    scanner = _make_scanner()
    scanner.settings = MagicMock(
        email_intel_mode="normal",
        social_media_mode="ai",
        voice_recognition_mode="ai",
        email_database_url=None,
    )

    with patch("app.services.fraud_scanner.get_cached_scan", new_callable=AsyncMock, return_value=None), \
         patch("app.services.fraud_scanner.set_cached_scan", new_callable=AsyncMock), \
         patch("app.services.fraud_scanner._resolve_origin_from_content", new_callable=AsyncMock, return_value=None), \
         patch.object(scanner.threat_intel, "analyze", new_callable=AsyncMock) as mock_intel:
        mock_intel.return_value = MagicMock(score_boost=0, indicators=[], actions=[], explanations=[])
        mock_intel.return_value.__bool__ = lambda self: False

        result = await scanner.analyze("verify your account urgently", channel="email")
        # AI should NOT have been called
        scanner.ai_client.analyze_text.assert_not_called()
        assert result.score >= 15


@pytest.mark.asyncio
async def test_analyze_cache_hit():
    cached = {
        "risk_level": "low",
        "score": 10,
        "summary": "Cached.",
        "explanation": "",
        "recommended_actions": ["None needed."],
        "flagged_indicators": [],
    }
    scanner = _make_scanner()

    with patch("app.services.fraud_scanner.get_cached_scan", new_callable=AsyncMock, return_value=cached):
        result = await scanner.analyze("anything")
        assert result.score == 10
        assert result.summary == "Cached."
        scanner.ai_client.analyze_text.assert_not_called()


# ── _geolocate_ip ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_geolocate_ip_module_level():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Germany",
        "city": "Frankfurt",
        "isp": "Hetzner",
        "proxy": True,
        "hosting": True,
    }

    with patch("app.services.fraud_scanner._httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.get.return_value = mock_resp
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        result = await _geolocate_ip("1.2.3.4")

    assert result is not None
    assert result["country"] == "Germany"
    assert result["is_proxy_or_vpn"] is True


# ── _resolve_origin_from_content ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_origin_no_url():
    result = await _resolve_origin_from_content("just some plain text with no links")
    assert result is None
