"""Tests for app/schemas.py — Pydantic models and request/response validation."""

import pytest
from pydantic import ValidationError

from app.schemas import ScanChannel, ScanRequest, ScanResult, ScanResponse, ScanSource, VoiceRecognitionMode


# ── ScanSource enum ─────────────────────────────────────────────────────────

def test_scan_source_telegram():
    assert ScanSource.telegram.value == "telegram"


def test_scan_source_api():
    assert ScanSource.api.value == "api"


# ── ScanChannel enum ────────────────────────────────────────────────────────

def test_scan_channel_values():
    assert set(c.value for c in ScanChannel) == {"text", "email", "social", "voice"}


# ── VoiceRecognitionMode enum ──────────────────────────────────────────────

def test_voice_mode_values():
    assert VoiceRecognitionMode.ai.value == "ai"
    assert VoiceRecognitionMode.normal.value == "normal"


# ── ScanRequest validation ──────────────────────────────────────────────────

def test_valid_scan_request():
    req = ScanRequest(
        source="telegram",
        content="Check this message for fraud please",
        consent_confirmed=True,
    )
    assert req.channel == ScanChannel.text
    assert req.voice_recognition_mode == VoiceRecognitionMode.ai
    assert req.external_user_id is None


def test_scan_request_all_fields():
    req = ScanRequest(
        source="api",
        content="Suspicious email content here",
        consent_confirmed=True,
        external_user_id="user-123",
        channel="email",
        voice_recognition_mode="normal",
        email_address="test@example.com",
        social_handle="@badactor",
    )
    assert req.channel == ScanChannel.email
    assert req.email_address == "test@example.com"
    assert req.social_handle == "@badactor"


def test_scan_request_content_too_short():
    with pytest.raises(ValidationError) as exc_info:
        ScanRequest(source="telegram", content="ab", consent_confirmed=True)
    assert "content" in str(exc_info.value).lower()


def test_scan_request_content_too_long():
    with pytest.raises(ValidationError):
        ScanRequest(source="telegram", content="x" * 4001, consent_confirmed=True)


def test_scan_request_missing_consent():
    with pytest.raises(ValidationError):
        ScanRequest(source="telegram", content="some content here")


def test_scan_request_invalid_source():
    with pytest.raises(ValidationError):
        ScanRequest(source="unknown_source", content="test content", consent_confirmed=True)


def test_scan_request_invalid_channel():
    with pytest.raises(ValidationError):
        ScanRequest(source="telegram", content="test content", consent_confirmed=True, channel="fax")


# ── ScanResult validation ──────────────────────────────────────────────────

def test_valid_scan_result():
    r = ScanResult(
        risk_level="high",
        score=85,
        summary="Fraud detected.",
        explanation="Multiple risk signals.",
        recommended_actions=["Block sender."],
        flagged_indicators=["Phishing pattern"],
    )
    assert r.score == 85
    assert len(r.recommended_actions) == 1


def test_scan_result_score_bounds():
    with pytest.raises(ValidationError):
        ScanResult(risk_level="low", score=-1, summary="", recommended_actions=[], flagged_indicators=[])

    with pytest.raises(ValidationError):
        ScanResult(risk_level="low", score=101, summary="", recommended_actions=[], flagged_indicators=[])


def test_scan_result_zero_score():
    r = ScanResult(risk_level="low", score=0, summary="Clean.", recommended_actions=[], flagged_indicators=[])
    assert r.score == 0


def test_scan_result_max_score():
    r = ScanResult(risk_level="high", score=100, summary="Max.", recommended_actions=[], flagged_indicators=[])
    assert r.score == 100


def test_scan_result_default_explanation():
    r = ScanResult(risk_level="low", score=0, summary="", recommended_actions=[], flagged_indicators=[])
    assert r.explanation == ""


# ── ScanResponse ────────────────────────────────────────────────────────────

def test_scan_response_structure():
    from datetime import datetime

    result = ScanResult(
        risk_level="medium",
        score=50,
        summary="Caution.",
        recommended_actions=["Verify sender."],
        flagged_indicators=["Urgency language."],
    )
    resp = ScanResponse(scan_id="abc-123", created_at=datetime(2026, 4, 13), result=result)
    assert resp.scan_id == "abc-123"
    assert resp.result.score == 50
