"""Tests for app/api/routes.py — FastAPI /v1/scan endpoint."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ── App fixture ─────────────────────────────────────────────────────────────

@pytest.fixture()
def client():
    from app.api.routes import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ── Mock helpers ────────────────────────────────────────────────────────────

def _mock_db_session():
    """Return an AsyncMock that acts as an AsyncSession dependency."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.add = MagicMock()
    return session


def _scan_log_stub():
    """Fake ScanLog row returned by the repo."""
    log = MagicMock()
    log.id = "scan-123"
    log.created_at = datetime(2026, 4, 13, 12, 0, 0)
    return log


def _default_scan_result():
    from app.schemas import ScanResult
    return ScanResult(
        risk_level="low",
        score=10,
        summary="All clear.",
        explanation="No risk indicators.",
        recommended_actions=["Stay safe."],
        flagged_indicators=[],
    )


# ── POST /v1/scan — successful ─────────────────────────────────────────────

def test_scan_success(client):
    with patch("app.api.routes.get_db_session") as mock_get_db, \
         patch("app.api.routes.FraudScannerService") as MockScanner, \
         patch("app.api.routes.ScanLogRepository") as MockRepo:

        session = _mock_db_session()

        async def db_gen():
            yield session

        mock_get_db.return_value = db_gen()

        scanner_instance = MagicMock()
        scanner_instance.analyze = AsyncMock(return_value=_default_scan_result())
        MockScanner.return_value = scanner_instance

        repo_instance = MagicMock()
        repo_instance.create_scan_log = AsyncMock(return_value=_scan_log_stub())
        MockRepo.return_value = repo_instance

        response = client.post("/v1/scan", json={
            "source": "telegram",
            "content": "Check this message for scam please.",
            "consent_confirmed": True,
        })

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "scan-123"
    assert body["result"]["risk_level"] == "low"
    assert body["result"]["score"] == 10


# ── POST /v1/scan — consent not confirmed ──────────────────────────────────

def test_scan_no_consent(client):
    with patch("app.api.routes.get_db_session") as mock_get_db:
        session = _mock_db_session()

        async def db_gen():
            yield session

        mock_get_db.return_value = db_gen()

        response = client.post("/v1/scan", json={
            "source": "telegram",
            "content": "Check this suspicious message please.",
            "consent_confirmed": False,
        })

    assert response.status_code in (400, 422)
    assert "consent" in str(response.json()).lower()


# ── POST /v1/scan — content too short ──────────────────────────────────────

def test_scan_content_too_short(client):
    response = client.post("/v1/scan", json={
        "source": "api",
        "content": "hi",
        "consent_confirmed": True,
    })
    assert response.status_code == 422  # Pydantic validation error


# ── POST /v1/scan — missing source ─────────────────────────────────────────

def test_scan_missing_source(client):
    response = client.post("/v1/scan", json={
        "content": "test content here for scan",
        "consent_confirmed": True,
    })
    assert response.status_code == 422


# ── POST /v1/scan — with channel and optional fields ───────────────────────

def test_scan_with_email_channel(client):
    with patch("app.api.routes.get_db_session") as mock_get_db, \
         patch("app.api.routes.FraudScannerService") as MockScanner, \
         patch("app.api.routes.ScanLogRepository") as MockRepo:

        session = _mock_db_session()

        async def db_gen():
            yield session

        mock_get_db.return_value = db_gen()

        scanner_instance = MagicMock()
        scanner_instance.analyze = AsyncMock(return_value=_default_scan_result())
        MockScanner.return_value = scanner_instance

        repo_instance = MagicMock()
        repo_instance.create_scan_log = AsyncMock(return_value=_scan_log_stub())
        MockRepo.return_value = repo_instance

        response = client.post("/v1/scan", json={
            "source": "api",
            "content": "Suspicious email content to analyze.",
            "consent_confirmed": True,
            "channel": "email",
            "email_address": "test@example.com",
            "voice_recognition_mode": "normal",
        })

    assert response.status_code == 200
    # Verify scanner was called with correct channel
    scanner_instance.analyze.assert_called_once()
    call_kwargs = scanner_instance.analyze.call_args
    assert call_kwargs.kwargs["channel"] == "email"
    assert call_kwargs.kwargs["email_address"] == "test@example.com"
