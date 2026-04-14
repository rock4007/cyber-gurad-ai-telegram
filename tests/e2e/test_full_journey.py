import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.security.compliance import enforce_user_provided_only
from app.services.fraud_scanner import FraudScannerService


@pytest.mark.asyncio
async def test_full_journey_rule_mode(monkeypatch):
    monkeypatch.setattr("app.services.fraud_scanner.get_cached_scan", AsyncMock(return_value=None))
    monkeypatch.setattr("app.services.fraud_scanner.set_cached_scan", AsyncMock(return_value=True))

    service = FraudScannerService()
    service.threat_intel.analyze = AsyncMock(
        return_value=SimpleNamespace(
            score_boost=0,
            indicators=[],
            actions=[],
            explanations=[],
        )
    )

    # Force rule mode by disabling AI for social channel in this test.
    monkeypatch.setattr(service.settings, "social_media_mode", "normal")

    enforce_user_provided_only("Please verify your account urgently", True)

    result = await service.analyze(
        "Please verify your account urgently",
        channel="social",
        social_handle="@suspicious",
    )

    assert result.score >= 0
    assert result.risk_level in {"low", "medium", "high"}
