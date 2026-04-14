"""Tests for app/services/threat_intel.py — ThreatIntelService."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.threat_intel import ThreatIntelService, ThreatIntelSummary


# ── ThreatIntelSummary ──────────────────────────────────────────────────────

def test_summary_empty():
    s = ThreatIntelSummary()
    assert s.score_boost == 0
    assert s.indicators == []
    assert s.actions == []
    assert s.explanations == []


def test_summary_merge_adds_values():
    s = ThreatIntelSummary()
    s.merge({
        "score_boost": 10,
        "indicators": ["indicator1"],
        "actions": ["action1"],
        "explanations": ["reason1"],
    })
    assert s.score_boost == 10
    assert "indicator1" in s.indicators


def test_summary_merge_none():
    s = ThreatIntelSummary()
    s.merge(None)
    assert s.score_boost == 0


def test_summary_normalized_caps_boost():
    s = ThreatIntelSummary(score_boost=50)
    s.normalized()
    assert s.score_boost == 35  # max cap


def test_summary_normalized_deduplicates():
    s = ThreatIntelSummary(indicators=["dup", "dup", "unique"])
    s.normalized()
    assert s.indicators == ["dup", "unique"]


def test_summary_normalized_limits_length():
    s = ThreatIntelSummary(indicators=[f"ind-{i}" for i in range(20)])
    s.normalized()
    assert len(s.indicators) <= 8


# ── ThreatIntelService.has_live_providers ───────────────────────────────────

def test_has_no_live_providers():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.virustotal_api_key = None
        settings.hibp_api_key = None
        settings.dehashed_api_key = None
        settings.shodan_api_key = None
        settings.hunter_api_key = None
        settings.urlscan_api_key = None
        mock_settings.return_value = settings

        service = ThreatIntelService()
        assert service.has_live_providers() is False


def test_has_live_providers_vt():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.virustotal_api_key = "vt-key"
        settings.hibp_api_key = None
        settings.dehashed_api_key = None
        settings.shodan_api_key = None
        settings.hunter_api_key = None
        settings.urlscan_api_key = None
        mock_settings.return_value = settings

        service = ThreatIntelService()
        assert service.has_live_providers() is True


# ── ThreatIntelService.analyze with no providers ───────────────────────────

@pytest.mark.asyncio
async def test_analyze_no_providers_no_content():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        for attr in ("virustotal_api_key", "hibp_api_key", "dehashed_api_key",
                      "shodan_api_key", "hunter_api_key", "urlscan_api_key",
                      "dehashed_email"):
            setattr(settings, attr, None)
        mock_settings.return_value = settings

        service = ThreatIntelService()
        result = await service.analyze("plain text no indicators")
        assert result.score_boost == 0


# ── ThreatIntelService._hibp_lookup ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_hibp_lookup_breach_found():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.hibp_api_key = "test-key"
        mock_settings.return_value = settings

        service = ThreatIntelService()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"Name": "BigBreach"}, {"Name": "SmallBreach"}]

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await service._hibp_lookup("victim@example.com")

        assert result is not None
        assert result["score_boost"] == 12  # 2 * 6
        assert "BigBreach" in result["indicators"]


@pytest.mark.asyncio
async def test_hibp_lookup_not_found():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.hibp_api_key = "test-key"
        mock_settings.return_value = settings

        service = ThreatIntelService()
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await service._hibp_lookup("clean@example.com")
        assert result is None


# ── ThreatIntelService._virustotal_domain_lookup ────────────────────────────

@pytest.mark.asyncio
async def test_vt_domain_flagged():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.virustotal_api_key = "vt-key"
        mock_settings.return_value = settings

        service = ThreatIntelService()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 2}}}
        }

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await service._virustotal_domain_lookup("evil.com")

        assert result is not None
        assert result["score_boost"] == 22  # min(22, 5*4 + 2*2 = 24) -> 22


@pytest.mark.asyncio
async def test_vt_domain_clean():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.virustotal_api_key = "vt-key"
        mock_settings.return_value = settings

        service = ThreatIntelService()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
        }

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await service._virustotal_domain_lookup("safe.org")
        assert result is None


# ── ThreatIntelService._shodan_lookup ───────────────────────────────────────

@pytest.mark.asyncio
async def test_shodan_with_vulns():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.shodan_api_key = "shodan-key"
        mock_settings.return_value = settings

        service = ThreatIntelService()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ports": [22, 80, 443],
            "vulns": {"CVE-2021-12345": {}},
        }

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await service._shodan_lookup("1.2.3.4")

        assert result is not None
        assert result["score_boost"] == 5  # has vulns


@pytest.mark.asyncio
async def test_shodan_no_data():
    with patch("app.services.threat_intel.get_settings") as mock_settings:
        settings = MagicMock()
        settings.shodan_api_key = "shodan-key"
        mock_settings.return_value = settings

        service = ThreatIntelService()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ports": [], "vulns": {}}

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get.return_value = mock_resp
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            result = await service._shodan_lookup("1.2.3.4")
        assert result is None


# ── ThreatIntelService._extract_domain ──────────────────────────────────────

def test_extract_domain_with_www():
    assert ThreatIntelService._extract_domain("https://www.example.com/path") == "example.com"


def test_extract_domain_plain():
    assert ThreatIntelService._extract_domain("http://evil.org") == "evil.org"


def test_extract_domain_garbage():
    # "not-a-url" has no scheme so the regex strips nothing and returns the host part
    result = ThreatIntelService._extract_domain("not-a-url")
    assert result == "not-a-url"
