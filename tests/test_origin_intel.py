"""Tests for services/origin_intel.py — IP/domain/phone origin resolution."""

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import pytest


# ── OriginIntelligenceService._extract_domain ───────────────────────────────

def test_extract_domain_http(origin_service):
    assert origin_service._extract_domain("http://example.com/path") == "example.com"


def test_extract_domain_https_with_port(origin_service):
    assert origin_service._extract_domain("https://evil.com:8080/login") == "evil.com"


def test_extract_domain_no_dot_returns_none(origin_service):
    assert origin_service._extract_domain("localhost") is None


def test_extract_domain_bare_url(origin_service):
    assert origin_service._extract_domain("https://sub.domain.co.uk/foo") == "sub.domain.co.uk"


# ── OriginIntelligenceService._dns_resolve ──────────────────────────────────

def test_dns_resolve_invalid_returns_none(origin_service):
    result = origin_service._dns_resolve("this-domain-definitely-does-not-exist-12345.xyz")
    assert result is None


# ── OriginIntelligenceService._correlate ────────────────────────────────────

def test_correlate_no_signals(origin_service):
    result = origin_service._correlate([])
    assert result["country"] == "Unknown"
    assert result["confidence"] == "none"


def test_correlate_single_signal(origin_service):
    signals = [{"source": "ip_geolocation", "country": "Germany", "city": "Berlin"}]
    result = origin_service._correlate(signals)
    assert result["country"] == "Germany"
    assert result["city"] == "Berlin"


def test_correlate_multiple_agreeing_signals(origin_service):
    signals = [
        {"source": "domain_hosting", "country": "India", "city": "Mumbai"},
        {"source": "phone_origin", "country": "India"},
    ]
    result = origin_service._correlate(signals)
    assert result["country"] == "India"
    assert result["confidence"] == "high"
    assert result["signals_count"] == 2


def test_correlate_conflicting_signals(origin_service):
    signals = [
        {"source": "domain_hosting", "country": "USA", "city": "Dallas"},
        {"source": "phone_origin", "country": "Nigeria"},
    ]
    result = origin_service._correlate(signals)
    assert result["confidence"] == "low"
    assert result["country"] in ("USA", "Nigeria")


def test_correlate_vpn_flag(origin_service):
    signals = [
        {"source": "ip_geolocation", "country": "Netherlands", "city": "Amsterdam", "is_proxy_or_vpn": True},
    ]
    result = origin_service._correlate(signals)
    assert result["vpn_detected"] is True


def test_correlate_subdomain_bypass_preferred(origin_service):
    signals = [
        {"source": "domain_hosting", "country": "USA", "city": "New York"},
        {"source": "dns_real_ip", "country": "Russia", "city": "Moscow", "method": "subdomain_bypass"},
    ]
    result = origin_service._correlate(signals)
    assert result["city"] == "Moscow"
    assert result["method"] == "subdomain_bypass"


# ── OriginIntelligenceService._resolve_phone ────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_phone_valid(origin_service):
    result = await origin_service._resolve_phone("+14155552671")
    assert result is not None
    assert result["region_code"] == "US"


@pytest.mark.asyncio
async def test_resolve_phone_invalid(origin_service):
    result = await origin_service._resolve_phone("not-a-number")
    assert result is None


# ── OriginIntelligenceService._geolocate_ip ─────────────────────────────────

@pytest.mark.asyncio
async def test_geolocate_ip_success(origin_service):
    import httpx

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "success",
        "country": "United States",
        "regionName": "California",
        "city": "Mountain View",
        "lat": 37.386,
        "lon": -122.084,
        "isp": "Google LLC",
        "org": "Google",
        "as": "AS15169",
        "proxy": False,
        "hosting": True,
    }

    with patch("httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.get.return_value = mock_response
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        result = await origin_service._geolocate_ip("8.8.8.8")

    assert result is not None
    assert result["country"] == "United States"
    assert result["is_hosting"] is True
    assert result["is_proxy_or_vpn"] is False


@pytest.mark.asyncio
async def test_geolocate_ip_failure(origin_service):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "fail"}

    with patch("httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.get.return_value = mock_response
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = instance

        result = await origin_service._geolocate_ip("0.0.0.0")

    assert result is None


# ── OriginIntelligenceService.resolve (integration-style) ───────────────────

@pytest.mark.asyncio
async def test_resolve_with_url_and_phone(origin_service):
    async def fake_resolve_domain(domain):
        return {"domain": domain, "country": "Germany", "city": "Frankfurt", "resolved_ip": "1.2.3.4"}

    async def fake_resolve_phone(phone):
        return {"phone": phone, "country": "Germany", "region_code": "DE"}

    origin_service._resolve_domain = fake_resolve_domain
    origin_service._resolve_phone = fake_resolve_phone
    origin_service._resolve_domain_real_ip = AsyncMock(return_value=None)

    result = await origin_service.resolve(url="https://scam.de/login", phone="+4915112345678")

    assert result["best_estimate"]["country"] == "Germany"
    assert result["best_estimate"]["confidence"] == "high"
    assert len(result["origin_signals"]) == 2


@pytest.mark.asyncio
async def test_resolve_no_inputs(origin_service):
    result = await origin_service.resolve()
    assert result["best_estimate"]["country"] == "Unknown"
    assert result["origin_signals"] == []


@pytest.mark.asyncio
async def test_resolve_handles_exceptions_gracefully(origin_service):
    async def exploding(*_a, **_k):
        raise RuntimeError("network down")

    origin_service._resolve_domain = exploding
    origin_service._resolve_domain_real_ip = exploding

    result = await origin_service.resolve(url="https://example.com")
    assert result["best_estimate"]["country"] == "Unknown"
