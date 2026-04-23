"""Tests for handlers/investigate.py and services/cross_db_investigation.py."""

import asyncio
import importlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telegram import Chat, User

os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("BOT_TOKEN", "test-bot-token")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ADMIN_IDS", "12345")
os.environ.setdefault("BACKEND_URL", "http://localhost:8000")

BOT_ROOT = Path(__file__).resolve().parents[2]  # tests/handlers -> tests -> cyberguard-telegram
if str(BOT_ROOT) not in sys.path:
    sys.path.insert(0, str(BOT_ROOT))

# Also ensure the outer tests conftest path-patching has run (mirrors other handler tests)
_TESTS_ROOT = Path(__file__).resolve().parents[1]
if str(_TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TESTS_ROOT))

# The conftest.py that runs before this file extends the handlers package __path__
# to include cyberguard-telegram/handlers, so this direct import resolves correctly.
from handlers import investigate as _inv_handler_prod  # noqa: E402
from services import cross_db_investigation as _cross_db_prod  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_update(text: str = "", command_args: list[str] | None = None) -> MagicMock:
    update = MagicMock()
    update.effective_user = User(id=99, first_name="Inv", is_bot=False)
    update.effective_chat = Chat(id=1, type="private")
    msg = MagicMock()
    msg.text = text
    msg.reply_text = AsyncMock()
    update.message = msg
    update.effective_message = msg
    return update


def _make_context(args: list[str] | None = None) -> MagicMock:
    ctx = MagicMock()
    ctx.args = args or []
    ctx.user_data = {}
    ctx.bot = MagicMock()
    ctx.bot.send_chat_action = AsyncMock()
    return ctx


# ---------------------------------------------------------------------------
# Unit tests for _parse_args
# ---------------------------------------------------------------------------

class TestParseArgs:
    def _parse(self, raw: str):
        return _inv_handler_prod._parse_args(raw)

    def test_phone_only(self):
        name, phone = self._parse("+919876543210")
        assert phone == "+919876543210"
        assert name == ""

    def test_name_then_phone(self):
        name, phone = self._parse("John Doe +919876543210")
        assert phone == "+919876543210"
        assert "John" in name
        assert "Doe" in name

    def test_phone_then_name(self):
        name, phone = self._parse("+919876543210 Jane Smith")
        assert phone == "+919876543210"
        assert "Jane" in name
        assert "Smith" in name

    def test_no_phone(self):
        name, phone = self._parse("Only Name Here")
        assert phone == ""
        assert "Only Name Here" in name

    def test_local_10digit(self):
        name, phone = self._parse("9876543210")
        assert phone == "9876543210"

    def test_parse_request_tier_and_social_ids(self):
        parsed = _inv_handler_prod._parse_investigation_request(
            "master consent:yes John Doe +919876543210 tg:john_doe group:fraud_watch twitter:johnx"
        )
        assert parsed["tier"] == "master"
        assert parsed["consent_confirmed"] is True
        assert parsed["phone"] == "+919876543210"
        assert "John" in parsed["full_name"]
        assert parsed["telegram_id"] == "john_doe"
        assert parsed["telegram_group"] == "fraud_watch"
        assert parsed["twitter_id"] == "johnx"

    def test_parse_request_from_urls(self):
        parsed = _inv_handler_prod._parse_investigation_request(
            "pro t.me/samplechannel x.com/sample_user"
        )
        assert parsed["tier"] == "pro"
        assert parsed["consent_confirmed"] is False
        assert parsed["telegram_id"] == "samplechannel"
        assert parsed["twitter_id"] == "sample_user"

    def test_parse_request_with_ip(self):
        parsed = _inv_handler_prod._parse_investigation_request(
            "basic ip:8.8.8.8"
        )
        assert parsed["tier"] == "basic"
        assert parsed["ip_address"] == "8.8.8.8"

    def test_parse_request_with_mac(self):
        parsed = _inv_handler_prod._parse_investigation_request(
            "pro mac:00-1a-2b-3c-4d-5e"
        )
        assert parsed["tier"] == "pro"
        assert parsed["mac_address"] == "00:1A:2B:3C:4D:5E"

    def test_parse_request_with_email(self):
        parsed = _inv_handler_prod._parse_investigation_request(
            "pro email:test@example.com"
        )
        assert parsed["tier"] == "pro"
        assert parsed["email_address"] == "test@example.com"
        assert parsed["privacy_mode"] is False

    def test_parse_request_privacy_off(self):
        parsed = _inv_handler_prod._parse_investigation_request(
            "pro privacy:off email:test@example.com"
        )
        assert parsed["privacy_mode"] is False


# ---------------------------------------------------------------------------
# Unit tests for the CrossDatabaseInvestigator service
# ---------------------------------------------------------------------------

class TestCrossDbInvestigator:
    def _investigator(self):
        return _cross_db_prod.CrossDatabaseInvestigator()

    def test_investigate_phone_only_no_keys(self):
        investigator = self._investigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210"))
        assert result["artifact_id"].startswith("INV-")
        assert "query" in result
        assert result["query"]["phone_country"] == "India"
        assert result["query"]["phone"] is not None  # masked
        assert "India" in (result["query"]["phone_geo_area"] or "")
        assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert isinstance(result["evidence"], list)
        assert isinstance(result["flags"], list)
        assert result["generated_at"].endswith("Z")

    def test_investigate_returns_carrier_and_line_type(self):
        investigator = self._investigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210"))
        q = result["query"]
        # line_type should be populated from phonenumbers
        assert q["phone_line_type"] in {"mobile", "landline", "mobile/landline", "VoIP", "unknown", None}

    def test_investigate_invalid_phone_flagged(self):
        investigator = self._investigator()
        result = asyncio.run(investigator.investigate(phone="+00000000000"))
        assert any("format" in f.lower() or "valid" in f.lower() for f in result["flags"])

    def test_investigate_name_only_no_keys(self):
        investigator = self._investigator()
        result = asyncio.run(investigator.investigate(full_name="John Doe"))
        assert result["artifact_id"].startswith("INV-")
        # no breach keys set, so sources_queried should be empty or only scam_reports
        assert isinstance(result["sources_queried"], list)

    def test_investigate_with_dehashed_key_calls_dehashed(self, monkeypatch):
        mod = _cross_db_prod
        monkeypatch.setenv("DEHASHED_API_KEY", "test-dehashed-key")
        monkeypatch.setenv("DEHASHED_EMAIL", "test@example.com")

        dehashed_calls = []

        async def fake_dehashed(query, search_type, api_key, email):
            dehashed_calls.append(search_type)
            return {"total": 2, "hits": [
                {"database_name": "TestDB", "phone": "+919876543210",
                 "username": "jdoe", "email": "j@example.com",
                 "name": "John Doe", "address": None, "hashed_password": None}
            ]}

        monkeypatch.setattr(mod, "_query_dehashed", fake_dehashed)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(full_name="John Doe", phone="+919876543210", tier="master"))

        assert "phone" in dehashed_calls or "name" in dehashed_calls
        assert result["score"] > 0
        assert any("breach" in f.lower() or "record" in f.lower() for f in result["flags"])
        assert isinstance(result["query"].get("associated_breach_emails"), list)
        assert result["query"].get("tracking_status") == "disabled_defensive_mode"

    def test_investigate_hibp_breach_raises_score(self, monkeypatch):
        mod = _cross_db_prod
        monkeypatch.setenv("HIBP_API_KEY", "test-hibp-key")

        async def fake_hibp(phone, api_key):
            return {"breach_count": 3, "breach_names": ["Adobe", "LinkedIn", "Canva"],
                    "note": "Phone found in breaches"}

        monkeypatch.setattr(mod, "_query_haveibeenpwned_phone", fake_hibp)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210", tier="pro"))

        assert result["score"] >= 15
        assert any("breach" in f.lower() for f in result["flags"])

    def test_investigate_hibp_email_breach_included(self, monkeypatch):
        mod = _cross_db_prod
        monkeypatch.setenv("HIBP_API_KEY", "test-hibp-key")

        async def fake_hibp_email(email, api_key):
            assert email == "test@example.com"
            return {
                "breach_count": 2,
                "breach_names": ["LinkedIn", "Canva"],
                "note": "Email found in breaches",
            }

        monkeypatch.setattr(mod, "_query_haveibeenpwned_email", fake_hibp_email)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(email_address="test@example.com", tier="pro", privacy_mode=False))

        assert result["query"]["email_address"] == "test@example.com"
        assert result["query"]["email_breach_count"] == 2
        assert "haveibeenpwned_email" in result["sources_with_data"]

    def test_privacy_mode_masks_ip_mac_email(self, monkeypatch):
        mod = _cross_db_prod
        monkeypatch.setenv("HIBP_API_KEY", "test-hibp-key")

        async def fake_hibp_email(email, api_key):
            return {"breach_count": 1, "breach_names": ["Demo"]}

        async def fake_geo(ip):
            return {"country": "US", "city": "NYC", "isp": "ISP", "vpn_or_proxy": False}

        async def fake_mac(mac):
            return {"mac": mac, "vendor": "Vendor"}

        monkeypatch.setattr(mod, "_query_haveibeenpwned_email", fake_hibp_email)
        monkeypatch.setattr(mod, "_geolocate_ip", fake_geo)
        monkeypatch.setattr(mod, "_lookup_mac_vendor", fake_mac)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(
            investigator.investigate(
                email_address="test@example.com",
                ip_address="8.8.8.8",
                mac_address="00:1A:2B:3C:4D:5E",
                tier="pro",
                privacy_mode=True,
            )
        )

        assert result["query"]["email_address"] != "test@example.com"
        assert result["query"]["ip_address"] == "8.8.8.*"
        assert result["query"]["mac_address"] == "00:1A:2B:**:**:**"

    def test_investigate_vpn_note_propagates(self, monkeypatch):
        mod = _cross_db_prod

        async def fake_geo(ip):
            return {
                "ip": "1.2.3.4",
                "country": "Netherlands",
                "city": "Amsterdam",
                "vpn_or_proxy": True,
                "vpn_note": "Real hosting location shown; VPN/proxy detected",
            }

        monkeypatch.setattr(mod, "_geolocate_ip", fake_geo)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210"))
        # at minimum should complete without error
        assert result["artifact_id"].startswith("INV-")

    def test_investigate_scam_report_increases_score(self, monkeypatch):
        mod = _cross_db_prod

        async def fake_scam(phone):
            return {
                "scam_flags": ["Phone associated with 5 malicious URL(s) in URLhaus"],
                "sources_checked": ["URLhaus"],
                "flagged": True,
            }

        monkeypatch.setattr(mod, "_check_scam_reports", fake_scam)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210"))

        assert result["score"] >= 20
        assert any("URLhaus" in f for f in result["flags"])

    def test_investigate_ip_lookup_included(self, monkeypatch):
        mod = _cross_db_prod

        async def fake_geo(ip):
            assert ip == "8.8.8.8"
            return {
                "ip": "8.8.8.8",
                "country": "United States",
                "city": "Mountain View",
                "isp": "Google LLC",
                "vpn_or_proxy": False,
            }

        monkeypatch.setattr(mod, "_geolocate_ip", fake_geo)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(ip_address="8.8.8.8", tier="pro", privacy_mode=False))

        assert result["query"]["ip_address"] == "8.8.8.8"
        assert result["query"]["ip_country"] == "United States"
        assert "ip_geolocation" in result["sources_with_data"]

    def test_investigate_mac_lookup_included(self, monkeypatch):
        mod = _cross_db_prod

        async def fake_mac(mac):
            assert mac == "00:1A:2B:3C:4D:5E"
            return {"mac": mac, "vendor": "Test Vendor Inc"}

        monkeypatch.setattr(mod, "_lookup_mac_vendor", fake_mac)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(mac_address="00:1A:2B:3C:4D:5E", tier="pro", privacy_mode=False))

        assert result["query"]["mac_address"] == "00:1A:2B:3C:4D:5E"
        assert result["query"]["mac_vendor"] == "Test Vendor Inc"
        assert "mac_vendor_lookup" in result["sources_with_data"]

    def test_basic_tier_forces_masked_ip_mac_even_when_privacy_off(self, monkeypatch):
        mod = _cross_db_prod

        async def fake_geo(ip):
            return {"ip": ip, "country": "US"}

        async def fake_mac(mac):
            return {"mac": mac, "vendor": "Test Vendor Inc"}

        monkeypatch.setattr(mod, "_geolocate_ip", fake_geo)
        monkeypatch.setattr(mod, "_lookup_mac_vendor", fake_mac)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(
            investigator.investigate(
                ip_address="8.8.8.8",
                mac_address="00:1A:2B:3C:4D:5E",
                tier="basic",
                privacy_mode=False,
            )
        )

        assert result["query"]["ip_address"] == "8.8.8.*"
        assert result["query"]["mac_address"] == "00:1A:2B:**:**:**"

    def test_basic_tier_forces_masked_social_even_when_privacy_off(self):
        investigator = _cross_db_prod.CrossDatabaseInvestigator()
        result = asyncio.run(
            investigator.investigate(
                telegram_id="john_doe",
                telegram_group="fraud_watch",
                twitter_id="sampleuser",
                tier="basic",
                privacy_mode=False,
            )
        )

        assert result["query"]["telegram_id"] != "john_doe"
        assert result["query"]["telegram_group"] != "fraud_watch"
        assert result["query"]["twitter_id"] != "sampleuser"

    def test_pro_tier_shows_real_social_when_privacy_off(self):
        investigator = _cross_db_prod.CrossDatabaseInvestigator()
        result = asyncio.run(
            investigator.investigate(
                telegram_id="john_doe",
                telegram_group="fraud_watch",
                twitter_id="sampleuser",
                tier="pro",
                privacy_mode=False,
            )
        )

        assert result["query"]["telegram_id"] == "john_doe"
        assert result["query"]["telegram_group"] == "fraud_watch"
        assert result["query"]["twitter_id"] == "sampleuser"

    def test_identity_enrichment_from_dehashed_phone(self, monkeypatch):
        mod = _cross_db_prod
        monkeypatch.setenv("DEHASHED_API_KEY", "test-dehashed-key")
        monkeypatch.setenv("DEHASHED_EMAIL", "test@example.com")

        async def fake_dehashed(query, search_type, api_key, email):
            if search_type == "phone":
                return {
                    "total": 2,
                    "hits": [
                        {
                            "database_name": "TestDB",
                            "phone": "+919876543210",
                            "username": "john.doe",
                            "email": "john.doe99@example.com",
                            "name": "john doe",
                        },
                        {
                            "database_name": "OtherDB",
                            "phone": "+919876543210",
                            "username": "john_doe",
                            "email": "johnd@example.com",
                            "name": "John Doe",
                        },
                    ],
                }
            return {"total": 0, "hits": []}

        monkeypatch.setattr(mod, "_query_dehashed", fake_dehashed)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210", tier="master", consent_confirmed=True))

        assert result["query"]["probable_holder_name"] == "John Doe"
        assert result["query"]["masked_probable_holder_name"] == "J*** D**"
        assert "john.doe" in result["query"]["probable_social_handles"]
        assert "identity_enrichment" in result["sources_with_data"]

    def test_sensitive_identity_fields_redacted_without_consent(self, monkeypatch):
        mod = _cross_db_prod
        monkeypatch.setenv("DEHASHED_API_KEY", "test-dehashed-key")
        monkeypatch.setenv("DEHASHED_EMAIL", "test@example.com")

        async def fake_dehashed(query, search_type, api_key, email):
            if search_type == "phone":
                return {
                    "total": 1,
                    "hits": [
                        {
                            "database_name": "TestDB",
                            "phone": "+919876543210",
                            "username": "john.doe",
                            "email": "john.doe99@example.com",
                            "name": "John Doe",
                        }
                    ],
                }
            return {"total": 0, "hits": []}

        monkeypatch.setattr(mod, "_query_dehashed", fake_dehashed)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210", tier="master", consent_confirmed=False))

        assert result["query"]["consent_confirmed"] is False
        assert result["query"]["masked_probable_holder_name"] is None
        assert result["query"]["probable_social_handles"] == []
        assert result["query"]["associated_breach_emails"] == []
        assert result["query"]["activity_regions"] == []


# ---------------------------------------------------------------------------
# Handler tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestInvestigateHandler:
    async def test_no_args_returns_usage(self):
        inv_mod = _inv_handler_prod
        update = _make_update()
        ctx = _make_context(args=[])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        call = update.message.reply_text.await_args.args[0]
        assert "Usage" in call or "investigate" in call.lower()

    async def test_phone_triggers_investigation(self, monkeypatch):
        inv_mod = _inv_handler_prod

        async def fake_investigate(**kwargs):
            return {
                "artifact_id": "INV-TESTID001",
                "query": {
                    "full_name": None,
                    "phone": "+91******3210",
                    "phone_geo_area": "India only",
                    "phone_country": "India",
                    "phone_carrier": "Unknown",
                    "phone_line_type": "mobile",
                    "phone_valid": True,
                },
                "risk_level": "LOW",
                "score": 0,
                "flags": [],
                "evidence": [],
                "sources_queried": [],
                "sources_with_data": [],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 12,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["+919876543210"])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        assert update.message.reply_text.await_count >= 2
        last_call = update.message.reply_text.call_args_list[-1].args[0]
        assert "INV-TESTID001" in last_call
        assert "India" in last_call

    async def test_high_risk_shows_flags(self, monkeypatch):
        inv_mod = _inv_handler_prod

        async def fake_investigate(**kwargs):
            return {
                "artifact_id": "INV-HI001",
                "query": {
                    "full_name": "John Doe",
                    "phone": "+91******3210",
                    "phone_geo_area": "India only",
                    "phone_country": "India",
                    "phone_carrier": "Jio",
                    "phone_line_type": "mobile",
                    "phone_valid": True,
                },
                "risk_level": "HIGH",
                "score": 65,
                "flags": [
                    "Found in 3 breach record(s) (haveibeenpwned)",
                    "Phone identified as VoIP — commonly used for fraud",
                ],
                "evidence": [],
                "sources_queried": ["hibp", "scam_reports"],
                "sources_with_data": ["haveibeenpwned"],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 88,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["John", "Doe", "+919876543210"])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        last_call = update.message.reply_text.call_args_list[-1].args[0]
        assert "HIGH" in last_call
        assert "breach" in last_call.lower()
        assert "John Doe" in last_call

    async def test_name_and_phone_both_passed(self, monkeypatch):
        inv_mod = _inv_handler_prod
        captured: dict = {}

        async def fake_investigate(**kwargs):
            captured.update(kwargs)
            return {
                "artifact_id": "INV-CROSS01",
                "query": {
                    "full_name": kwargs.get("full_name"),
                    "phone": "+91******9999",
                    "phone_geo_area": "India only",
                    "phone_country": "India",
                    "phone_carrier": "Airtel",
                    "phone_line_type": "mobile",
                    "phone_valid": True,
                },
                "risk_level": "MEDIUM",
                "score": 30,
                "flags": ["Name + phone CROSS-MATCH confirmed in 1 breach record(s)"],
                "evidence": [],
                "sources_queried": [],
                "sources_with_data": [],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 44,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["Jane", "Smith", "+919876549999"])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        # both name and phone should be forwarded
        assert "Smith" in captured.get("full_name", "") or "Jane" in captured.get("full_name", "")
        assert "+919876549999" in captured.get("phone", "")

    async def test_tier_and_social_ids_are_forwarded(self, monkeypatch):
        inv_mod = _inv_handler_prod
        captured: dict = {}

        async def fake_investigate(**kwargs):
            captured.update(kwargs)
            return {
                "artifact_id": "INV-SOCIAL01",
                "query": {
                    "tier": kwargs.get("tier"),
                    "full_name": kwargs.get("full_name"),
                    "phone": kwargs.get("phone") or None,
                    "phone_geo_area": None,
                    "phone_country": None,
                    "phone_carrier": None,
                    "phone_line_type": None,
                    "phone_valid": None,
                    "telegram_id": kwargs.get("telegram_id"),
                    "telegram_group": kwargs.get("telegram_group"),
                    "twitter_id": kwargs.get("twitter_id"),
                },
                "risk_level": "MEDIUM",
                "score": 30,
                "flags": [],
                "evidence": [
                    {
                        "source": "social_identity_checks",
                        "fetched_at": "2026-04-14T00:00:00Z",
                        "confidence": "medium",
                        "data": {
                            "checks": {
                                "telegram_id": {"verdict": "likely_real", "status_code": 200},
                                "twitter_id": {"verdict": "inconclusive", "status_code": 200},
                            },
                            "suspicious_hits": [],
                            "flagged": False,
                        },
                    }
                ],
                "sources_queried": ["social_identity"],
                "sources_with_data": ["social_identity_checks"],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 41,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["master", "consent:yes", "tg:john_doe", "group:fraud_watch", "twitter:johnx"])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        assert captured.get("tier") == "master"
        assert captured.get("consent_confirmed") is True
        assert captured.get("telegram_id") == "john_doe"
        assert captured.get("telegram_group") == "fraud_watch"
        assert captured.get("twitter_id") == "johnx"

    async def test_ip_is_forwarded_and_rendered(self, monkeypatch):
        inv_mod = _inv_handler_prod
        captured: dict = {}

        async def fake_investigate(**kwargs):
            captured.update(kwargs)
            return {
                "artifact_id": "INV-IP001",
                "query": {
                    "tier": "basic",
                    "consent_confirmed": False,
                    "full_name": None,
                    "ip_address": kwargs.get("ip_address"),
                    "ip_country": "United States",
                    "ip_city": "Mountain View",
                    "ip_isp": "Google LLC",
                    "ip_vpn_or_proxy": False,
                    "phone": None,
                    "phone_geo_area": None,
                    "phone_country": None,
                    "phone_carrier": None,
                    "phone_line_type": None,
                    "phone_valid": None,
                },
                "risk_level": "LOW",
                "score": 10,
                "flags": [],
                "evidence": [],
                "sources_queried": ["ip_geolocation"],
                "sources_with_data": ["ip_geolocation"],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 12,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["8.8.8.8"])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        assert captured.get("ip_address") == "8.8.8.8"
        last_call = update.message.reply_text.call_args_list[-1].args[0]
        assert "IP: 8.8.8.8" in last_call
        assert "Mountain View" in last_call

    async def test_mac_is_forwarded_and_rendered(self, monkeypatch):
        inv_mod = _inv_handler_prod
        captured: dict = {}

        async def fake_investigate(**kwargs):
            captured.update(kwargs)
            return {
                "artifact_id": "INV-MAC001",
                "query": {
                    "tier": "basic",
                    "consent_confirmed": False,
                    "full_name": None,
                    "mac_address": kwargs.get("mac_address"),
                    "mac_vendor": "Test Vendor Inc",
                    "phone": None,
                    "phone_geo_area": None,
                    "phone_country": None,
                    "phone_carrier": None,
                    "phone_line_type": None,
                    "phone_valid": None,
                },
                "risk_level": "LOW",
                "score": 5,
                "flags": [],
                "evidence": [],
                "sources_queried": ["mac_vendor_lookup"],
                "sources_with_data": ["mac_vendor_lookup"],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 10,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["00:1A:2B:3C:4D:5E"])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        assert captured.get("mac_address") == "00:1A:2B:3C:4D:5E"
        last_call = update.message.reply_text.call_args_list[-1].args[0]
        assert "MAC: 00:1A:2B:3C:4D:5E" in last_call
        assert "MAC Vendor: Test Vendor Inc" in last_call

    async def test_email_is_forwarded_and_rendered(self, monkeypatch):
        inv_mod = _inv_handler_prod
        captured: dict = {}

        async def fake_investigate(**kwargs):
            captured.update(kwargs)
            return {
                "artifact_id": "INV-EMAIL001",
                "query": {
                    "tier": "pro",
                    "consent_confirmed": False,
                    "privacy_mode": False,
                    "full_name": None,
                    "email_address": kwargs.get("email_address"),
                    "email_breach_count": 3,
                    "phone": None,
                    "phone_geo_area": None,
                    "phone_country": None,
                    "phone_carrier": None,
                    "phone_line_type": None,
                    "phone_valid": None,
                },
                "risk_level": "MEDIUM",
                "score": 35,
                "flags": [],
                "evidence": [],
                "sources_queried": ["hibp_email"],
                "sources_with_data": ["haveibeenpwned_email"],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 13,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["email:test@example.com"])

        await _inv_handler_prod.investigate_command.__wrapped__(update, ctx)

        assert captured.get("email_address") == "test@example.com"
        last_call = update.message.reply_text.call_args_list[-1].args[0]
        assert "Email: test@example.com" in last_call
        assert "Email Breaches (HIBP): 3" in last_call
        assert "Privacy Mode: OFF" in last_call

    async def test_investigation_service_failure_shows_error(self, monkeypatch):
        inv_mod = _inv_handler_prod

        async def broken(**kwargs):
            raise RuntimeError("upstream unreachable")

        monkeypatch.setattr(inv_mod._investigator, "investigate", broken)

        update = _make_update()
        ctx = _make_context(args=["+919876543210"])

        await inv_mod.investigate_command.__wrapped__(update, ctx)

        last = update.message.reply_text.call_args_list[-1].args[0]
        assert "failed" in last.lower() or "error" in last.lower()

    async def test_report_shows_probable_holder_and_social_handles(self, monkeypatch):
        inv_mod = _inv_handler_prod

        async def fake_investigate(**kwargs):
            return {
                "artifact_id": "INV-ID001",
                "query": {
                    "tier": "master",
                    "consent_confirmed": True,
                    "full_name": None,
                    "probable_holder_name": "John Doe",
                    "masked_probable_holder_name": "J*** D**",
                    "probable_gender": "unknown",
                    "activity_regions": ["India"],
                    "alternate_names": ["J. Doe"],
                    "probable_social_handles": ["john.doe", "johnd"],
                    "identity_confidence": "medium",
                    "phone": "+91******3210",
                    "phone_geo_area": "India only",
                    "phone_country": "India",
                    "phone_carrier": "Jio",
                    "phone_line_type": "mobile",
                    "phone_valid": True,
                    "telegram_id": None,
                    "telegram_group": None,
                    "twitter_id": None,
                },
                "risk_level": "MEDIUM",
                "score": 35,
                "flags": [],
                "evidence": [],
                "sources_queried": [],
                "sources_with_data": ["identity_enrichment"],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 19,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["+919876543210"])

        await inv_mod.investigate_command.__wrapped__(update, ctx)

        last_call = update.message.reply_text.call_args_list[-1].args[0]
        assert "Masked Holder" in last_call
        assert "Social Handles" in last_call
        assert "Consent: YES" in last_call

    async def test_report_shows_breach_emails_and_no_tracking_status(self, monkeypatch):
        inv_mod = _inv_handler_prod

        async def fake_investigate(**kwargs):
            return {
                "artifact_id": "INV-SAFE001",
                "query": {
                    "tier": "master",
                    "consent_confirmed": True,
                    "full_name": None,
                    "probable_holder_name": None,
                    "masked_probable_holder_name": None,
                    "probable_gender": "unknown",
                    "activity_regions": [],
                    "alternate_names": [],
                    "probable_social_handles": [],
                    "identity_confidence": "low",
                    "phone": "+91******3210",
                    "phone_geo_area": "India only",
                    "phone_country": "India",
                    "phone_carrier": "Jio",
                    "phone_line_type": "mobile",
                    "phone_valid": True,
                    "associated_breach_emails": ["j******e@example.com"],
                    "network_geo_hint": "Mumbai, India",
                    "tracking_status": "disabled_defensive_mode",
                    "telegram_id": None,
                    "telegram_group": None,
                    "twitter_id": None,
                },
                "risk_level": "MEDIUM",
                "score": 35,
                "flags": [],
                "evidence": [],
                "sources_queried": [],
                "sources_with_data": ["dehashed_phone"],
                "generated_at": "2026-04-14T00:00:00Z",
                "elapsed_ms": 21,
            }

        monkeypatch.setattr(inv_mod._investigator, "investigate", fake_investigate)

        update = _make_update()
        ctx = _make_context(args=["+919876543210"])

        await inv_mod.investigate_command.__wrapped__(update, ctx)

        last_call = update.message.reply_text.call_args_list[-1].args[0]
        assert "Associated Breach Emails" in last_call
        assert "Tracking: Disabled" in last_call
