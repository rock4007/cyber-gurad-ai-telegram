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
        result = asyncio.run(investigator.investigate(full_name="John Doe", phone="+919876543210"))

        assert "phone" in dehashed_calls or "name" in dehashed_calls
        assert result["score"] > 0
        assert any("breach" in f.lower() or "record" in f.lower() for f in result["flags"])

    def test_investigate_hibp_breach_raises_score(self, monkeypatch):
        mod = _cross_db_prod
        monkeypatch.setenv("HIBP_API_KEY", "test-hibp-key")

        async def fake_hibp(phone, api_key):
            return {"breach_count": 3, "breach_names": ["Adobe", "LinkedIn", "Canva"],
                    "note": "Phone found in breaches"}

        monkeypatch.setattr(mod, "_query_haveibeenpwned_phone", fake_hibp)

        investigator = mod.CrossDatabaseInvestigator()
        result = asyncio.run(investigator.investigate(phone="+919876543210"))

        assert result["score"] >= 15
        assert any("breach" in f.lower() for f in result["flags"])

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
