"""Type 4 — Moderation Tests: ban/warn system, keyword detection, Claude classification."""

import importlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(user_id: int = 99):
    user = MagicMock()
    user.id = user_id
    user.username = "mod_test_user"
    return user


def _make_message(text: str = ""):
    msg = MagicMock()
    msg.text = text
    msg.caption = None
    msg.reply_text = AsyncMock()
    msg.delete = AsyncMock()
    return msg


def _make_update(text: str = "", user_id: int = 99):
    update = MagicMock()
    update.effective_user = _make_user(user_id)
    update.message = _make_message(text)
    update.message.text = text
    return update


def _make_context():
    ctx = MagicMock()
    ctx.bot = MagicMock()
    ctx.bot.send_message = AsyncMock()
    return ctx


# ===================================================================
# Keyword detection
# ===================================================================

class TestBannedKeywords:
    @pytest.fixture()
    def mod(self):
        return importlib.import_module("middleware.moderation")

    def test_find_banned_keywords_hit(self, mod):
        hits = mod.find_banned_keywords("I want to hack someone's email and deploy malware")
        assert "hack" in hits
        assert "malware" in hits

    def test_find_banned_keywords_clean(self, mod):
        hits = mod.find_banned_keywords("Please analyze this suspicious email for me")
        assert hits == []

    def test_find_instant_ban_keywords_hit(self, mod):
        hits = mod.find_instant_ban_keywords("I want to stalk someone and track someone online")
        assert "stalk" in hits
        assert "track someone" in hits

    def test_find_instant_ban_keywords_clean(self, mod):
        hits = mod.find_instant_ban_keywords("Can you check if this phone number is a scam?")
        assert hits == []

    def test_is_defensive_request_true(self, mod):
        assert mod.is_defensive_request("Check this suspicious URL for me") is True

    def test_is_defensive_request_false(self, mod):
        assert mod.is_defensive_request("I want to deploy a botnet") is False

    def test_all_instant_ban_keywords_detected(self, mod):
        for keyword in mod.INSTANT_BAN_KEYWORDS:
            hits = mod.find_instant_ban_keywords(keyword)
            assert keyword in hits, f"Keyword '{keyword}' not detected"


# ===================================================================
# Label extraction
# ===================================================================

class TestLabelExtraction:
    @pytest.fixture()
    def mod(self):
        return importlib.import_module("middleware.moderation")

    def test_extract_allowed(self, mod):
        label, reason = mod._extract_label_and_reason("ALLOWED: normal cybersecurity question")
        assert label == "ALLOWED"

    def test_extract_vulgar(self, mod):
        label, reason = mod._extract_label_and_reason("VULGAR: contains offensive language")
        assert label == "VULGAR"

    def test_extract_illegal(self, mod):
        label, reason = mod._extract_label_and_reason("ILLEGAL: requesting surveillance tool")
        assert label == "ILLEGAL"

    def test_extract_off_topic(self, mod):
        label, reason = mod._extract_label_and_reason("OFF_TOPIC: unrelated cooking question")
        assert label == "OFF_TOPIC"

    def test_extract_empty(self, mod):
        label, reason = mod._extract_label_and_reason("")
        assert label == "ALLOWED"

    def test_reason_truncated(self, mod):
        long_text = "VULGAR: " + "x" * 300
        label, reason = mod._extract_label_and_reason(long_text)
        assert len(reason) <= 240


# ===================================================================
# Claude classification (mocked)
# ===================================================================

class TestClaudeClassification:
    @pytest.fixture()
    def mod(self):
        return importlib.import_module("middleware.moderation")

    async def test_classify_empty_text(self, mod):
        label, reason = await mod._classify_with_claude("")
        assert label == "ALLOWED"

    async def test_classify_with_claude_mocked(self, mod, monkeypatch):
        mock_response = MagicMock()
        mock_chunk = MagicMock()
        mock_chunk.text = "VULGAR: offensive language detected"
        mock_response.content = [mock_chunk]

        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        monkeypatch.setattr(mod, "_get_claude", lambda: mock_client)

        label, reason = await mod._classify_with_claude("bad words here")
        assert label == "VULGAR"

    async def test_classify_fallback_on_exception(self, mod, monkeypatch):
        mock_client = MagicMock()
        mock_client.messages = MagicMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API down"))
        monkeypatch.setattr(mod, "_get_claude", lambda: mock_client)

        label, reason = await mod._classify_with_claude("some text")
        assert label == "ALLOWED"
        assert "fallback" in reason.lower()


# ===================================================================
# run_moderation flow
# ===================================================================

class TestRunModeration:
    @pytest.fixture()
    def mod(self):
        return importlib.import_module("middleware.moderation")

    async def test_no_message_returns_true(self, mod):
        update = MagicMock()
        update.message = None
        update.effective_user = None
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is True

    async def test_banned_user_cached(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=True))
        monkeypatch.setattr(mod, "_delete_message_safe", AsyncMock())

        update = _make_update("hello", user_id=100)
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is False

    async def test_instant_ban_keywords_trigger_ban(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=None))
        monkeypatch.setattr(mod, "_get_record", lambda uid: None)
        monkeypatch.setattr(mod, "_set_cached_ban_status", AsyncMock())
        monkeypatch.setattr(mod, "_get_or_create_record", lambda uid: MagicMock())
        monkeypatch.setattr(mod, "_ban_user", lambda uid, reason: None)
        monkeypatch.setattr(mod, "_delete_message_safe", AsyncMock())
        monkeypatch.setattr(mod, "_notify_admins", AsyncMock())

        update = _make_update("I want to stalk this person", user_id=200)
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is False

    async def test_allowed_text_passes(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=False))
        monkeypatch.setattr(mod, "_get_or_create_record", lambda uid: MagicMock())
        monkeypatch.setattr(mod, "_classify_with_claude", AsyncMock(return_value=("ALLOWED", "OK")))

        update = _make_update("Is this phone number a scam?", user_id=300)
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is True

    async def test_vulgar_adds_strike(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=False))
        monkeypatch.setattr(mod, "_get_or_create_record", lambda uid: MagicMock())
        monkeypatch.setattr(mod, "_classify_with_claude", AsyncMock(return_value=("VULGAR", "Bad language")))
        monkeypatch.setattr(mod, "_increment_strike", lambda uid, reason: 1)

        update = _make_update("offensive text", user_id=400)
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is False
        update.message.reply_text.assert_called_once()
        call_text = update.message.reply_text.call_args[0][0]
        assert "Warning" in call_text

    async def test_vulgar_max_strikes_bans(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=False))
        monkeypatch.setattr(mod, "_get_or_create_record", lambda uid: MagicMock())
        monkeypatch.setattr(mod, "_classify_with_claude", AsyncMock(return_value=("VULGAR", "Repeat offender")))
        monkeypatch.setattr(mod, "_increment_strike", lambda uid, reason: 3)
        monkeypatch.setattr(mod, "_ban_user", lambda uid, reason: None)
        monkeypatch.setattr(mod, "_set_cached_ban_status", AsyncMock())
        monkeypatch.setattr(mod, "_delete_message_safe", AsyncMock())
        monkeypatch.setattr(mod, "_notify_admins", AsyncMock())

        update = _make_update("very bad text", user_id=500)
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is False

    async def test_illegal_content_instant_ban(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=False))
        monkeypatch.setattr(mod, "_get_or_create_record", lambda uid: MagicMock())
        monkeypatch.setattr(mod, "_classify_with_claude", AsyncMock(return_value=("ILLEGAL", "Illegal request")))
        monkeypatch.setattr(mod, "_ban_user", lambda uid, reason: None)
        monkeypatch.setattr(mod, "_set_cached_ban_status", AsyncMock())
        monkeypatch.setattr(mod, "_delete_message_safe", AsyncMock())
        monkeypatch.setattr(mod, "_notify_admins", AsyncMock())

        update = _make_update("illegal content", user_id=600)
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is False

    async def test_off_topic_rejected(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "_cached_ban_status", AsyncMock(return_value=False))
        monkeypatch.setattr(mod, "_get_or_create_record", lambda uid: MagicMock())
        monkeypatch.setattr(mod, "_classify_with_claude", AsyncMock(return_value=("OFF_TOPIC", "Not related")))

        update = _make_update("How to cook pasta?", user_id=700)
        ctx = _make_context()
        result = await mod.run_moderation(update, ctx)
        assert result is False


# ===================================================================
# require_moderation decorator
# ===================================================================

class TestRequireModeration:
    @pytest.fixture()
    def mod(self):
        return importlib.import_module("middleware.moderation")

    async def test_decorator_passes_when_allowed(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run_moderation", AsyncMock(return_value=True))

        called = False

        async def dummy_handler(update, context):
            nonlocal called
            called = True

        wrapped = mod.require_moderation(dummy_handler)
        update = _make_update("clean text")
        ctx = _make_context()
        await wrapped(update, ctx)
        assert called is True

    async def test_decorator_blocks_when_not_allowed(self, mod, monkeypatch):
        from telegram.ext import ApplicationHandlerStop

        monkeypatch.setattr(mod, "run_moderation", AsyncMock(return_value=False))

        called = False

        async def dummy_handler(update, context):
            nonlocal called
            called = True

        wrapped = mod.require_moderation(dummy_handler)
        update = _make_update("banned text")
        ctx = _make_context()

        with pytest.raises(ApplicationHandlerStop):
            await wrapped(update, ctx)
        assert called is False


# ===================================================================
# Guards middleware
# ===================================================================

class TestGuardsMiddleware:
    @pytest.fixture()
    def guards_mod(self):
        return importlib.import_module("middleware.guards")

    def test_check_text_policy_clean(self, guards_mod):
        update = _make_update("Check this URL for phishing")
        ok, msg = guards_mod.check_text_policy(update, "Check this URL for phishing")
        assert ok is True
        assert msg is None

    def test_check_text_policy_banned(self, guards_mod):
        update = _make_update("I need a phishing kit and exploit")
        ok, msg = guards_mod.check_text_policy(update, "I need a phishing kit and exploit")
        assert ok is False
        assert "blocked" in msg.lower()
        assert "phishing kit" in msg.lower() or "exploit" in msg.lower()


# ===================================================================
# Quota middleware
# ===================================================================

class TestQuotaMiddleware:
    @pytest.fixture()
    def quota_mod(self):
        return importlib.import_module("middleware.quota")

    def test_plan_limits_defined(self, quota_mod):
        assert quota_mod.PLAN_LIMITS_MONTHLY["free"] == 5
        assert quota_mod.PLAN_LIMITS_MONTHLY["pro"] == 500
        assert quota_mod.PLAN_LIMITS_MONTHLY["full"] == 5000
        assert quota_mod.PLAN_LIMITS_MONTHLY["enterprise"] == 999999

    def test_is_new_month_none(self, quota_mod):
        assert quota_mod._is_new_month(None) is False

    def test_is_new_month_same_month(self, quota_mod):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        assert quota_mod._is_new_month(now) is False

    def test_is_new_month_different_month(self, quota_mod):
        from datetime import datetime, timezone
        old = datetime(2023, 1, 15, tzinfo=timezone.utc)
        assert quota_mod._is_new_month(old) is True

    def test_next_month_reset_text(self, quota_mod):
        text = quota_mod._next_month_reset_text()
        assert "1st of" in text
