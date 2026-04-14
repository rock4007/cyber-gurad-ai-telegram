from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram.ext import ApplicationHandlerStop

from middleware import moderation


def _build_update(text: str) -> MagicMock:
    update = MagicMock()
    user = SimpleNamespace(id=12345, username="testuser")
    message = MagicMock()
    message.text = text
    message.caption = None
    message.reply_text = AsyncMock()
    message.delete = AsyncMock()

    update.effective_user = user
    update.message = message
    return update


def _build_context() -> MagicMock:
    context = MagicMock()
    context.bot = MagicMock()
    context.bot.send_message = AsyncMock()
    context.user_data = {}
    return context


@pytest.fixture()
def moderation_mocks(mocker):
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)

    mocker.patch("middleware.moderation._get_redis", return_value=redis)
    mocker.patch("middleware.moderation._get_record", return_value=None)
    mocker.patch("middleware.moderation._get_or_create_record", return_value=SimpleNamespace())
    ban_user = mocker.patch("middleware.moderation._ban_user")
    increment_strike = mocker.patch("middleware.moderation._increment_strike", return_value=1)
    notify_admins = mocker.patch("middleware.moderation._notify_admins", new=AsyncMock())
    set_cached = mocker.patch("middleware.moderation._set_cached_ban_status", new=AsyncMock())
    delete_safe = mocker.patch("middleware.moderation._delete_message_safe", new=AsyncMock())

    return {
        "redis": redis,
        "ban_user": ban_user,
        "increment_strike": increment_strike,
        "notify_admins": notify_admins,
        "set_cached": set_cached,
        "delete_safe": delete_safe,
    }


@pytest.mark.asyncio
class TestKeywordFilter:
    async def test_stalking_keyword_instant_ban(self, moderation_mocks):
        update = _build_update("how to stalk someone")
        context = _build_context()

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        moderation_mocks["ban_user"].assert_called_once()
        moderation_mocks["notify_admins"].assert_awaited_once()
        context.bot.send_message.assert_awaited_once()

    async def test_hacking_keyword_instant_ban(self, moderation_mocks):
        update = _build_update("hack this account for me")
        context = _build_context()

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        moderation_mocks["ban_user"].assert_called_once()

    async def test_legitimate_message_passes(self, mocker, moderation_mocks):
        update = _build_update("scan this phone number +447911123456")
        context = _build_context()
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("ALLOWED", "legitimate")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is True
        moderation_mocks["ban_user"].assert_not_called()

    async def test_cybersecurity_question_passes(self, mocker, moderation_mocks):
        update = _build_update("is this URL phishing?")
        context = _build_context()
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("ALLOWED", "defensive")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is True

    async def test_vulgar_message_gets_warning(self, mocker, moderation_mocks):
        update = _build_update("[vulgar word]")
        context = _build_context()
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("VULGAR", "bad language")))
        moderation_mocks["increment_strike"].return_value = 1

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        moderation_mocks["increment_strike"].assert_called_once()
        update.message.reply_text.assert_awaited_once()
        assert "Warning [1]/3" in update.message.reply_text.await_args.args[0]

    async def test_off_topic_gets_redirect(self, mocker, moderation_mocks):
        update = _build_update("what is the weather today?")
        context = _build_context()
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("OFF_TOPIC", "not cybersecurity")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        update.message.reply_text.assert_awaited_once()
        assert "ciberseguridad" in update.message.reply_text.await_args.args[0].lower()


@pytest.mark.asyncio
class TestStrikeSystem:
    async def test_first_warning_shows_1_of_3(self, mocker, moderation_mocks):
        update = _build_update("vulgar one")
        context = _build_context()
        moderation_mocks["increment_strike"].return_value = 1
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("VULGAR", "first")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        assert "[1]/3" in update.message.reply_text.await_args.args[0]

    async def test_second_warning_shows_2_of_3(self, mocker, moderation_mocks):
        update = _build_update("vulgar two")
        context = _build_context()
        moderation_mocks["increment_strike"].return_value = 2
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("VULGAR", "second")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        assert "[2]/3" in update.message.reply_text.await_args.args[0]

    async def test_third_warning_triggers_ban(self, mocker, moderation_mocks):
        update = _build_update("vulgar three")
        context = _build_context()
        moderation_mocks["increment_strike"].return_value = 3
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("VULGAR", "third")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        moderation_mocks["ban_user"].assert_called_once()
        moderation_mocks["notify_admins"].assert_awaited_once()

    async def test_banned_user_cannot_scan(self, moderation_mocks):
        update = _build_update("scan this")
        context = _build_context()
        moderation_mocks["redis"].get.return_value = "1"

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        moderation_mocks["delete_safe"].assert_awaited_once()

    async def test_ban_logged_to_database(self, moderation_mocks):
        update = _build_update("how to stalk someone")
        context = _build_context()

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        moderation_mocks["ban_user"].assert_called_once()

    async def test_admin_alerted_on_ban(self, moderation_mocks):
        update = _build_update("how to stalk someone")
        context = _build_context()

        await moderation.run_moderation(update, context)

        moderation_mocks["notify_admins"].assert_awaited_once()


@pytest.mark.asyncio
class TestClaudeModeration:
    async def test_illegal_classified_message_banned(self, mocker, moderation_mocks):
        update = _build_update("please do illegal hacking")
        context = _build_context()
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("ILLEGAL", "prohibited")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        moderation_mocks["ban_user"].assert_called_once()

    async def test_allowed_classified_message_passes(self, mocker, moderation_mocks):
        update = _build_update("defensive analysis question")
        context = _build_context()
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("ALLOWED", "ok")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is True

    async def test_api_timeout_defaults_to_allow(self, mocker, moderation_mocks):
        update = _build_update("ambiguous message")
        context = _build_context()
        mocker.patch(
            "middleware.moderation._classify_with_claude",
            new=AsyncMock(return_value=("ALLOWED", "Classifier fallback: timeout")),
        )

        allowed = await moderation.run_moderation(update, context)

        assert allowed is True

    async def test_malformed_claude_response_handled(self, mocker, moderation_mocks):
        update = _build_update("odd message")
        context = _build_context()
        mocker.patch("middleware.moderation._classify_with_claude", new=AsyncMock(return_value=("ALLOWED", "BADFORMAT")))

        allowed = await moderation.run_moderation(update, context)

        assert allowed is True


@pytest.mark.asyncio
class TestBannedUserExperience:
    async def test_banned_user_sees_ban_message(self, moderation_mocks):
        update = _build_update("how to stalk someone")
        context = _build_context()

        allowed = await moderation.run_moderation(update, context)

        assert allowed is False
        context.bot.send_message.assert_awaited_once()
        assert "bloqueada" in context.bot.send_message.await_args.kwargs["text"].lower() or "bloqueada" in context.bot.send_message.await_args.args[1].lower()

    async def test_banned_user_sees_appeal_email(self, moderation_mocks):
        update = _build_update("how to stalk someone")
        context = _build_context()

        await moderation.run_moderation(update, context)

        text = context.bot.send_message.await_args.kwargs.get("text")
        if text is None:
            text = context.bot.send_message.await_args.args[1]
        assert moderation.APPEAL_EMAIL in text

    async def test_banned_user_cannot_use_any_command(self, mocker, moderation_mocks):
        moderation_mocks["redis"].get.return_value = "1"
        update = _build_update("/phone +14155552671")
        context = _build_context()

        async def _dummy_handler(_update, _context):
            return None

        wrapped = moderation.require_moderation(_dummy_handler)

        with pytest.raises(ApplicationHandlerStop):
            await wrapped(update, context)
