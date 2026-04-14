from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram import Chat, User

from handlers import start


def _build_update(user_id: int = 12345, username: str = "tester", first_name: str = "Test") -> MagicMock:
    update = MagicMock()
    update.effective_user = User(id=user_id, first_name=first_name, is_bot=False, username=username)
    update.effective_chat = Chat(id=777, type="private")

    message = MagicMock()
    message.reply_text = AsyncMock()
    update.message = message

    callback_query = MagicMock()
    callback_query.answer = AsyncMock()
    callback_query.edit_message_text = AsyncMock()
    callback_query.message = message
    callback_query.data = "agree_terms"
    update.callback_query = callback_query
    return update


def _build_context() -> MagicMock:
    context = MagicMock()
    context.user_data = {}
    context.bot = MagicMock()
    context.bot.send_message = AsyncMock()
    return context


@pytest.mark.asyncio
class TestStartCommand:
    async def test_new_user_gets_welcome_message(self, mocker):
        update = _build_update()
        context = _build_context()

        create_user = mocker.patch("handlers.start._create_user", return_value=SimpleNamespace(id=1))
        mocker.patch("handlers.start._find_user", return_value=None)

        await start.start_command(update, context)

        update.message.reply_text.assert_awaited_once()
        sent_text = update.message.reply_text.await_args.args[0]
        sent_markup = update.message.reply_text.await_args.kwargs.get("reply_markup")
        assert "CyberGuard AI" in sent_text
        assert sent_markup is not None
        assert any("I Agree to Terms" in btn.text for row in sent_markup.inline_keyboard for btn in row)
        create_user.assert_called_once_with(update.effective_user.id, update.effective_user.username, update.effective_user.first_name)

    async def test_existing_user_gets_menu(self, mocker):
        update = _build_update()
        context = _build_context()
        existing = SimpleNamespace(first_name="Alice", plan="free", scans_used=2)
        mocker.patch("handlers.start._find_user", return_value=existing)

        await start.start_command(update, context)

        update.message.reply_text.assert_awaited_once()
        text = update.message.reply_text.await_args.args[0]
        markup = update.message.reply_text.await_args.kwargs.get("reply_markup")
        assert "Welcome back" in text
        assert "Scans remaining" in text
        buttons = [b.text for row in markup.inline_keyboard for b in row]
        assert "Phone" in buttons
        assert "URL" in buttons

    async def test_agreement_button_records_consent(self, mocker):
        update = _build_update()
        context = _build_context()
        agreed_user = SimpleNamespace(plan="free", scans_used=0, agreed_terms_at=datetime.now(timezone.utc))
        mark_agreed = mocker.patch("handlers.start._mark_terms_agreed", return_value=agreed_user)

        await start.agreement_button_handler(update, context)

        update.callback_query.answer.assert_awaited_once()
        mark_agreed.assert_called_once_with(update.effective_user.id)
        assert agreed_user.agreed_terms_at is not None
        update.callback_query.edit_message_text.assert_awaited_once()
        context.bot.send_message.assert_awaited_once()
        sent_text = context.bot.send_message.await_args.kwargs.get("text", "")
        assert "Scans remaining" in sent_text

    async def test_help_command_shows_all_commands(self):
        update = _build_update()
        context = _build_context()

        await start.help_command(update, context)

        update.message.reply_text.assert_awaited_once()
        help_text = update.message.reply_text.await_args.args[0]
        assert "/start" in help_text
        assert "/help" in help_text
        assert "/scan" in help_text
        assert "/social" in help_text
        assert "/status" in help_text

    async def test_status_command_shows_quota(self):
        # start.py does not expose a dedicated status_command; quota text is surfaced in the existing-user welcome flow.
        update = _build_update()
        existing = SimpleNamespace(first_name="Bob", plan="pro", scans_used=12)

        await start._send_existing_user_welcome(update.message, existing)

        update.message.reply_text.assert_awaited_once()
        sent_text = update.message.reply_text.await_args.args[0]
        assert "Plan:" in sent_text
        assert "Scans used:" in sent_text
        assert "Scans remaining:" in sent_text
