import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram import Chat, User

from handlers import file as file_handler
from handlers import phone, url


def _build_update_with_message(text: str = "") -> MagicMock:
    update = MagicMock()
    update.effective_user = User(id=12345, first_name="Test", is_bot=False, username="tester")
    update.effective_chat = Chat(id=777, type="private")

    message = MagicMock()
    message.text = text
    message.caption = None
    message.reply_text = AsyncMock()
    message.forward_origin = None
    update.message = message
    update.effective_message = message
    return update


def _build_context() -> MagicMock:
    context = MagicMock()
    context.args = []
    context.user_data = {}
    context.bot = MagicMock()
    context.bot.send_chat_action = AsyncMock()
    return context


@pytest.mark.asyncio
class TestPhoneHandler:
    async def test_valid_phone_triggers_scan(self, mocker):
        update = _build_update_with_message("+14155552671")
        context = _build_context()
        mocker.patch("handlers.phone.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.phone.scanner.analyze_text", new=AsyncMock(
            return_value={
                "result": {
                    "risk_level": "LOW",
                    "score": 20,
                    "flagged_indicators": [],
                    "recommended_actions": ["Be cautious"],
                }
            }
        ))

        handled = await phone._process_phone_text(update, context, "+14155552671")

        assert handled is True
        analyze.assert_awaited_once()

    async def test_invalid_phone_shows_format_guide(self, mocker):
        update = _build_update_with_message("+4412345")
        context = _build_context()
        mocker.patch("handlers.phone.check_text_policy", return_value=(True, ""))
        mocker.patch("handlers.phone._extract_phone_candidate", return_value="+4412345")

        handled = await phone._process_phone_text(update, context, "+4412345")

        assert handled is True
        update.message.reply_text.assert_awaited_once()
        assert "Invalid phone number format" in update.message.reply_text.await_args.args[0]

    async def test_scan_result_contains_risk_level(self, mocker):
        update = _build_update_with_message("+14155552671")
        context = _build_context()
        mocker.patch("handlers.phone.check_text_policy", return_value=(True, ""))
        mocker.patch(
            "handlers.phone.scanner.analyze_text",
            new=AsyncMock(
                return_value={
                    "result": {
                        "risk_level": "HIGH",
                        "score": 85,
                        "flagged_indicators": ["Known fraud pattern"],
                        "recommended_actions": ["Block caller"],
                    }
                }
            ),
        )

        await phone._process_phone_text(update, context, "+14155552671")
        rendered = update.message.reply_text.await_args.args[0]
        assert "HIGH" in rendered

    async def test_high_risk_shows_complaint_button(self, mocker):
        update = _build_update_with_message("+14155552671")
        context = _build_context()
        mocker.patch("handlers.phone.check_text_policy", return_value=(True, ""))
        mocker.patch("handlers.phone.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "HIGH", "score": 90}}))

        await phone._process_phone_text(update, context, "+14155552671")
        markup = update.message.reply_text.await_args.kwargs.get("reply_markup")
        callbacks = [b.callback_data for row in markup.inline_keyboard for b in row if getattr(b, "callback_data", None)]
        assert "phone_file_complaint" in callbacks

    async def test_low_risk_no_complaint_button(self, mocker):
        update = _build_update_with_message("+14155552671")
        context = _build_context()
        mocker.patch("handlers.phone.check_text_policy", return_value=(True, ""))
        mocker.patch("handlers.phone.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 10}}))

        await phone._process_phone_text(update, context, "+14155552671")
        markup = update.message.reply_text.await_args.kwargs.get("reply_markup")
        callbacks = [b.callback_data for row in markup.inline_keyboard for b in row if getattr(b, "callback_data", None)]
        assert "phone_file_complaint" not in callbacks

    async def test_api_timeout_shows_error_gracefully(self, mocker):
        update = _build_update_with_message("+14155552671")
        context = _build_context()
        mocker.patch("handlers.phone.check_text_policy", return_value=(True, ""))
        mocker.patch("handlers.phone.scanner.analyze_text", new=AsyncMock(side_effect=TimeoutError("timeout")))

        await phone._process_phone_text(update, context, "+14155552671")
        assert "Scan failed" in update.message.reply_text.await_args.args[0]


@pytest.mark.asyncio
class TestUrlHandler:
    async def test_http_url_triggers_scan(self, mocker):
        update = _build_update_with_message("http://example.com")
        context = _build_context()
        mocker.patch("handlers.url.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.url.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 10}}))

        handled = await url.maybe_handle_url_message(update, context, "http://example.com")

        assert handled is True
        analyze.assert_awaited_once()

    async def test_https_url_triggers_scan(self, mocker):
        update = _build_update_with_message("https://example.com")
        context = _build_context()
        mocker.patch("handlers.url.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.url.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 10}}))

        await url.maybe_handle_url_message(update, context, "https://example.com")
        analyze.assert_awaited_once()

    async def test_url_in_long_message_extracted(self, mocker):
        message = "Please check this urgently there is a suspicious login link https://example.com/login now"
        update = _build_update_with_message(message)
        context = _build_context()
        mocker.patch("handlers.url.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.url.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 10}}))

        await url.maybe_handle_url_message(update, context, message)
        analyze.assert_awaited_once()

    async def test_multiple_urls_all_scanned(self, mocker):
        message = "https://one.com and also http://two.com"
        update = _build_update_with_message(message)
        context = _build_context()
        mocker.patch("handlers.url.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.url.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 10}}))

        await url.maybe_handle_url_message(update, context, message)
        assert analyze.await_count == 2

    async def test_phishing_shows_red_warning(self, mocker):
        update = _build_update_with_message("https://phish.example")
        context = _build_context()
        mocker.patch("handlers.url.check_text_policy", return_value=(True, ""))
        mocker.patch(
            "handlers.url.scanner.analyze_text",
            new=AsyncMock(return_value={"result": {"risk_level": "HIGH", "score": 95, "flagged_indicators": ["Phishing"]}}),
        )

        await url.maybe_handle_url_message(update, context, "https://phish.example")
        text = update.message.reply_text.await_args.args[0]
        assert "🔴 DANGEROUS" in text

    async def test_safe_url_shows_green_result(self, mocker):
        update = _build_update_with_message("https://safe.example")
        context = _build_context()
        mocker.patch("handlers.url.check_text_policy", return_value=(True, ""))
        mocker.patch(
            "handlers.url.scanner.analyze_text",
            new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 5}}),
        )

        await url.maybe_handle_url_message(update, context, "https://safe.example")
        text = update.message.reply_text.await_args.args[0]
        assert "🟢 LOW" in text


@pytest.mark.asyncio
class TestFileHandler:
    async def test_pdf_upload_triggers_scan(self, mocker, tmp_path):
        update = _build_update_with_message()
        context = _build_context()

        doc = MagicMock()
        doc.file_name = "doc.pdf"
        doc.file_size = 1024
        tg_file = MagicMock()
        tg_file.download_to_drive = AsyncMock(side_effect=lambda p: open(p, "wb").write(b"abc"))
        doc.get_file = AsyncMock(return_value=tg_file)
        update.message.document = doc

        mocker.patch("handlers.file.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.file.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 8, "flagged_indicators": []}}))

        await file_handler.file_command.__wrapped__(update, context)
        analyze.assert_awaited_once()

    async def test_exe_upload_triggers_scan(self, mocker):
        update = _build_update_with_message()
        context = _build_context()
        doc = MagicMock()
        doc.file_name = "tool.exe"
        doc.file_size = 2048
        tg_file = MagicMock()
        tg_file.download_to_drive = AsyncMock(side_effect=lambda p: open(p, "wb").write(b"bin"))
        doc.get_file = AsyncMock(return_value=tg_file)
        update.message.document = doc

        mocker.patch("handlers.file.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.file.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "MEDIUM", "score": 40, "flagged_indicators": []}}))

        await file_handler.file_command.__wrapped__(update, context)
        analyze.assert_awaited_once()

    async def test_file_over_20mb_rejected(self, mocker):
        update = _build_update_with_message()
        context = _build_context()
        doc = MagicMock()
        doc.file_name = "big.pdf"
        doc.file_size = 25 * 1024 * 1024
        update.message.document = doc

        mocker.patch("handlers.file.check_text_policy", return_value=(True, ""))
        analyze = mocker.patch("handlers.file.scanner.analyze_text", new=AsyncMock())

        await file_handler.file_command.__wrapped__(update, context)
        assert "File too large" in update.message.reply_text.await_args.args[0]
        analyze.assert_not_awaited()

    async def test_temp_file_deleted_after_scan(self, mocker, tmp_path):
        update = _build_update_with_message()
        context = _build_context()

        temp_target = tmp_path / "scan.pdf"
        fd = os.open(str(temp_target), os.O_CREAT | os.O_RDWR)
        mocker.patch("handlers.file.tempfile.mkstemp", return_value=(fd, str(temp_target)))

        doc = MagicMock()
        doc.file_name = "doc.pdf"
        doc.file_size = 1024
        tg_file = MagicMock()
        tg_file.download_to_drive = AsyncMock(side_effect=lambda p: open(p, "wb").write(b"abc"))
        doc.get_file = AsyncMock(return_value=tg_file)
        update.message.document = doc

        mocker.patch("handlers.file.check_text_policy", return_value=(True, ""))
        mocker.patch("handlers.file.scanner.analyze_text", new=AsyncMock(return_value={"result": {"risk_level": "LOW", "score": 8, "flagged_indicators": []}}))

        await file_handler.file_command.__wrapped__(update, context)
        assert not temp_target.exists()

    async def test_malicious_file_shows_delete_warning(self, mocker):
        update = _build_update_with_message()
        context = _build_context()
        doc = MagicMock()
        doc.file_name = "trojan.exe"
        doc.file_size = 1024
        tg_file = MagicMock()
        tg_file.download_to_drive = AsyncMock(side_effect=lambda p: open(p, "wb").write(b"abc"))
        doc.get_file = AsyncMock(return_value=tg_file)
        update.message.document = doc

        mocker.patch("handlers.file.check_text_policy", return_value=(True, ""))
        mocker.patch(
            "handlers.file.scanner.analyze_text",
            new=AsyncMock(return_value={"result": {"risk_level": "HIGH", "score": 92, "flagged_indicators": ["Malware"]}}),
        )

        await file_handler.file_command.__wrapped__(update, context)
        rendered = update.message.reply_text.await_args.args[0]
        assert "DELETE this file immediately" in rendered
