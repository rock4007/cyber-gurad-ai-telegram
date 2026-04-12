import logging
import os
import re
from datetime import datetime, timezone

from telegram import BotCommand, KeyboardButton, ReplyKeyboardMarkup, Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from config import settings
from handlers.file import register_file_handlers
from handlers.image import register_image_handlers
from handlers.phone import maybe_handle_phone_text, register_phone_handlers
from handlers.social import maybe_handle_social_message, register_social_handlers
from handlers.start import help_command, register_start_handlers, start_command
from handlers.url import maybe_handle_url_message, register_url_handlers
from handlers.voice import register_voice_handlers
from middleware.guards import check_text_policy
from middleware.moderation import register_moderation_middleware
from middleware.quota import check_quota, quota_guard
from services.formatter import format_scan_result
from services.scanner import ScannerService


logger = logging.getLogger("cyberguard.main")
scanner = ScannerService(settings.backend_url)
user_language_preferences: dict[int, str] = {}


async def scan_menu_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    keyboard = [
        [KeyboardButton("Send URL/Text")],
        [KeyboardButton("Send Social Profile")],
        [KeyboardButton("Send Contact", request_contact=True)],
        [KeyboardButton("Send Image"), KeyboardButton("Send File")],
        [KeyboardButton("Send Voice")],
    ]
    markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)
    await update.message.reply_text(
        "Choose scan input type and send user-provided content only.",
        reply_markup=markup,
    )


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    user_key = str(update.effective_user.id) if update.effective_user else "0"
    remaining = await quota_guard.remaining(user_key)
    await update.message.reply_text(
        f"Monthly quota remaining: {remaining} scans"
    )


async def language_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    if not update.effective_user:
        await update.message.reply_text("Unable to set language for unknown user.")
        return

    lang = (" ".join(context.args).strip() or "en").lower()
    user_language_preferences[update.effective_user.id] = lang
    await update.message.reply_text(f"Language preference set to: {lang}")


async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return

    details = " ".join(context.args).strip()
    if not details:
        await update.message.reply_text("Usage: /report <scam details>")
        return

    report_text = (
        f"Scam report from user {update.effective_user.id if update.effective_user else 'unknown'}:\n"
        f"{details}"
    )
    for admin_id in settings.admin_ids:
        try:
            await context.bot.send_message(chat_id=admin_id, text=report_text)
        except Exception:
            logger.exception("Failed to forward report to admin_id=%s", admin_id)

    await update.message.reply_text("Report received. Thank you for helping keep users safe.")


def _contains_url(text: str) -> bool:
    return bool(re.search(r"(https?://\S+|www\.\S+)", text, re.IGNORECASE))


@check_quota
async def text_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text:
        return

    text = update.message.text.strip()
    if not text:
        return

    if await maybe_handle_social_message(update, context, text):
        return

    if await maybe_handle_url_message(update, context, text):
        return

    if await maybe_handle_phone_text(update, context, text):
        return

    ok, error_message = check_text_policy(update, text)
    if not ok:
        await update.message.reply_text(error_message)
        return

    scan_mode = str(context.user_data.get("scan_mode", "")).lower()
    if scan_mode == "phone":
        prefix = "Phone number submitted for fraud analysis: "
    elif scan_mode == "url":
        prefix = "URL submitted for fraud analysis: "
    elif scan_mode == "social":
        prefix = "Social media content submitted for fraud analysis: "
    else:
        prefix = "URL/text submitted for fraud analysis: " if _contains_url(text) else "Text submitted for fraud analysis: "

    await update.message.reply_text("Analyzing message...")

    try:
        scan_payload = await scanner.analyze_text(
            content=prefix + text,
            source="telegram",
            external_user_id=str(update.effective_user.id) if update.effective_user else None,
        )
    except Exception as exc:
        await update.message.reply_text(f"Scan failed: {exc}")
        return

    if scan_mode in {"phone", "url", "social"}:
        context.user_data.pop("scan_mode", None)

    await update.message.reply_text(format_scan_result(scan_payload))


@check_quota
async def contact_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.contact:
        return

    phone_number = update.message.contact.phone_number or "unknown"
    content = f"Phone contact submitted for fraud analysis: {phone_number}"

    ok, error_message = check_text_policy(update, content)
    if not ok:
        await update.message.reply_text(error_message)
        return

    await update.message.reply_text("Analyzing phone contact...")
    try:
        scan_payload = await scanner.analyze_text(
            content=content,
            source="telegram",
            external_user_id=str(update.effective_user.id) if update.effective_user else None,
        )
    except Exception as exc:
        await update.message.reply_text(f"Scan failed: {exc}")
        return

    await update.message.reply_text(format_scan_result(scan_payload))


async def post_init(application: Application) -> None:
    commands = [
        BotCommand("start", "Start CyberGuard AI"),
        BotCommand("help", "Show help"),
        BotCommand("scan", "Show scan menu"),
        BotCommand("social", "Scan social media profile/message"),
        BotCommand("status", "Show quota status"),
        BotCommand("language", "Set language preference"),
        BotCommand("report", "Report a scam"),
    ]
    await application.bot.set_my_commands(commands)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    logger.exception("[%s] Unhandled bot error", timestamp, exc_info=context.error)

    error_text = f"[{timestamp}] Bot error: {context.error}"
    for admin_id in settings.admin_ids:
        try:
            await context.bot.send_message(chat_id=admin_id, text=error_text)
        except Exception:
            logger.exception("Failed to notify admin_id=%s about error", admin_id)

    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "Something went wrong while processing your request. Please try again shortly."
            )
        except Exception:
            logger.exception("Failed to send friendly error message to user")


def build_application() -> Application:
    application = ApplicationBuilder().token(settings.bot_token).post_init(post_init).build()

    register_moderation_middleware(application)

    register_start_handlers(application)
    register_phone_handlers(application)
    register_social_handlers(application)
    register_url_handlers(application)
    register_file_handlers(application)
    register_image_handlers(application)
    register_voice_handlers(application)
    application.add_handler(CommandHandler("scan", scan_menu_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("language", language_command))
    application.add_handler(CommandHandler("report", report_command))

    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, text_message_handler)
    )
    application.add_handler(MessageHandler(filters.CONTACT, contact_message_handler))

    application.add_error_handler(on_error)

    return application


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )

    print("CyberGuard AI Telegram bot starting...")
    app = build_application()
    if settings.environment == "production":
        webhook_url = os.getenv("WEBHOOK_URL", "").strip()
        if not webhook_url:
            raise RuntimeError("WEBHOOK_URL is required when ENVIRONMENT=production")

        app.run_webhook(
            listen="0.0.0.0",
            port=int(os.getenv("PORT", "8000")),
            url_path=settings.bot_token,
            webhook_url=f"{webhook_url.rstrip('/')}/{settings.bot_token}",
        )
    else:
        app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
