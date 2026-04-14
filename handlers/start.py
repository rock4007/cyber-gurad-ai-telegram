import asyncio
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes

from config import PLAN_LIMITS, settings
from database.models import Base, BotUser


engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base.metadata.create_all(engine)


def _main_scan_menu_markup() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Phone", callback_data="scan_phone"),
                InlineKeyboardButton("URL", callback_data="scan_url"),
            ],
            [
                InlineKeyboardButton("Social", callback_data="scan_social"),
                InlineKeyboardButton("File", callback_data="scan_file"),
            ],
            [
                InlineKeyboardButton("Image", callback_data="scan_image"),
                InlineKeyboardButton("Voice", callback_data="scan_voice"),
            ],
            [
                InlineKeyboardButton("Help", callback_data="open_help"),
            ],
        ]
    )


def _find_user(telegram_user_id: int) -> BotUser | None:
    with SessionLocal() as session:
        return session.execute(
            select(BotUser).where(BotUser.telegram_user_id == telegram_user_id)
        ).scalar_one_or_none()


def _create_user(telegram_user_id: int, username: str | None, first_name: str | None) -> BotUser:
    with SessionLocal() as session:
        user = BotUser(
            telegram_user_id=telegram_user_id,
            username=username,
            first_name=first_name,
            plan="free",
            scans_used=0,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def _mark_terms_agreed(telegram_user_id: int) -> BotUser | None:
    with SessionLocal() as session:
        user = session.execute(
            select(BotUser).where(BotUser.telegram_user_id == telegram_user_id)
        ).scalar_one_or_none()
        if not user:
            return None
        user.agreed_terms_at = datetime.now(timezone.utc)
        session.commit()
        session.refresh(user)
        return user


def _plan_remaining(plan: str, scans_used: int) -> int:
    plan_limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    return max(plan_limit - scans_used, 0)


async def _send_existing_user_welcome(message_target, user: BotUser) -> None:
    plan = user.plan
    remaining = _plan_remaining(plan, user.scans_used)
    first_name = user.first_name or "there"
    text = (
        f"*Welcome back, {first_name}!*\n\n"
        f"Plan: *{plan.title()}*\n"
        f"Scans used: *{user.scans_used}*\n"
        f"Scans remaining: *{remaining}*\n\n"
        "Select what you want to scan:"
    )
    await message_target.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=_main_scan_menu_markup(),
    )


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_user:
        return

    tg_user = update.effective_user
    existing_user = await asyncio.to_thread(_find_user, tg_user.id)

    if existing_user is None:
        await asyncio.to_thread(_create_user, tg_user.id, tg_user.username, tg_user.first_name)
        welcome_text = (
            "CyberGuard AI\n"
            "AI-powered scam protection\n\n"
            "What you can scan:\n"
            "- Suspicious phone numbers\n"
            "- Fraudulent URLs and text messages\n"
            "- Files, images, and voice content\n\n"
            "Platform rules:\n"
            "1. Defensive use only\n"
            "2. Scan only user-provided content\n"
            "3. No individual tracking or misuse"
        )
        keyboard = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("I Agree to Terms", callback_data="agree_terms")],
                [InlineKeyboardButton("Visit Website", url="https://cyberguard.ai")],
            ]
        )
        await update.message.reply_text(
            welcome_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=keyboard,
        )
        return

    await _send_existing_user_welcome(update.message, existing_user)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    help_text = (
        "*CyberGuard AI Help*\n\n"
        "Commands:\n"
        "/start - Start or resume your account\n"
        "/help - Show this help menu\n"
        "/scan - Show scan options\n"
        "/social - Scan a social profile/message\n"
        "/status - View your plan usage\n"
        "/language - Set your language preference\n"
        "/report - Report a scam\n\n"
        "How to use scans:\n"
        "- Phone: submit a number/contact for risk analysis\n"
        "- Social: submit @handle, profile URL, or suspicious social DM\n"
        "- URL/Text: send suspicious links or messages\n"
        "- File: upload suspicious documents\n"
        "- Image: upload screenshots/photos for analysis\n"
        "- Voice: upload suspicious voice messages\n\n"
        "Support: support@cyberguard.ai"
    )
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)


async def agreement_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query or not update.effective_user:
        return

    query = update.callback_query
    await query.answer()

    user = await asyncio.to_thread(_mark_terms_agreed, update.effective_user.id)
    if user is None:
        await query.edit_message_text(
            "Unable to record agreement. Please send /start again.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    await query.edit_message_text(
        "Agreement recorded successfully. You can now use CyberGuard AI scan features.",
        parse_mode=ParseMode.MARKDOWN,
    )

    remaining = _plan_remaining(user.plan, user.scans_used)
    menu_text = (
        f"Plan: *{user.plan.title()}*\n"
        f"Scans used: *{user.scans_used}*\n"
        f"Scans remaining: *{remaining}*\n\n"
        "Select what you want to scan:"
    )
    await context.bot.send_message(
        chat_id=update.effective_user.id,
        text=menu_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=_main_scan_menu_markup(),
    )


async def start_menu_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query:
        return
    query = update.callback_query
    await query.answer()

    if query.data == "scan_phone":
        context.user_data["scan_mode"] = "phone"
        await query.message.reply_text(
            "Phone scan mode enabled. Send a phone number now, or share a contact."
        )
        return

    if query.data == "scan_url":
        context.user_data["scan_mode"] = "url"
        await query.message.reply_text(
            "URL scan mode enabled. Send a suspicious link or message now."
        )
        return

    if query.data == "scan_social":
        context.user_data["scan_mode"] = "social"
        await query.message.reply_text(
            "Social scan mode enabled. Send @handle, profile URL, or suspicious social message now."
        )
        return

    if query.data == "scan_file":
        context.user_data["scan_mode"] = "file"
        await query.message.reply_text(
            "File scan mode enabled. Upload a supported document now."
        )
        return

    if query.data == "scan_image":
        context.user_data["scan_mode"] = "image"
        await query.message.reply_text(
            "Image scan mode enabled. Upload a suspicious image now."
        )
        return

    if query.data == "scan_voice":
        context.user_data["scan_mode"] = "voice"
        await query.message.reply_text(
            "Voice scan mode enabled. Upload a suspicious voice/audio message now."
        )
        return

    if query.data == "open_help":
        await query.message.reply_text("Use /help to view full command and scan guidance.")
        return

    await query.message.reply_text("Please choose a valid option.")


def register_start_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(agreement_button_handler, pattern=r"^agree_terms$"))
    application.add_handler(
        CallbackQueryHandler(
            start_menu_callback_handler,
            pattern=r"^(scan_phone|scan_url|scan_social|scan_file|scan_image|scan_voice|open_help)$",
        )
    )
