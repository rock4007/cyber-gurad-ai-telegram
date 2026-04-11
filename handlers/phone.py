import phonenumbers
from telegram import Update
from telegram.ext import ContextTypes

from services.scanner import scan_phone
from services.formatter import format_phone_report


async def phone_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle shared contacts and analyse the phone number."""
    contact = update.message.contact
    if not contact:
        await update.message.reply_text("Please share a contact to analyse.")
        return

    phone_number = contact.phone_number
    await update.message.reply_text(f"🔍 Analysing phone number: `{phone_number}`…", parse_mode="Markdown")

    try:
        parsed = phonenumbers.parse(phone_number, None)
        is_valid = phonenumbers.is_valid_number(parsed)
    except phonenumbers.NumberParseException:
        await update.message.reply_text("❌ Could not parse the phone number.")
        return

    result = await scan_phone(phone_number, is_valid)
    report = format_phone_report(result)
    await update.message.reply_text(report, parse_mode="Markdown")
