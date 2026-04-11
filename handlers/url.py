import re
from telegram import Update
from telegram.ext import ContextTypes

from services.scanner import scan_url
from services.formatter import format_url_report

URL_PATTERN = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


async def url_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle text messages and scan any URLs found."""
    text = update.message.text or ""
    urls = URL_PATTERN.findall(text)

    if not urls:
        await update.message.reply_text(
            "ℹ️ No URL detected. Send a link, file, contact, voice, or image to get started."
        )
        return

    for url in urls:
        await update.message.reply_text(f"🔍 Scanning URL: `{url}`…", parse_mode="Markdown")
        result = await scan_url(url)
        report = format_url_report(result)
        await update.message.reply_text(report, parse_mode="Markdown")
