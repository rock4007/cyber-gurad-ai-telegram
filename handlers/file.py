import tempfile
import os
from telegram import Update
from telegram.ext import ContextTypes

from services.scanner import scan_file
from services.formatter import format_file_report


async def file_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle document uploads and scan the file."""
    document = update.message.document
    if not document:
        await update.message.reply_text("Please send a file to scan.")
        return

    await update.message.reply_text(
        f"📄 Received *{document.file_name}* ({document.mime_type}). Scanning…",
        parse_mode="Markdown",
    )

    file = await context.bot.get_file(document.file_id)
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(document.file_name)[1]) as tmp:
        tmp_path = tmp.name

    try:
        await file.download_to_drive(tmp_path)
        result = await scan_file(tmp_path, document.file_name, document.mime_type)
        report = format_file_report(result)
        await update.message.reply_text(report, parse_mode="Markdown")
    finally:
        os.unlink(tmp_path)
