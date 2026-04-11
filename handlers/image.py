import tempfile
import os
from telegram import Update
from telegram.ext import ContextTypes

from services.scanner import scan_image
from services.formatter import format_image_report


async def image_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle photo uploads and analyse the image."""
    photos = update.message.photo
    if not photos:
        await update.message.reply_text("Please send an image to analyse.")
        return

    # Use the highest-resolution variant
    photo = photos[-1]
    await update.message.reply_text("🖼️ Received image. Analysing…")

    file = await context.bot.get_file(photo.file_id)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
        tmp_path = tmp.name

    try:
        await file.download_to_drive(tmp_path)
        result = await scan_image(tmp_path)
        report = format_image_report(result)
        await update.message.reply_text(report, parse_mode="Markdown")
    finally:
        os.unlink(tmp_path)
