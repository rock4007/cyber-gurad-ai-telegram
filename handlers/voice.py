import tempfile
import os
from telegram import Update
from telegram.ext import ContextTypes

from services.scanner import scan_voice
from services.formatter import format_voice_report


async def voice_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle voice messages and analyse the audio."""
    voice = update.message.voice
    if not voice:
        await update.message.reply_text("Please send a voice message to analyse.")
        return

    await update.message.reply_text("🎤 Received voice message. Analysing…")

    file = await context.bot.get_file(voice.file_id)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ogg") as tmp:
        tmp_path = tmp.name

    try:
        await file.download_to_drive(tmp_path)
        result = await scan_voice(tmp_path, voice.duration)
        report = format_voice_report(result)
        await update.message.reply_text(report, parse_mode="Markdown")
    finally:
        os.unlink(tmp_path)
