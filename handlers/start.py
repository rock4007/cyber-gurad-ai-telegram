from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    await update.message.reply_text(
        "CyberGuard AI is online. Use /phone, /url, /file, /voice, or /image with user-provided content only."
    )


def register_start_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("start", start_command))
