from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


async def voice_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    await update.message.reply_text("Voice scan endpoint ready. Add transcription and scanner integration next.")


def register_voice_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("voice", voice_command))
