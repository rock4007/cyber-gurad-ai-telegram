from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


async def file_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    await update.message.reply_text("File scan endpoint ready. Attach parsing logic in services/scanner.py.")


def register_file_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("file", file_command))
