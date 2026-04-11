from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


async def url_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text("Usage: /url <link>")
        return
    await update.message.reply_text("URL scan queued. This starter is ready for your scanner service logic.")


def register_url_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("url", url_command))
