from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text("Usage: /phone <phone_number>")
        return
    await update.message.reply_text("Phone scan queued. This starter is ready for your scanner service logic.")


def register_phone_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("phone", phone_command))
