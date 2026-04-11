from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes


async def image_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message:
        return
    await update.message.reply_text("Image scan endpoint ready. Add OCR and scanner integration next.")


def register_image_handlers(application: Application) -> None:
    application.add_handler(CommandHandler("image", image_command))
