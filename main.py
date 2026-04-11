import logging
from telegram.ext import Application, CommandHandler, MessageHandler, filters

from config import TELEGRAM_BOT_TOKEN
from handlers.start import start_handler
from handlers.phone import phone_handler
from handlers.url import url_handler
from handlers.file import file_handler
from handlers.voice import voice_handler
from handlers.image import image_handler
from database.models import init_db

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def main() -> None:
    init_db()

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, url_handler))
    app.add_handler(MessageHandler(filters.CONTACT, phone_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, file_handler))
    app.add_handler(MessageHandler(filters.VOICE, voice_handler))
    app.add_handler(MessageHandler(filters.PHOTO, image_handler))

    logger.info("CyberGuard AI bot started.")
    app.run_polling()


if __name__ == "__main__":
    main()
