import logging

from telegram.ext import Application

from config import settings
from handlers.file import register_file_handlers
from handlers.image import register_image_handlers
from handlers.phone import register_phone_handlers
from handlers.start import register_start_handlers
from handlers.url import register_url_handlers
from handlers.voice import register_voice_handlers


def build_application() -> Application:
    if not settings.telegram_bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is required")

    application = Application.builder().token(settings.telegram_bot_token).build()

    register_start_handlers(application)
    register_phone_handlers(application)
    register_url_handlers(application)
    register_file_handlers(application)
    register_voice_handlers(application)
    register_image_handlers(application)

    return application


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
    )

    app = build_application()
    app.run_polling(allowed_updates=None)


if __name__ == "__main__":
    main()
