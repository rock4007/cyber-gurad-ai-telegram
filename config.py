import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    database_url: str = os.getenv("DATABASE_URL", "")
    redis_url: str = os.getenv("REDIS_URL", "")
    bot_name: str = os.getenv("BOT_NAME", "CyberGuard AI")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    max_scans_per_day: int = int(os.getenv("MAX_SCANS_PER_DAY", "25"))


settings = Settings()
