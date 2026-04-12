import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


def _require_env(var_name: str) -> str:
    value = os.getenv(var_name, "").strip()
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {var_name}. "
            "Set it in your .env file before starting the bot."
        )
    return value


def _parse_admin_ids(raw_value: str) -> list[int]:
    parts = [item.strip() for item in raw_value.split(",") if item.strip()]
    if not parts:
        raise RuntimeError(
            "ADMIN_IDS must contain at least one Telegram user ID (comma separated)."
        )

    try:
        return [int(item) for item in parts]
    except ValueError as exc:
        raise RuntimeError(
            "Invalid ADMIN_IDS value. Use comma-separated numeric Telegram user IDs."
        ) from exc


def _optional_env(var_name: str) -> str | None:
    value = os.getenv(var_name, "").strip()
    return value or None


PLAN_LIMITS: dict[str, int] = {
    "free": 5,
    "pro": 500,
    "enterprise": 999999,
}

SCAN_TIMEOUT = 30
MAX_FILE_SIZE = 20 * 1024 * 1024
SUPPORTED_FILE_TYPES = [
    "pdf",
    "txt",
    "doc",
    "docx",
    "png",
    "jpg",
    "jpeg",
    "mp3",
    "wav",
    "ogg",
]
BANNED_KEYWORDS = [
    "hack",
    "exploit",
    "malware",
    "ransomware",
    "phishing kit",
    "ddos",
    "botnet",
    "credential stuffing",
]


@dataclass(frozen=True)
class Settings:
    bot_token: str
    anthropic_api_key: str
    database_url: str
    redis_url: str
    admin_ids: list[int]
    backend_url: str
    environment: str
    openai_api_key: str | None
    whisper_api_key: str | None
    whisper_api_url: str | None
    whisper_model: str | None
    shodan_api_key: str | None
    virustotal_api_key: str | None
    haveibeenpwned_api_key: str | None
    intelligencex_api_key: str | None
    dehashed_api_key: str | None
    dehashed_email: str | None
    hunter_api_key: str | None
    urlscan_api_key: str | None

    @property
    def telegram_bot_token(self) -> str:
        # Backward-compatible alias for older imports.
        return self.bot_token


def _build_settings() -> Settings:
    environment = _require_env("ENVIRONMENT").lower()
    if environment not in {"development", "production"}:
        raise RuntimeError("ENVIRONMENT must be either 'development' or 'production'.")

    return Settings(
        bot_token=_require_env("BOT_TOKEN"),
        anthropic_api_key=_require_env("ANTHROPIC_API_KEY"),
        database_url=_require_env("DATABASE_URL"),
        redis_url=_require_env("REDIS_URL"),
        admin_ids=_parse_admin_ids(_require_env("ADMIN_IDS")),
        backend_url=_require_env("BACKEND_URL"),
        environment=environment,
        openai_api_key=_optional_env("OPENAI_API_KEY"),
        whisper_api_key=_optional_env("WHISPER_API_KEY"),
        whisper_api_url=_optional_env("WHISPER_API_URL"),
        whisper_model=_optional_env("WHISPER_MODEL"),
        shodan_api_key=_optional_env("SHODAN_API_KEY"),
        virustotal_api_key=_optional_env("VIRUSTOTAL_API_KEY"),
        haveibeenpwned_api_key=_optional_env("HIBP_API_KEY"),
        intelligencex_api_key=_optional_env("INTELLIGENCEX_API_KEY"),
        dehashed_api_key=_optional_env("DEHASHED_API_KEY"),
        dehashed_email=_optional_env("DEHASHED_EMAIL"),
        hunter_api_key=_optional_env("HUNTER_API_KEY"),
        urlscan_api_key=_optional_env("URLSCAN_API_KEY"),
    )


settings = _build_settings()
