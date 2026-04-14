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
    "full": 5000,
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
    google_safe_browsing_api_key: str | None
    abstract_api_key: str | None
    leakcheck_api_key: str | None
    breach_directory_api_key: str | None
    spycloud_api_key: str | None
    google_cloud_vision_api_key: str | None
    aws_access_key_id: str | None
    aws_secret_access_key: str | None
    aws_region: str | None
    imagga_api_key: str | None
    imagga_api_secret: str | None
    tineye_api_key: str | None
    opencage_api_key: str | None
    mapbox_api_key: str | None
    geoapify_api_key: str | None
    x_bearer_token: str | None
    facebook_graph_api_token: str | None
    instagram_access_token: str | None
    linkedin_access_token: str | None
    youtube_api_key: str | None
    google_custom_search_api_key: str | None
    google_geocoding_api_key: str | None
    abuseipdb_api_key: str | None
    tiktok_access_token: str | None
    reddit_client_id: str | None
    reddit_client_secret: str | None
    reddit_user_agent: str | None
    telegram_api_id: str | None
    telegram_api_hash: str | None
    email_database_url: str | None
    email_intel_mode: str | None
    social_media_mode: str | None
    voice_recognition_mode: str | None

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
        google_safe_browsing_api_key=_optional_env("GOOGLE_SAFE_BROWSING_API_KEY"),
        abstract_api_key=_optional_env("ABSTRACT_API_KEY"),
        leakcheck_api_key=_optional_env("LEAKCHECK_API_KEY"),
        breach_directory_api_key=_optional_env("BREACH_DIRECTORY_API_KEY"),
        spycloud_api_key=_optional_env("SPYCLOUD_API_KEY"),
        google_cloud_vision_api_key=_optional_env("GOOGLE_CLOUD_VISION_API_KEY"),
        aws_access_key_id=_optional_env("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=_optional_env("AWS_SECRET_ACCESS_KEY"),
        aws_region=_optional_env("AWS_REGION"),
        imagga_api_key=_optional_env("IMAGGA_API_KEY"),
        imagga_api_secret=_optional_env("IMAGGA_API_SECRET"),
        tineye_api_key=_optional_env("TINEYE_API_KEY"),
        opencage_api_key=_optional_env("OPENCAGE_API_KEY"),
        mapbox_api_key=_optional_env("MAPBOX_API_KEY"),
        geoapify_api_key=_optional_env("GEOAPIFY_API_KEY"),
        x_bearer_token=_optional_env("X_BEARER_TOKEN"),
        facebook_graph_api_token=_optional_env("FACEBOOK_GRAPH_API_TOKEN"),
        instagram_access_token=_optional_env("INSTAGRAM_ACCESS_TOKEN"),
        linkedin_access_token=_optional_env("LINKEDIN_ACCESS_TOKEN"),
        youtube_api_key=_optional_env("YOUTUBE_API_KEY"),
        google_custom_search_api_key=_optional_env("GOOGLE_CUSTOM_SEARCH_API_KEY"),
        google_geocoding_api_key=_optional_env("GOOGLE_GEOCODING_API_KEY"),
        abuseipdb_api_key=_optional_env("ABUSEIPDB_API_KEY"),
        tiktok_access_token=_optional_env("TIKTOK_ACCESS_TOKEN"),
        reddit_client_id=_optional_env("REDDIT_CLIENT_ID"),
        reddit_client_secret=_optional_env("REDDIT_CLIENT_SECRET"),
        reddit_user_agent=_optional_env("REDDIT_USER_AGENT"),
        telegram_api_id=_optional_env("TELEGRAM_API_ID"),
        telegram_api_hash=_optional_env("TELEGRAM_API_HASH"),
        email_database_url=_optional_env("EMAIL_DATABASE_URL"),
        email_intel_mode=_optional_env("EMAIL_INTEL_MODE"),
        social_media_mode=_optional_env("SOCIAL_MEDIA_MODE"),
        voice_recognition_mode=_optional_env("VOICE_RECOGNITION_MODE"),
    )


settings = _build_settings()
