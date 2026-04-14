"""Type 1 — Enhanced Unit Tests: individual functions in isolation."""

import importlib
import os
from unittest.mock import MagicMock

import pytest


# ===================================================================
# config.py
# ===================================================================

class TestConfig:
    @pytest.fixture()
    def config_mod(self):
        return importlib.import_module("config")

    def test_settings_is_frozen_dataclass(self, config_mod):
        s = config_mod.settings
        with pytest.raises(AttributeError):
            s.bot_token = "new-value"

    def test_settings_has_required_fields(self, config_mod):
        s = config_mod.settings
        assert s.bot_token
        assert s.anthropic_api_key
        assert s.database_url
        assert s.redis_url
        assert isinstance(s.admin_ids, list)
        assert s.backend_url

    def test_settings_telegram_bot_token_alias(self, config_mod):
        s = config_mod.settings
        assert s.telegram_bot_token == s.bot_token

    def test_plan_limits(self, config_mod):
        assert config_mod.PLAN_LIMITS["free"] == 5
        assert config_mod.PLAN_LIMITS["pro"] == 500
        assert config_mod.PLAN_LIMITS["enterprise"] == 999999

    def test_scan_timeout(self, config_mod):
        assert config_mod.SCAN_TIMEOUT == 30

    def test_max_file_size(self, config_mod):
        assert config_mod.MAX_FILE_SIZE == 20 * 1024 * 1024

    def test_banned_keywords_list(self, config_mod):
        assert "hack" in config_mod.BANNED_KEYWORDS
        assert "exploit" in config_mod.BANNED_KEYWORDS
        assert len(config_mod.BANNED_KEYWORDS) >= 8

    def test_supported_file_types(self, config_mod):
        assert "pdf" in config_mod.SUPPORTED_FILE_TYPES
        assert "png" in config_mod.SUPPORTED_FILE_TYPES

    def test_parse_admin_ids(self, config_mod):
        ids = config_mod._parse_admin_ids("123,456,789")
        assert ids == [123, 456, 789]

    def test_parse_admin_ids_invalid_raises(self, config_mod):
        with pytest.raises(RuntimeError):
            config_mod._parse_admin_ids("abc,def")

    def test_parse_admin_ids_empty_raises(self, config_mod):
        with pytest.raises(RuntimeError):
            config_mod._parse_admin_ids("")

    def test_require_env_missing_raises(self, config_mod, monkeypatch):
        monkeypatch.delenv("BOT_TOKEN", raising=False)
        monkeypatch.setenv("BOT_TOKEN", "")
        with pytest.raises(RuntimeError, match="Missing required"):
            config_mod._require_env("BOT_TOKEN")
        # Restore
        monkeypatch.setenv("BOT_TOKEN", "test-bot-token")

    def test_optional_env_returns_none(self, config_mod, monkeypatch):
        monkeypatch.setenv("NONEXISTENT_KEY_TEST", "")
        result = config_mod._optional_env("NONEXISTENT_KEY_TEST")
        assert result is None

    def test_optional_env_returns_value(self, config_mod, monkeypatch):
        monkeypatch.setenv("TEST_OPT_KEY", "hello")
        result = config_mod._optional_env("TEST_OPT_KEY")
        assert result == "hello"


# ===================================================================
# database/models.py — async DB URL conversion
# ===================================================================

class TestDatabaseUrlConversion:
    @pytest.fixture()
    def db_mod(self):
        return importlib.import_module("database.models")

    def test_sqlite_to_async(self, db_mod):
        result = db_mod._to_async_database_url("sqlite:///./test.db")
        assert "aiosqlite" in result

    def test_postgres_to_asyncpg(self, db_mod):
        result = db_mod._to_async_database_url("postgres://user:pass@host/db")
        assert "postgresql+asyncpg" in result

    def test_postgresql_to_asyncpg(self, db_mod):
        result = db_mod._to_async_database_url("postgresql://user:pass@host/db")
        assert "postgresql+asyncpg" in result

    def test_already_async_unchanged(self, db_mod):
        url = "postgresql+asyncpg://user:pass@host/db"
        result = db_mod._to_async_database_url(url)
        assert result == url


# ===================================================================
# services/transcription.py
# ===================================================================

class TestTranscriptionService:
    @pytest.fixture()
    def svc(self):
        mod = importlib.import_module("services.transcription")
        return mod.WhisperTranscriptionService()

    def test_configured_when_key_present(self, svc, monkeypatch):
        monkeypatch.setenv("WHISPER_API_KEY", "test-key")
        svc.api_key = "test-key"
        assert svc.configured is True

    def test_not_configured_when_key_empty(self, svc):
        svc.api_key = ""
        assert svc.configured is False

    async def test_transcribe_raises_when_not_configured(self, svc):
        svc.api_key = ""
        with pytest.raises(RuntimeError, match="not configured"):
            await svc.transcribe_file("/fake/path.ogg", mime_type="audio/ogg")


# ===================================================================
# services/origin_intel.py
# ===================================================================

class TestOriginIntelPureFunctions:
    @pytest.fixture()
    def intel_mod(self):
        return importlib.import_module("services.origin_intel")

    def test_extract_domain_from_url(self, intel_mod):
        svc = intel_mod.OriginIntelligenceService()
        assert svc._extract_domain("https://example.com/path") == "example.com"

    def test_extract_domain_bare(self, intel_mod):
        svc = intel_mod.OriginIntelligenceService()
        assert svc._extract_domain("example.com") == "example.com"


# ===================================================================
# app/services/cache.py
# ===================================================================

class TestCacheService:
    async def test_get_cached_scan_returns_none(self, fake_redis, monkeypatch):
        from app.services import cache
        monkeypatch.setattr(cache, "get_redis_client", lambda: fake_redis)
        result = await cache.get_cached_scan("nonexistent_key")
        assert result is None

    async def test_set_and_get_cached_scan(self, fake_redis, monkeypatch):
        import json
        from app.services import cache
        monkeypatch.setattr(cache, "get_redis_client", lambda: fake_redis)

        payload = {"risk_level": "HIGH", "score": 90}
        await cache.set_cached_scan("test_key", payload)
        # FakeRedis stores json string
        stored = await fake_redis.get("test_key")
        assert json.loads(stored)["risk_level"] == "HIGH"


# ===================================================================
# app/services/ai_client.py
# ===================================================================

class TestClaudeClient:
    def test_client_initialization(self):
        from app.services.ai_client import ClaudeClient
        client = ClaudeClient()
        assert client.base_url == "https://api.anthropic.com/v1/messages"
        assert client.api_key is not None


# ===================================================================
# Formatter helpers (already covered but verify key pure functions)
# ===================================================================

class TestFormatterUnit:
    @pytest.fixture()
    def fmt(self):
        return importlib.import_module("services.formatter")

    def test_risk_emoji_mapping(self, fmt):
        assert "🔴" in fmt.risk_emoji("high")
        assert "🟢" in fmt.risk_emoji("low")

    def test_progress_bar_length(self, fmt):
        bar = fmt.progress_bar(50, total=100, length=10)
        assert len(bar) == 10

    def test_shorten_hash_preserves_prefix(self, fmt):
        full = "abcdef1234567890" * 4
        short = fmt.shorten_hash(full)
        assert short.startswith("abcdef")


# ===================================================================
# app/schemas.py
# ===================================================================

class TestSchemasUnit:
    def test_scan_request_valid(self):
        from app.schemas import ScanRequest
        req = ScanRequest(
            source="telegram",
            content="Check this for phishing",
            consent_confirmed=True,
        )
        assert req.source == "telegram"
        assert req.consent_confirmed is True

    def test_scan_request_no_consent_fails(self):
        from app.schemas import ScanRequest
        with pytest.raises(Exception):
            ScanRequest(
                source="telegram",
                content="Check this",
                consent_confirmed=False,
            )
