"""Shared fixtures and test configuration for CyberGuard AI test suite."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


_ENV_DEFAULTS = {
    "ENVIRONMENT": "development",
    "BOT_TOKEN": "test-bot-token",
    "ANTHROPIC_API_KEY": "test-anthropic-key",
    "DATABASE_URL": "sqlite:///./test.db",
    "REDIS_URL": "redis://localhost:6379/0",
    "ADMIN_IDS": "12345",
    "BACKEND_URL": "http://localhost:8000",
    "POSTGRES_DSN": "sqlite+aiosqlite:///./test.db",
    "TELEGRAM_BOT_TOKEN": "test-telegram-token",
    "CLAUDE_API_KEY": "test-claude-key",
    "VIRUSTOTAL_API_KEY": "test-virustotal-key",
}

for key, value in _ENV_DEFAULTS.items():
    os.environ.setdefault(key, value)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BOT_ROOT = PROJECT_ROOT / "cyberguard-telegram"

for p in (str(PROJECT_ROOT), str(BOT_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)
# tests/conftest.py lives at cyberguard-telegram/tests/conftest.py
# parents[0] = tests/  parents[1] = cyberguard-telegram/  (the bot root itself)
BOT_ROOT_INNER = Path(__file__).resolve().parents[1]
if str(BOT_ROOT_INNER) not in sys.path:
    sys.path.insert(0, str(BOT_ROOT_INNER))


class _MockerProxy:
    """Lightweight pytest-mock compatible proxy for environments without pytest-mock plugin."""

    def __init__(self) -> None:
        self._patchers: list[Any] = []

    def patch(self, target: str, *args, **kwargs):
        p = patch(target, *args, **kwargs)
        mocked = p.start()
        self._patchers.append(p)
        return mocked

    def stopall(self) -> None:
        while self._patchers:
            self._patchers.pop().stop()


@pytest.fixture()
def mocker():
    """Provide pytest-mock style API even when pytest-mock plugin is unavailable."""
    proxy = _MockerProxy()
    try:
        yield proxy
    finally:
        proxy.stopall()


@pytest.fixture(autouse=True)
def test_environment(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Set required environment variables for every test."""
    for key, value in _ENV_DEFAULTS.items():
        monkeypatch.setenv(key, value)
    return _ENV_DEFAULTS




@pytest.fixture()
def mock_update() -> MagicMock:
    user = SimpleNamespace(id=12345, username="test_user", first_name="Test")

    message = MagicMock()
    message.text = "suspicious text"
    message.caption = None
    message.reply_text = AsyncMock()
    message.reply_document = AsyncMock()
    message.reply_photo = AsyncMock()
    message.reply_voice = AsyncMock()
    message.delete = AsyncMock()

    callback_query = MagicMock()
    callback_query.data = "scan_phone"
    callback_query.answer = AsyncMock()
    callback_query.edit_message_text = AsyncMock()
    callback_query.message = message

    update = MagicMock()
    update.effective_user = user
    update.message = message
    update.callback_query = callback_query
    update.effective_chat = SimpleNamespace(id=777)
    return update


@pytest.fixture()
def mock_context() -> MagicMock:
    context = MagicMock()
    context.user_data = {}
    context.chat_data = {}
    context.bot = MagicMock()
    context.bot.send_message = AsyncMock()
    context.bot.send_chat_action = AsyncMock()
    return context


@pytest.fixture()
def mock_db_session() -> MagicMock:
    session = MagicMock()
    session.execute = MagicMock()
    session.add = MagicMock()
    session.commit = MagicMock()
    session.refresh = MagicMock()
    session.flush = MagicMock()
    session.rollback = MagicMock()
    session.close = MagicMock()
    return session


@pytest.fixture()
async def test_db_session():
    models_mod = importlib.import_module("database.models")
    session = models_mod.AsyncSessionLocal()
    try:
        yield session
    finally:
        await session.rollback()
        await session.close()


@pytest.fixture()
def mock_redis_client() -> MagicMock:
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.delete = AsyncMock(return_value=1)
    redis.incr = AsyncMock(return_value=1)
    redis.expire = AsyncMock(return_value=True)
    redis.zadd = AsyncMock(return_value=1)
    redis.zrangebyscore = AsyncMock(return_value=[])
    redis.zremrangebyscore = AsyncMock(return_value=0)
    redis.zcard = AsyncMock(return_value=0)
    return redis


@pytest.fixture()
def mock_claude_client() -> MagicMock:
    response_chunk = SimpleNamespace(text='{"risk_level": "LOW", "score": 10, "summary": "ok", "flags": []}')
    response = SimpleNamespace(content=[response_chunk])
    client = MagicMock()
    client.messages = MagicMock()
    client.messages.create = AsyncMock(return_value=response)
    return client


@pytest.fixture()
def mock_virustotal_api() -> dict[str, dict]:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                }
            }
        }
    }


@pytest.fixture()
def test_user_free() -> dict[str, object]:
    return {
        "telegram_user_id": 111,
        "username": "free_user",
        "plan": "free",
        "scans_used": 0,
        "scans_limit": 5,
    }


@pytest.fixture()
def test_user_pro() -> dict[str, object]:
    return {
        "telegram_user_id": 222,
        "username": "pro_user",
        "plan": "pro",
        "scans_used": 5,
        "scans_limit": 500,
    }


@pytest.fixture()
def test_bot_application() -> MagicMock:
    app = MagicMock()
    app.add_handler = MagicMock()
    app.bot = MagicMock()
    app.bot.send_message = AsyncMock()
    return app


@pytest.fixture()
def scanner_service():
    mod = importlib.import_module("services.scanner")
    return mod.AsyncScannerService()


@pytest.fixture()
def scanner_module():
    return importlib.import_module("services.scanner")


@pytest.fixture()
def formatter():
    return importlib.import_module("services.formatter")


@pytest.fixture()
def origin_service():
    mod = importlib.import_module("services.origin_intel")
    return mod.OriginIntelligenceService()


@pytest.fixture()
def app_settings():
    from app.config import Settings

    return Settings(
        postgres_dsn="sqlite+aiosqlite:///./test.db",
        redis_url="redis://localhost:6379/0",
        telegram_bot_token="test-token",
        claude_api_key="test-key",
    )


class FakeRedis:
    def __init__(self):
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self._store.pop(key, None)


@pytest.fixture()
def fake_redis():
    return FakeRedis()
