import importlib
from datetime import datetime, timezone

import pytest

_models = importlib.import_module("database.models")
BotUser = _models.BotUser
User = _models.User
UserModeration = _models.UserModeration
_to_async_database_url = _models._to_async_database_url


def test_to_async_database_url_sqlite():
    converted = _to_async_database_url("sqlite:///./test.db")
    assert converted.startswith("sqlite+aiosqlite:///")


def test_to_async_database_url_postgres():
    converted = _to_async_database_url("postgres://user:pass@localhost/db")
    assert converted.startswith("postgresql+asyncpg://")


@pytest.mark.asyncio
async def test_user_model_defaults(test_db_session):
    user = User(telegram_id="u1", full_name="User One")
    test_db_session.add(user)
    await test_db_session.flush()

    saved = await test_db_session.get(User, "u1")
    assert saved is not None
    assert saved.plan == "free"
    assert saved.is_banned is False


@pytest.mark.asyncio
async def test_usermoderation_model_defaults(test_db_session):
    row = UserModeration(telegram_user_id=12345)
    test_db_session.add(row)
    await test_db_session.flush()

    assert row.strikes == 0
    assert row.is_banned is False


def test_botuser_model_table_and_columns():
    assert BotUser.__tablename__ == "bot_users"
    cols = {col.name for col in BotUser.__table__.columns}
    assert {"telegram_user_id", "plan", "scans_used", "agreed_terms_at"}.issubset(cols)


@pytest.mark.asyncio
async def test_user_timestamps_roundtrip(test_db_session):
    now = datetime.now(timezone.utc)
    user = User(telegram_id="u2", full_name="User Two", agreed_to_terms=True, agreed_at=now)
    test_db_session.add(user)
    await test_db_session.flush()

    saved = await test_db_session.get(User, "u2")
    assert saved.agreed_to_terms is True
    assert saved.agreed_at is not None
