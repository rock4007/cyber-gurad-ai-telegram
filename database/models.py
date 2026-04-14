from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Uuid, func, select, update
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from config import settings


def _to_async_database_url(database_url: str) -> str:
    url = database_url.strip()

    if url.startswith("sqlite:///") and "+aiosqlite" not in url:
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)

    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)

    if url.startswith("postgresql://") and "+asyncpg" not in url:
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)

    return url


ASYNC_DATABASE_URL = _to_async_database_url(settings.database_url)


class Base(AsyncAttrs, DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    telegram_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    language_code: Mapped[str] = mapped_column(String(8), default="en")
    country_code: Mapped[str | None] = mapped_column(String(8), nullable=True)
    plan: Mapped[str] = mapped_column(String(32), default="free")
    scans_used: Mapped[int] = mapped_column(Integer, default=0)
    scans_limit: Mapped[int] = mapped_column(Integer, default=5)
    warnings: Mapped[int] = mapped_column(Integer, default=0)
    is_banned: Mapped[bool] = mapped_column(Boolean, default=False)
    ban_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    agreed_to_terms: Mapped[bool] = mapped_column(Boolean, default=False)
    agreed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_active: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    telegram_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("users.telegram_id", ondelete="CASCADE"),
        index=True,
    )
    scan_type: Mapped[str] = mapped_column(String(16), index=True)
    risk_level: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ModerationLog(Base):
    __tablename__ = "moderation_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    telegram_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# Backward-compatibility model used by current handlers/middleware.
class BotUser(Base):
    __tablename__ = "bot_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    telegram_user_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    plan: Mapped[str] = mapped_column(String(32), default="free")
    scans_used: Mapped[int] = mapped_column(Integer, default=0)
    agreed_terms_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


# Backward-compatibility model used by moderation middleware state.
class UserModeration(Base):
    __tablename__ = "user_moderation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    telegram_user_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    strikes: Mapped[int] = mapped_column(Integer, default=0)
    is_banned: Mapped[bool] = mapped_column(Boolean, default=False)
    last_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    banned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


async_engine = create_async_engine(ASYNC_DATABASE_URL, future=True, echo=False)
AsyncSessionLocal = async_sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    session = AsyncSessionLocal()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_or_create_user(telegram_id: str, username: str | None, name: str) -> User:
    async with session_scope() as session:
        user = await session.get(User, telegram_id)
        if user is None:
            user = User(
                telegram_id=telegram_id,
                username=username,
                full_name=name or username or telegram_id,
                language_code="en",
                plan="free",
                scans_used=0,
                scans_limit=5,
                warnings=0,
                is_banned=False,
                agreed_to_terms=False,
            )
            session.add(user)
            await session.flush()
        else:
            user.username = username
            if name:
                user.full_name = name
            user.last_active = datetime.now(timezone.utc)
            await session.flush()

        await session.refresh(user)
        return user


async def increment_scan_count(telegram_id: str) -> User | None:
    async with session_scope() as session:
        user = await session.get(User, telegram_id)
        if user is None:
            return None

        user.scans_used = int(user.scans_used or 0) + 1
        user.last_active = datetime.now(timezone.utc)
        await session.flush()
        await session.refresh(user)
        return user


async def add_warning(telegram_id: str, reason: str) -> User | None:
    async with session_scope() as session:
        user = await session.get(User, telegram_id)
        if user is None:
            return None

        user.warnings = int(user.warnings or 0) + 1
        user.last_active = datetime.now(timezone.utc)
        session.add(
            ModerationLog(
                telegram_id=telegram_id,
                action="warn",
                reason=reason,
            )
        )
        await session.flush()
        await session.refresh(user)
        return user


async def ban_user(telegram_id: str, reason: str) -> User | None:
    async with session_scope() as session:
        user = await session.get(User, telegram_id)
        if user is None:
            return None

        user.is_banned = True
        user.ban_reason = reason
        user.last_active = datetime.now(timezone.utc)
        session.add(
            ModerationLog(
                telegram_id=telegram_id,
                action="ban",
                reason=reason,
            )
        )
        await session.flush()
        await session.refresh(user)
        return user


async def reset_monthly_scans() -> int:
    async with session_scope() as session:
        result = await session.execute(update(User).values(scans_used=0))
        return int(result.rowcount or 0)


async def log_scan(
    telegram_id: str,
    scan_type: str,
    risk_level: str,
    risk_score: float,
) -> ScanLog:
    async with session_scope() as session:
        item = ScanLog(
            telegram_id=telegram_id,
            scan_type=scan_type,
            risk_level=risk_level,
            risk_score=risk_score,
        )
        session.add(item)
        await session.flush()
        await session.refresh(item)
        return item
