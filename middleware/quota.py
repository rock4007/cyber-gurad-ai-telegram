from datetime import datetime, timezone
from functools import wraps
from typing import Awaitable, Callable

from redis.asyncio import Redis
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ApplicationHandlerStop, ContextTypes

from config import PLAN_LIMITS, settings
from database.models import Base, BotUser


PLAN_LIMITS_MONTHLY = {
    "free": 5,
    "pro": 500,
    "enterprise": 999999,
}

PLAN_CACHE_TTL_SECONDS = 300

engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base.metadata.create_all(engine)

_redis_client: Redis | None = None


def _get_redis() -> Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def _plan_cache_key(user_id: int) -> str:
    return f"cgai:plan:{user_id}"


def _ensure_user(user_id: int, username: str | None, first_name: str | None) -> BotUser:
    with SessionLocal() as session:
        user = session.execute(
            select(BotUser).where(BotUser.telegram_user_id == user_id)
        ).scalar_one_or_none()
        if user is None:
            user = BotUser(
                telegram_user_id=user_id,
                username=username,
                first_name=first_name,
                plan="free",
                scans_used=0,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
        return user


def _is_new_month(last_dt: datetime | None) -> bool:
    if last_dt is None:
        return False
    now = datetime.now(timezone.utc)
    compare_dt = last_dt if last_dt.tzinfo else last_dt.replace(tzinfo=timezone.utc)
    return compare_dt.year != now.year or compare_dt.month != now.month


def _next_month_reset_text() -> str:
    now = datetime.now(timezone.utc)
    if now.month == 12:
        month_name = "January"
        year = now.year + 1
    else:
        month_name = datetime(now.year, now.month + 1, 1).strftime("%B")
        year = now.year
    return f"1st of {month_name} {year}"


class QuotaGuard:
    async def get_plan(self, user_id: int, username: str | None = None, first_name: str | None = None) -> str:
        cache_key = _plan_cache_key(user_id)
        cached = await _get_redis().get(cache_key)
        if cached:
            return cached

        user = _ensure_user(user_id, username, first_name)
        plan = (user.plan or "free").lower()
        await _get_redis().set(cache_key, plan, ex=PLAN_CACHE_TTL_SECONDS)
        return plan

    def _get_usage(self, user_id: int, username: str | None, first_name: str | None) -> tuple[str, int]:
        with SessionLocal() as session:
            user = session.execute(
                select(BotUser).where(BotUser.telegram_user_id == user_id)
            ).scalar_one_or_none()
            if user is None:
                user = BotUser(
                    telegram_user_id=user_id,
                    username=username,
                    first_name=first_name,
                    plan="free",
                    scans_used=0,
                )
                session.add(user)
                session.commit()
                session.refresh(user)

            if _is_new_month(user.updated_at):
                user.scans_used = 0
                session.commit()
                session.refresh(user)

            return (user.plan or "free").lower(), int(user.scans_used or 0)

    async def remaining(self, user_key: str) -> int:
        try:
            user_id = int(user_key)
        except ValueError:
            return PLAN_LIMITS_MONTHLY["free"]

        plan, scans_used = self._get_usage(user_id, None, None)
        if plan == "enterprise":
            return 999999
        limit = PLAN_LIMITS_MONTHLY.get(plan, PLAN_LIMITS_MONTHLY["free"])
        return max(limit - scans_used, 0)

    async def check_and_increment(
        self,
        *,
        user_id: int,
        username: str | None,
        first_name: str | None,
    ) -> tuple[bool, str, int, int]:
        plan = await self.get_plan(user_id, username, first_name)
        if plan == "enterprise":
            return True, plan, 0, 999999

        with SessionLocal() as session:
            user = session.execute(
                select(BotUser).where(BotUser.telegram_user_id == user_id)
            ).scalar_one_or_none()
            if user is None:
                user = BotUser(
                    telegram_user_id=user_id,
                    username=username,
                    first_name=first_name,
                    plan="free",
                    scans_used=0,
                )
                session.add(user)
                session.commit()
                session.refresh(user)

            if _is_new_month(user.updated_at):
                user.scans_used = 0
                session.commit()
                session.refresh(user)

            plan = (user.plan or plan or "free").lower()
            await _get_redis().set(_plan_cache_key(user_id), plan, ex=PLAN_CACHE_TTL_SECONDS)

            if plan == "enterprise":
                return True, plan, 0, 999999

            scans_limit = PLAN_LIMITS_MONTHLY.get(plan, PLAN_LIMITS_MONTHLY["free"])
            scans_used = int(user.scans_used or 0)
            if scans_used >= scans_limit:
                return False, plan, scans_used, scans_limit

            user.scans_used = scans_used + 1
            session.commit()
            session.refresh(user)
            return True, plan, int(user.scans_used), scans_limit


def _upgrade_markup() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("💳 Upgrade Now", url="https://cyberguard.ai/pricing"),
                InlineKeyboardButton("🌐 See Plans", url="https://cyberguard.ai/pricing"),
            ]
        ]
    )


quota_guard = QuotaGuard()


def check_quota(
    handler: Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[None]]
) -> Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[None]]:
    @wraps(handler)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not update.effective_user:
            await handler(update, context)
            return

        user = update.effective_user
        allowed, plan, used, scans_limit = await quota_guard.check_and_increment(
            user_id=user.id,
            username=user.username,
            first_name=user.first_name,
        )

        if not allowed:
            pretty_plan = plan.title()
            msg = (
                "❌ Scan Limit Reached\n"
                "─────────────────\n"
                f"Plan: {pretty_plan} ({used}/{scans_limit} used)\n"
                f"Resets: {_next_month_reset_text()}\n"
                "─────────────────\n"
                "Upgrade for more scans:\n"
                "Pro: 500 scans/month\n"
                "₹999 | £9.99 | €11.99"
            )
            target = update.effective_message
            if target:
                await target.reply_text(msg, reply_markup=_upgrade_markup())
            raise ApplicationHandlerStop

        await handler(update, context)

        if plan != "enterprise":
            remaining = max(scans_limit - used, 0)
            target = update.effective_message
            if target:
                await target.reply_text(f"📊 Scans remaining this month: {remaining}/{scans_limit}")

    return wrapped
