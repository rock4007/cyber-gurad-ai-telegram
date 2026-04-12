import re
from datetime import datetime, timezone
from functools import wraps
from typing import Awaitable, Callable

from anthropic import AsyncAnthropic
from redis.asyncio import Redis
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from telegram import Update
from telegram.ext import Application, ApplicationHandlerStop, ContextTypes, MessageHandler, filters

from config import BANNED_KEYWORDS, settings
from database.models import Base, UserModeration


INSTANT_BAN_KEYWORDS = [
    "stalk",
    "track someone",
    "spy on",
    "find location of",
    "hack account",
    "bypass security",
    "ddos attack",
    "keylogger",
    "rat tool",
    "exploit",
    "find this person",
]

APPEAL_EMAIL = "support@cyberguard.ai"
BAN_CACHE_TTL_SECONDS = 300
MAX_STRIKES = 3

engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base.metadata.create_all(engine)

_redis_client: Redis | None = None
_claude_client: AsyncAnthropic | None = None


def _get_redis() -> Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def _get_claude() -> AsyncAnthropic:
    global _claude_client
    if _claude_client is None:
        _claude_client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    return _claude_client


def find_banned_keywords(text: str) -> list[str]:
    lowered = text.lower()
    return [keyword for keyword in BANNED_KEYWORDS if keyword in lowered]


def find_instant_ban_keywords(text: str) -> list[str]:
    lowered = text.lower()
    return [keyword for keyword in INSTANT_BAN_KEYWORDS if keyword in lowered]


def is_defensive_request(text: str) -> bool:
    return len(find_banned_keywords(text)) == 0


def _cache_key(user_id: int) -> str:
    return f"cgai:moderation:ban:{user_id}"


async def _cached_ban_status(user_id: int) -> bool | None:
    cached = await _get_redis().get(_cache_key(user_id))
    if cached is None:
        return None
    return cached == "1"


async def _set_cached_ban_status(user_id: int, is_banned: bool) -> None:
    await _get_redis().set(_cache_key(user_id), "1" if is_banned else "0", ex=BAN_CACHE_TTL_SECONDS)


def _get_or_create_record(user_id: int) -> UserModeration:
    with SessionLocal() as session:
        record = session.execute(
            select(UserModeration).where(UserModeration.telegram_user_id == user_id)
        ).scalar_one_or_none()
        if record is None:
            record = UserModeration(telegram_user_id=user_id, strikes=0, is_banned=False)
            session.add(record)
            session.commit()
            session.refresh(record)
        return record


def _get_record(user_id: int) -> UserModeration | None:
    with SessionLocal() as session:
        return session.execute(
            select(UserModeration).where(UserModeration.telegram_user_id == user_id)
        ).scalar_one_or_none()


def _increment_strike(user_id: int, reason: str) -> int:
    with SessionLocal() as session:
        record = session.execute(
            select(UserModeration).where(UserModeration.telegram_user_id == user_id)
        ).scalar_one_or_none()
        if record is None:
            record = UserModeration(telegram_user_id=user_id, strikes=0, is_banned=False)
            session.add(record)
            session.flush()
        record.strikes = int(record.strikes or 0) + 1
        record.last_reason = reason[:250]
        record.updated_at = datetime.now(timezone.utc)
        session.commit()
        return record.strikes


def _ban_user(user_id: int, reason: str) -> None:
    with SessionLocal() as session:
        record = session.execute(
            select(UserModeration).where(UserModeration.telegram_user_id == user_id)
        ).scalar_one_or_none()
        if record is None:
            record = UserModeration(telegram_user_id=user_id, strikes=0, is_banned=False)
            session.add(record)
            session.flush()
        record.is_banned = True
        record.last_reason = reason[:250]
        record.banned_at = datetime.now(timezone.utc)
        record.updated_at = datetime.now(timezone.utc)
        session.commit()


async def _notify_admins(context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    for admin_id in settings.admin_ids:
        try:
            await context.bot.send_message(chat_id=admin_id, text=text)
        except Exception:
            continue


async def _delete_message_safe(update: Update) -> None:
    try:
        if update.message:
            await update.message.delete()
    except Exception:
        pass


def _extract_label_and_reason(raw: str) -> tuple[str, str]:
    if not raw:
        return "ALLOWED", "Empty classifier output"

    normalized = raw.upper()
    label = "ALLOWED"
    for candidate in ("ALLOWED", "VULGAR", "ILLEGAL", "OFF_TOPIC"):
        if re.search(rf"\b{candidate}\b", normalized):
            label = candidate
            break

    reason = raw.strip().splitlines()[0][:240]
    return label, reason


async def _classify_with_claude(text: str) -> tuple[str, str]:
    if not text.strip():
        return "ALLOWED", "No text content"

    client = _get_claude()
    try:
        response = await client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=120,
            temperature=0,
            system=(
                "You moderate a cybersecurity platform. "
                "Classify as ALLOWED/VULGAR/ILLEGAL/OFF_TOPIC only."
            ),
            messages=[
                {
                    "role": "user",
                    "content": f"Text: {text}\nReturn: LABEL + short reason.",
                }
            ],
        )
        chunks = getattr(response, "content", []) or []
        joined = "\n".join(str(getattr(chunk, "text", "")) for chunk in chunks).strip()
        return _extract_label_and_reason(joined)
    except Exception as exc:
        return "ALLOWED", f"Classifier fallback: {exc}"


async def run_moderation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not update.message or not update.effective_user:
        return True

    user = update.effective_user
    user_id = user.id
    text = (update.message.text or update.message.caption or "").strip()

    cached = await _cached_ban_status(user_id)
    if cached is True:
        await _delete_message_safe(update)
        return False

    if cached is None:
        record = _get_record(user_id)
        is_banned = bool(record.is_banned) if record else False
        await _set_cached_ban_status(user_id, is_banned)
        if is_banned:
            await _delete_message_safe(update)
            return False

    _get_or_create_record(user_id)

    # LAYER 1: instant-ban keyword scan (no API call)
    instant_hits = find_instant_ban_keywords(text)
    if instant_hits:
        reason = f"Instant ban keywords: {', '.join(instant_hits)}"
        _ban_user(user_id, reason)
        await _set_cached_ban_status(user_id, True)
        await _delete_message_safe(update)
        await context.bot.send_message(
            chat_id=user_id,
            text=(
                "🚫 Cuenta bloqueada permanentemente\n"
                "Motivo: solicitud prohibida por politicas de seguridad.\n"
                f"Si crees que es un error, envia apelacion a: {APPEAL_EMAIL}"
            ),
        )
        await _notify_admins(
            context,
            (
                "[MOD ALERT] Usuario bloqueado (Layer 1)\n"
                f"user_id={user_id}\n"
                f"username=@{user.username or 'unknown'}\n"
                f"reason={reason}\n"
                f"text={text[:400]}"
            ),
        )
        return False

    # LAYER 2: Claude classification
    label, reason = await _classify_with_claude(text)

    # LAYER 3: strike and enforcement
    if label == "ALLOWED":
        return True

    if label == "OFF_TOPIC":
        await update.message.reply_text(
            "Este chat es solo para ciberseguridad defensiva. Envia un caso de estafa, fraude o phishing para ayudarte."
        )
        return False

    if label == "VULGAR":
        strikes = _increment_strike(user_id, reason)
        if strikes >= MAX_STRIKES:
            _ban_user(user_id, f"Auto-ban after {MAX_STRIKES} strikes. Last reason: {reason}")
            await _set_cached_ban_status(user_id, True)
            await _delete_message_safe(update)
            await context.bot.send_message(
                chat_id=user_id,
                text=(
                    "🚫 Bloqueo permanente activado\n"
                    f"Has alcanzado {MAX_STRIKES}/{MAX_STRIKES} advertencias.\n"
                    f"Apelacion: {APPEAL_EMAIL}"
                ),
            )
            await _notify_admins(
                context,
                (
                    "[MOD ALERT] Usuario bloqueado por strikes\n"
                    f"user_id={user_id}\n"
                    f"username=@{user.username or 'unknown'}\n"
                    f"reason={reason}"
                ),
            )
            return False

        await update.message.reply_text(
            (
                f"⚠️ Warning [{strikes}]/3\n"
                f"Reason: {reason}\n"
                "CyberGuard es solo para ciberseguridad.\n"
                "3 warnings = permanent ban."
            )
        )
        return False

    if label == "ILLEGAL":
        _ban_user(user_id, f"Illegal content: {reason}")
        await _set_cached_ban_status(user_id, True)
        await _delete_message_safe(update)
        await context.bot.send_message(
            chat_id=user_id,
            text=(
                "🚫 Cuenta bloqueada permanentemente\n"
                f"Reason: {reason}\n"
                f"Appeal: {APPEAL_EMAIL}"
            ),
        )
        await _notify_admins(
            context,
            (
                "[MOD ALERT] Usuario bloqueado (Layer 3 ILLEGAL)\n"
                f"user_id={user_id}\n"
                f"username=@{user.username or 'unknown'}\n"
                f"reason={reason}\n"
                f"text={text[:400]}"
            ),
        )
        return False

    return True


def require_moderation(
    handler: Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[None]]
) -> Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[None]]:
    @wraps(handler)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        allowed = await run_moderation(update, context)
        if not allowed:
            raise ApplicationHandlerStop
        await handler(update, context)

    return wrapped


async def _pre_message_moderation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    allowed = await run_moderation(update, context)
    if not allowed:
        raise ApplicationHandlerStop


def register_moderation_middleware(application: Application) -> None:
    application.add_handler(MessageHandler(filters.ALL, _pre_message_moderation), group=-1)
