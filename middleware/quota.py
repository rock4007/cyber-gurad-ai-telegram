import logging
from typing import Any, Callable

import redis as redis_lib
from telegram import Update

from config import REDIS_URL, DAILY_QUOTA

logger = logging.getLogger(__name__)

_redis_client: redis_lib.Redis | None = None


def get_redis() -> redis_lib.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


class QuotaMiddleware:
    """Middleware that enforces a per-user daily request quota."""

    def __init__(self, daily_quota: int = DAILY_QUOTA) -> None:
        self.daily_quota = daily_quota

    def _quota_key(self, user_id: int) -> str:
        from datetime import date
        return f"quota:{user_id}:{date.today().isoformat()}"

    def get_usage(self, user_id: int) -> int:
        try:
            value = get_redis().get(self._quota_key(user_id))
            return int(value) if value else 0
        except Exception:
            return 0

    def increment_usage(self, user_id: int) -> int:
        try:
            r = get_redis()
            key = self._quota_key(user_id)
            count = r.incr(key)
            r.expire(key, 86400)
            return count
        except Exception:
            return 0

    async def __call__(
        self,
        handler: Callable[[Update, Any], Any],
        update: Update,
        data: dict[str, Any],
    ) -> Any:
        user = update.effective_user
        if user is None:
            return await handler(update, data)

        usage = self.get_usage(user.id)
        if usage >= self.daily_quota:
            await update.effective_message.reply_text(
                f"⚠️ You have reached your daily limit of {self.daily_quota} requests. "
                "Please try again tomorrow."
            )
            return

        self.increment_usage(user.id)
        return await handler(update, data)
