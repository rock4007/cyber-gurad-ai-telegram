from telegram import Update

from config import PLAN_LIMITS
from middleware.moderation import find_banned_keywords
from middleware.quota import InMemoryQuota


quota_guard = InMemoryQuota(max_per_day=PLAN_LIMITS["free"])


def _get_user_key(update: Update) -> str:
    user_id = update.effective_user.id if update.effective_user else 0
    return str(user_id)


def check_text_policy(update: Update, text: str) -> tuple[bool, str | None]:
    banned_hits = find_banned_keywords(text)
    if banned_hits:
        return False, (
            "Request blocked by defensive policy. "
            f"Detected banned terms: {', '.join(sorted(set(banned_hits)))}"
        )

    user_key = _get_user_key(update)
    if not quota_guard.allowed(user_key):
        return (
            False,
            "Daily free-plan scan limit reached. Upgrade plan or wait for quota reset.",
        )

    return True, None
