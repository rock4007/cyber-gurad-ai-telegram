from telegram import Update

from middleware.moderation import find_banned_keywords


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

    return True, None
