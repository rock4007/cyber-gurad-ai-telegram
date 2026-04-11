import logging
from typing import Any, Callable

from telegram import Update

logger = logging.getLogger(__name__)

# These keywords flag clearly abusive/off-topic content.
# They are intentionally narrow so that legitimate security queries
# (e.g. "check this phishing link") are never blocked.
BLOCKED_KEYWORDS = ["buy followers", "free money", "click here to win"]


class ModerationMiddleware:
    """Middleware that filters messages containing clearly abusive content."""

    def __init__(self, blocked_keywords: list[str] | None = None) -> None:
        self.blocked_keywords = blocked_keywords or BLOCKED_KEYWORDS

    def is_blocked(self, text: str) -> bool:
        lowered = text.lower()
        return any(kw in lowered for kw in self.blocked_keywords)

    async def __call__(
        self,
        handler: Callable[[Update, Any], Any],
        update: Update,
        data: dict[str, Any],
    ) -> Any:
        message = update.effective_message
        if message and message.text and self.is_blocked(message.text):
            logger.warning("Blocked message from user %s", update.effective_user.id)
            await message.reply_text("⚠️ Your message was flagged and could not be processed.")
            return
        return await handler(update, data)
