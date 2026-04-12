from config import BANNED_KEYWORDS


def find_banned_keywords(text: str) -> list[str]:
    lower_text = text.lower()
    return [keyword for keyword in BANNED_KEYWORDS if keyword in lower_text]


def is_defensive_request(text: str) -> bool:
    return len(find_banned_keywords(text)) == 0
