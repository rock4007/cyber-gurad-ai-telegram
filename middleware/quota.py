from collections import defaultdict
from datetime import date


class InMemoryQuota:
    def __init__(self, max_per_day: int) -> None:
        self.max_per_day = max_per_day
        self.counts: dict[str, int] = defaultdict(int)
        self.current_day = date.today()

    def _ensure_day_window(self) -> None:
        today = date.today()
        if today != self.current_day:
            self.current_day = today
            self.counts.clear()

    def remaining(self, user_key: str) -> int:
        self._ensure_day_window()
        used = self.counts.get(user_key, 0)
        return max(self.max_per_day - used, 0)

    def allowed(self, user_key: str) -> bool:
        self._ensure_day_window()
        self.counts[user_key] += 1
        return self.counts[user_key] <= self.max_per_day
