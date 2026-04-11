from collections import defaultdict


class InMemoryQuota:
    def __init__(self, max_per_day: int) -> None:
        self.max_per_day = max_per_day
        self.counts: dict[str, int] = defaultdict(int)

    def allowed(self, user_key: str) -> bool:
        self.counts[user_key] += 1
        return self.counts[user_key] <= self.max_per_day
