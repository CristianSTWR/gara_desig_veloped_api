from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Dict, Tuple

@dataclass
class Bucket:
    tokens: float
    last: float

class TokenBucketLimiter:
    """Rate limiter simple (memoria). Para producción seria usa WAF/Cloudflare o Redis."""
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = rate_per_sec
        self.burst = float(burst)
        self._buckets: Dict[str, Bucket] = {}

    def allow(self, key: str, cost: float = 1.0) -> Tuple[bool, float]:
        now = time.time()
        b = self._buckets.get(key)
        if b is None:
            b = Bucket(tokens=self.burst, last=now)
            self._buckets[key] = b

        # refill
        elapsed = max(0.0, now - b.last)
        b.tokens = min(self.burst, b.tokens + elapsed * self.rate)
        b.last = now

        if b.tokens >= cost:
            b.tokens -= cost
            return True, 0.0

        # seconds until next token
        missing = cost - b.tokens
        retry_after = missing / self.rate if self.rate > 0 else 1.0
        return False, retry_after
