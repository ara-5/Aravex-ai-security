"""Behavioral anomaly tracking, with an in-memory and a Redis-backed
implementation behind the same interface.

Tracks two signals per agent over a sliding time window: call rate
(excessive API calls / possible exfiltration staging) and denial rate
(repeated failed authorization, a classic sign of an agent -- or an
attacker driving one -- probing for a permission it doesn't have).

`InMemoryAnomalyTracker` is correct for exactly one gateway process. The
moment you run more than one replica, each instance has its own blind spot
-- an attacker spread across two instances looks like two separate,
under-threshold callers to each. `RedisAnomalyTracker` fixes that by
keeping the sliding window in Redis (sorted sets, score = timestamp) so
every replica sees the same counts. Selected automatically via REDIS_URL --
see build_tracker() below.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock


class AnomalyTracker:
    def __init__(
        self,
        window_seconds: float = 60.0,
        rate_threshold: int = 20,
        fail_threshold: int = 3,
    ):
        self.window_seconds = window_seconds
        self.rate_threshold = rate_threshold
        self.fail_threshold = fail_threshold
        self._calls: dict[str, deque] = defaultdict(deque)
        self._denials: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def _trim(self, q: deque, now: float) -> None:
        while q and now - q[0] > self.window_seconds:
            q.popleft()

    def record_call(self, agent_id: str) -> int:
        now = time.time()
        with self._lock:
            q = self._calls[agent_id]
            q.append(now)
            self._trim(q, now)
            return len(q)

    def record_denial(self, agent_id: str) -> int:
        now = time.time()
        with self._lock:
            q = self._denials[agent_id]
            q.append(now)
            self._trim(q, now)
            return len(q)

    def evaluate(self, agent_id: str) -> tuple[list[str], float]:
        now = time.time()
        with self._lock:
            calls = self._calls[agent_id]
            denials = self._denials[agent_id]
            self._trim(calls, now)
            self._trim(denials, now)
            call_count, denial_count = len(calls), len(denials)

        findings: list[str] = []
        score = 0.0
        if call_count > self.rate_threshold:
            findings.append(
                f"excessive_api_calls:{call_count}_in_{int(self.window_seconds)}s"
            )
            score += 0.3
        if denial_count >= self.fail_threshold:
            findings.append(
                f"repeated_failed_authorization:{denial_count}_in_{int(self.window_seconds)}s"
            )
            score += 0.3
        return findings, min(score, 0.5)


class RedisAnomalyTracker:
    """Same contract as AnomalyTracker, backed by Redis sorted sets so the
    sliding window is shared across every gateway replica. Each member is
    a unique token (not just the timestamp, to avoid collisions when two
    events land in the same millisecond); the score is the timestamp, so
    ZREMRANGEBYSCORE trims the window and ZCARD counts what's left.
    """

    def __init__(
        self,
        redis_client,
        window_seconds: float = 60.0,
        rate_threshold: int = 20,
        fail_threshold: int = 3,
        key_prefix: str = "aegisai:anomaly",
    ):
        self.redis = redis_client
        self.window_seconds = window_seconds
        self.rate_threshold = rate_threshold
        self.fail_threshold = fail_threshold
        self.key_prefix = key_prefix
        self._seq = 0
        self._seq_lock = Lock()

    def _calls_key(self, agent_id: str) -> str:
        return f"{self.key_prefix}:calls:{agent_id}"

    def _denials_key(self, agent_id: str) -> str:
        return f"{self.key_prefix}:denials:{agent_id}"

    def _member(self, now: float) -> str:
        with self._seq_lock:
            self._seq += 1
            return f"{now}:{self._seq}"

    def _record(self, key: str, now: float) -> int:
        member = self._member(now)
        pipe = self.redis.pipeline()
        pipe.zadd(key, {member: now})
        pipe.zremrangebyscore(key, 0, now - self.window_seconds)
        pipe.zcard(key)
        pipe.expire(key, int(self.window_seconds) + 5)
        _, _, count, _ = pipe.execute()
        return count

    def record_call(self, agent_id: str) -> int:
        return self._record(self._calls_key(agent_id), time.time())

    def record_denial(self, agent_id: str) -> int:
        return self._record(self._denials_key(agent_id), time.time())

    def evaluate(self, agent_id: str) -> tuple[list[str], float]:
        now = time.time()
        cutoff = now - self.window_seconds
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(self._calls_key(agent_id), 0, cutoff)
        pipe.zremrangebyscore(self._denials_key(agent_id), 0, cutoff)
        pipe.zcard(self._calls_key(agent_id))
        pipe.zcard(self._denials_key(agent_id))
        _, _, call_count, denial_count = pipe.execute()

        findings: list[str] = []
        score = 0.0
        if call_count > self.rate_threshold:
            findings.append(f"excessive_api_calls:{call_count}_in_{int(self.window_seconds)}s")
            score += 0.3
        if denial_count >= self.fail_threshold:
            findings.append(f"repeated_failed_authorization:{denial_count}_in_{int(self.window_seconds)}s")
            score += 0.3
        return findings, min(score, 0.5)


def build_tracker():
    """REDIS_URL configured -> shared Redis-backed tracker (multi-instance
    safe). Otherwise -> in-memory tracker (zero extra infrastructure)."""
    import os

    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        return AnomalyTracker()

    import redis as redis_lib

    client = redis_lib.Redis.from_url(redis_url, decode_responses=True)
    client.ping()  # fail fast at startup rather than on the first request
    return RedisAnomalyTracker(client)


tracker = build_tracker()
