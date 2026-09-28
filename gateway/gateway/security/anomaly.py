"""In-memory behavioral anomaly tracker.

Tracks two signals per agent over a sliding time window: call rate
(excessive API calls / possible exfiltration staging) and denial rate
(repeated failed authorization, a classic sign of an agent -- or an
attacker driving one -- probing for a permission it doesn't have).

Kept in-process and dependency-free for the demo; swap for a Redis-backed
window in a multi-instance deployment.
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


tracker = AnomalyTracker()
