"""Lightweight data-loss-prevention scanner.

Looks for secrets and sensitive-data patterns in text an agent is about to
read, write, or ship to a destination. This is heuristic/regex based by
design -- fast enough to run on every request, no external service needed.
A production deployment would layer in a classifier or a DLP vendor API
behind the same `scan()` contract.
"""
from __future__ import annotations

import re

PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key_or_secret": re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"
    ),
    "private_key_block": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----"),
    "credit_card_number": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}

MAX_SCORE = 0.6
PER_HIT_SCORE = 0.2


def scan(text: str) -> tuple[list[str], float]:
    """Returns (pattern names matched, risk contribution in [0, MAX_SCORE])."""
    text = text or ""
    hits = [name for name, pattern in PATTERNS.items() if pattern.search(text)]
    score = min(MAX_SCORE, PER_HIT_SCORE * len(hits))
    return hits, score
