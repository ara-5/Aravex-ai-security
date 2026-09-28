"""Heuristic prompt-injection detector.

Scans the text an agent is about to act on (tool output, retrieved document,
user message) for classic injection/jailbreak markers. This is a signal
that feeds the risk score -- it is not a substitute for permission checks,
which is the point: even a fully "jailbroken" agent is still bound by its
IAM permissions and the policy engine's hard rules downstream.
"""
from __future__ import annotations

import re

INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)ignore (all )?(previous|prior|above) instructions"),
    re.compile(r"(?i)disregard (your|the) (system|previous) prompt"),
    re.compile(r"(?i)you are now (in )?(developer|jailbreak|dan) mode"),
    re.compile(r"(?i)reveal (your|the) (system prompt|instructions|hidden prompt)"),
    re.compile(r"(?i)act as (if you (had|have) no|an unrestricted)"),
    re.compile(r"(?i)do anything now"),
    re.compile(r"(?i)override (your )?safety (rules|guidelines|settings)"),
    re.compile(r"(?i)this is a (test|simulation)[,.]?\s*(bypass|skip|ignore)"),
    re.compile(r"(?i)new instructions from (the )?(system|admin|developer)\s*:"),
]

MAX_SCORE = 0.5
PER_HIT_SCORE = 0.25


def scan(text: str) -> tuple[list[str], float]:
    """Returns (matched pattern descriptions, risk contribution in [0, MAX_SCORE])."""
    text = text or ""
    hits = [p.pattern for p in INJECTION_PATTERNS if p.search(text)]
    score = min(MAX_SCORE, PER_HIT_SCORE * len(hits))
    return hits, score
