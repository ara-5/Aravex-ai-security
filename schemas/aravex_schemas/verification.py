"""Proof that a mitigation works: the same attack, replayed against the defended system."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from .action import PolicyDecision


class VerificationOutcome(str, Enum):
    BLOCKED = "blocked"  # attack no longer succeeds
    STILL_SUCCEEDS = "still_succeeds"
    INCONCLUSIVE = "inconclusive"


class VerificationResult(BaseModel):
    finding_id: str
    policy_ids: list[str] = Field(default_factory=list)
    success_without_defense: bool
    success_with_defense: bool
    outcome: VerificationOutcome
    decisions: list[PolicyDecision] = Field(default_factory=list)
    verified_at: Optional[datetime] = None
    note: Optional[str] = None


def classify(success_without_defense: bool, success_with_defense: bool) -> VerificationOutcome:
    """An unreproducible baseline proves nothing, so it is inconclusive."""
    if not success_without_defense:
        return VerificationOutcome.INCONCLUSIVE
    return VerificationOutcome.STILL_SUCCEEDS if success_with_defense else VerificationOutcome.BLOCKED
