"""A vulnerability discovered by the red-team engine, and its lifecycle."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from .common import DefenseLayer, FindingStatus, Severity


class Finding(BaseModel):
    """Attack -> Evidence -> Impact -> Remediation, as the red-team engine records it.

    ``triggering_actions`` is the new link that makes the feedback loop
    possible: the concrete tool calls the attack caused, expressed in the
    same shape the gateway evaluates, so a policy can be derived from them.
    """

    id: str
    category: str
    technique: str
    severity: Severity
    title: str
    attack_payload: str = ""
    attack_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    last_regression_result: Optional[str] = None  # "PASS" | "FAIL"
    last_regression_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    defense_layer: DefenseLayer = DefenseLayer.MODEL
    triggering_actions: list[dict[str, Any]] = Field(default_factory=list)
    linked_policy_ids: list[str] = Field(default_factory=list)
