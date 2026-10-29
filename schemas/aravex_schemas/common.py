"""Enums shared by every Aravex contract.

Values mirror what the two source projects already emit, so existing data
validates unchanged: Decision and DataClassification come from the gateway,
Severity and FindingStatus from the red-team engine.
"""
from __future__ import annotations

from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED_PENDING_REGRESSION = "fixed_pending_regression"
    RESOLVED = "resolved"
    REGRESSED = "regressed"


class DefenseLayer(str, Enum):
    """Where a mitigation can realistically live.

    GATEWAY: the unsafe step is an agent *action* (tool call, data access,
    outbound send) that a runtime gateway can see and block.
    MODEL: the unsafe step happens inside the model's generation (jailbreak,
    prompt leakage); a gateway cannot see it and needs model-level defenses.
    PARTIAL: a gateway can limit the blast radius but not prevent the attack.
    """

    GATEWAY = "gateway"
    PARTIAL = "partial"
    MODEL = "model"
