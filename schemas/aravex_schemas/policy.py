"""A candidate policy derived from a finding, awaiting human review."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from .common import Decision


class ProposalStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    REJECTED = "rejected"
    ACTIVE = "active"


class PolicyProposal(BaseModel):
    """Generated rules are never auto-activated: a human approves them first."""

    id: str
    finding_id: str
    rule_id: str
    effect: Decision
    rationale: str
    rego: Optional[str] = None
    yaml_rule: Optional[str] = None
    status: ProposalStatus = ProposalStatus.DRAFT
    reviewed_by: Optional[str] = None
