"""What an agent wants to do, and what the runtime gateway decided."""
from __future__ import annotations

from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from .common import DataClassification, Decision


class AgentAction(BaseModel):
    """One request in the chain Human -> Agent -> Tool -> Resource.

    Field names match the gateway's ``ActionRequest`` exactly, so a gateway
    request validates as an ``AgentAction`` with no mapping code.
    """

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    human_id: str
    agent_id: str
    tool_id: str
    action: str
    resource: str
    data_classification: DataClassification = DataClassification.INTERNAL
    record_count: int = 1
    destination: str = "internal"
    payload_preview: str = ""
    context: dict[str, Any] = Field(default_factory=dict)


class RuntimeFinding(BaseModel):
    """A detector hit raised while evaluating an action (DLP, injection, anomaly)."""

    category: str
    detail: str


class PolicyDecision(BaseModel):
    """The gateway's verdict on an ``AgentAction``."""

    request_id: str
    agent_id: str
    action: str
    resource: str
    decision: Decision
    risk_score: float = Field(ge=0.0)
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    findings: list[RuntimeFinding] = Field(default_factory=list)
    approval_id: Optional[str] = None
