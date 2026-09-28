"""Core data contracts shared across the gateway: identity chain, the action
an agent wants to take, and the policy decision returned for it."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"


class ResourcePermission(BaseModel):
    read: bool = False
    write: bool = False
    send: bool = False
    delete: bool = False
    access: bool = False
    export: bool = False


class HumanIdentity(BaseModel):
    human_id: str
    name: str
    email: str = ""
    role: str = "user"


class AgentIdentity(BaseModel):
    agent_id: str
    name: str
    description: str = ""
    owner_human_id: str
    trust_level: str = "standard"
    allowed_tools: list[str] = Field(default_factory=list)
    permissions: dict[str, ResourcePermission] = Field(default_factory=dict)


class ToolIdentity(BaseModel):
    tool_id: str
    resource_category: str


class ActionRequest(BaseModel):
    """A single request in the identity chain: Human -> Agent -> Tool -> Resource."""

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


class SecurityFinding(BaseModel):
    category: str
    detail: str


class PolicyDecision(BaseModel):
    request_id: str
    agent_id: str
    action: str
    resource: str
    decision: Decision
    risk_score: float
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    approval_id: Optional[str] = None
