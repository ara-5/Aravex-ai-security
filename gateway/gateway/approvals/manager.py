"""Human-in-the-loop approval queue.

When the policy engine returns HUMAN_APPROVAL, the action does not execute.
It is parked here in a pending state until an authorized human resolves it.
The gateway never auto-executes a HUMAN_APPROVAL action -- that decision is
enforced by construction, not by convention.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from gateway.models import ActionRequest, PolicyDecision


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class ApprovalRecord(BaseModel):
    approval_id: str = Field(default_factory=lambda: str(uuid4()))
    request: ActionRequest
    decision: PolicyDecision
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


class ApprovalManager:
    def __init__(self):
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = Lock()

    def create(self, request: ActionRequest, decision: PolicyDecision) -> ApprovalRecord:
        record = ApprovalRecord(request=request, decision=decision)
        with self._lock:
            self._records[record.approval_id] = record
        return record

    def get(self, approval_id: str) -> Optional[ApprovalRecord]:
        return self._records.get(approval_id)

    def list_pending(self) -> list[ApprovalRecord]:
        return [r for r in self._records.values() if r.status == ApprovalStatus.PENDING]

    def pending_count(self) -> int:
        return len(self.list_pending())

    def resolve(self, approval_id: str, approver: str, approved: bool) -> Optional[ApprovalRecord]:
        with self._lock:
            record = self._records.get(approval_id)
            if record is None or record.status != ApprovalStatus.PENDING:
                return record
            record.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
            record.resolved_at = datetime.now(timezone.utc)
            record.resolved_by = approver
            return record


manager = ApprovalManager()
