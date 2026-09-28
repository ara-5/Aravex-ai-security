"""Human-in-the-loop approval queue.

When the policy engine returns HUMAN_APPROVAL, the action does not execute.
It is parked here in a pending state until an authorized human resolves it.
The gateway never auto-executes a HUMAN_APPROVAL action -- that decision is
enforced by construction, not by convention.

Two implementations behind the same interface: `ApprovalManager` (in-memory,
correct for one process) and `RedisApprovalManager` (JSON records + a Redis
set for the pending index, correct across a fleet of gateway replicas --
without it, an approval created on instance A would be invisible to whoever
resolves it against instance B). Selected via REDIS_URL, see build_manager().
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


class RedisApprovalManager:
    """Same contract as ApprovalManager. Each record is a JSON blob at
    aegisai:approval:{id}; a Redis set tracks which ids are still pending so
    list_pending() doesn't have to scan every record ever created."""

    def __init__(self, redis_client, key_prefix: str = "aegisai:approval"):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.pending_set_key = f"{key_prefix}:pending"

    def _record_key(self, approval_id: str) -> str:
        return f"{self.key_prefix}:{approval_id}"

    def create(self, request: ActionRequest, decision: PolicyDecision) -> ApprovalRecord:
        record = ApprovalRecord(request=request, decision=decision)
        pipe = self.redis.pipeline()
        pipe.set(self._record_key(record.approval_id), record.model_dump_json())
        pipe.sadd(self.pending_set_key, record.approval_id)
        pipe.execute()
        return record

    def get(self, approval_id: str) -> Optional[ApprovalRecord]:
        raw = self.redis.get(self._record_key(approval_id))
        if raw is None:
            return None
        return ApprovalRecord.model_validate_json(raw)

    def list_pending(self) -> list[ApprovalRecord]:
        records = []
        for approval_id in self.redis.smembers(self.pending_set_key):
            record = self.get(approval_id)
            if record is not None and record.status == ApprovalStatus.PENDING:
                records.append(record)
            else:
                self.redis.srem(self.pending_set_key, approval_id)
        return records

    def pending_count(self) -> int:
        return len(self.list_pending())

    def resolve(self, approval_id: str, approver: str, approved: bool) -> Optional[ApprovalRecord]:
        record = self.get(approval_id)
        if record is None or record.status != ApprovalStatus.PENDING:
            return record
        record.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        record.resolved_at = datetime.now(timezone.utc)
        record.resolved_by = approver
        pipe = self.redis.pipeline()
        pipe.set(self._record_key(approval_id), record.model_dump_json())
        pipe.srem(self.pending_set_key, approval_id)
        pipe.execute()
        return record


def build_manager():
    """REDIS_URL configured -> shared Redis-backed manager (multi-instance
    safe). Otherwise -> in-memory manager (zero extra infrastructure)."""
    import os

    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        return ApprovalManager()

    import redis as redis_lib

    client = redis_lib.Redis.from_url(redis_url, decode_responses=True)
    client.ping()
    return RedisApprovalManager(client)


manager = build_manager()
