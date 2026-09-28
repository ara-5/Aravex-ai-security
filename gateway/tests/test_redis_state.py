"""Integration tests for the Redis-backed AnomalyTracker/ApprovalManager.

Skipped unless REDIS_URL points at a real Redis server. Run locally with:

    docker run -d --rm -p 6379:6379 redis:7-alpine
    REDIS_URL=redis://localhost:6379/0 pytest tests/test_redis_state.py -v

CI runs this against a Redis service container on every push (see
.github/workflows/ci.yml).
"""
from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("REDIS_URL"), reason="REDIS_URL not set -- no live Redis to test against")


@pytest.fixture
def redis_client():
    import redis as redis_lib

    client = redis_lib.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    yield client
    for key in client.keys("aegisai:test:*"):
        client.delete(key)


def test_redis_anomaly_tracker_flags_burst_and_repeated_denials(redis_client):
    from gateway.security.anomaly import RedisAnomalyTracker

    agent_id = f"agent-{uuid.uuid4().hex[:8]}"
    t = RedisAnomalyTracker(redis_client, key_prefix="aegisai:test:anomaly", rate_threshold=5, fail_threshold=2)

    for _ in range(6):
        t.record_call(agent_id)
    findings, score = t.evaluate(agent_id)
    assert any(f.startswith("excessive_api_calls") for f in findings)
    assert score > 0

    for _ in range(2):
        t.record_denial(agent_id)
    findings, score = t.evaluate(agent_id)
    assert any(f.startswith("repeated_failed_authorization") for f in findings)


def test_redis_anomaly_tracker_isolates_agents(redis_client):
    from gateway.security.anomaly import RedisAnomalyTracker

    t = RedisAnomalyTracker(redis_client, key_prefix="aegisai:test:anomaly-iso", rate_threshold=3, fail_threshold=2)
    noisy = f"agent-{uuid.uuid4().hex[:8]}"
    quiet = f"agent-{uuid.uuid4().hex[:8]}"

    for _ in range(10):
        t.record_call(noisy)
    t.record_call(quiet)

    noisy_findings, _ = t.evaluate(noisy)
    quiet_findings, _ = t.evaluate(quiet)
    assert noisy_findings
    assert not quiet_findings


def test_redis_approval_manager_round_trip(redis_client):
    from gateway.approvals.manager import ApprovalStatus, RedisApprovalManager
    from gateway.models import ActionRequest, DataClassification, Decision, PolicyDecision

    m = RedisApprovalManager(redis_client, key_prefix="aegisai:test:approval")
    request = ActionRequest(
        human_id="h-jane-owner",
        agent_id="data-ops-agent",
        tool_id="database_admin_tool",
        action="delete",
        resource="database.production_orders",
        data_classification=DataClassification.HIGHLY_SENSITIVE,
    )
    decision = PolicyDecision(
        request_id=request.request_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=Decision.HUMAN_APPROVAL,
        risk_score=1.0,
        reasons=["test"],
        matched_rules=["require_approval_prod_delete"],
    )

    record = m.create(request, decision)
    assert record.status == ApprovalStatus.PENDING
    assert any(r.approval_id == record.approval_id for r in m.list_pending())

    resolved = m.resolve(record.approval_id, "h-jane-owner", True)
    assert resolved.status == ApprovalStatus.APPROVED
    assert resolved.resolved_by == "h-jane-owner"
    assert not any(r.approval_id == record.approval_id for r in m.list_pending())

    fetched = m.get(record.approval_id)
    assert fetched.status == ApprovalStatus.APPROVED
