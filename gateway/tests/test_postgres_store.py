"""Integration tests for the Postgres durable audit trail.

Skipped unless DATABASE_URL points at a real Postgres server. Run locally
with:

    docker run -d --rm -p 5432:5432 \\
        -e POSTGRES_USER=aegisai -e POSTGRES_PASSWORD=aegisai -e POSTGRES_DB=aegisai \\
        postgres:16-alpine
    DATABASE_URL=postgresql://aegisai:aegisai@localhost:5432/aegisai \\
        pytest tests/test_postgres_store.py -v

CI runs this against a Postgres service container on every push (see
.github/workflows/ci.yml).
"""
from __future__ import annotations

import os

import pytest

from gateway.audit import postgres_store
from gateway.models import ActionRequest, DataClassification, Decision, PolicyDecision, SecurityFinding

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL not set -- no live Postgres to test against"
)


@pytest.fixture(autouse=True)
def reset_schema_cache():
    postgres_store.reset_schema_cache()
    yield


def _connect():
    import psycopg

    return psycopg.connect(os.environ["DATABASE_URL"])


def test_write_decision_is_queryable():
    request = ActionRequest(
        human_id="h-jane-owner",
        agent_id="customer-support-agent",
        tool_id="customer_db_tool",
        action="export",
        resource="customer_db.bulk",
        record_count=50000,
        data_classification=DataClassification.SENSITIVE,
        destination="external_api",
    )
    decision = PolicyDecision(
        request_id=request.request_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=Decision.DENY,
        risk_score=1.0,
        reasons=["rule 'deny_bulk_export': too many records"],
        matched_rules=["deny_bulk_export"],
        findings=[SecurityFinding(category="dlp", detail="generic_api_key_or_secret")],
    )

    postgres_store.write_decision(request, decision)

    with _connect() as conn:
        row = conn.execute(
            "SELECT agent_id, action, decision, risk_score, matched_rules, findings "
            "FROM decisions WHERE request_id = %s",
            (request.request_id,),
        ).fetchone()

    assert row is not None
    agent_id, action, decision_value, risk_score, matched_rules, findings = row
    assert agent_id == "customer-support-agent"
    assert action == "export"
    assert decision_value == "DENY"
    assert risk_score == 1.0
    assert matched_rules == ["deny_bulk_export"]
    assert findings == ["dlp:generic_api_key_or_secret"]


def test_write_decision_does_not_raise_when_database_url_missing(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    request = ActionRequest(
        human_id="h-jane-owner",
        agent_id="customer-support-agent",
        tool_id="customer_db_tool",
        action="read",
        resource="customer_db.profile",
    )
    decision = PolicyDecision(
        request_id=request.request_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=Decision.ALLOW,
        risk_score=0.1,
        reasons=[],
    )
    postgres_store.write_decision(request, decision)  # must not raise
