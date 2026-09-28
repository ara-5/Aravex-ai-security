"""Integration tests for the OPA-backed declarative rule path.

Skipped unless OPA_URL points at a real OPA server loaded with
gateway/policy/rego/. Run locally with:

    docker run -d --rm -p 8181:8181 \\
        -v "$(pwd)/gateway/policy/rego:/policy" \\
        openpolicyagent/opa run --server --addr 0.0.0.0:8181 /policy
    OPA_URL=http://localhost:8181 pytest tests/test_opa_integration.py -v

CI runs this against an OPA service container on every push (see
.github/workflows/ci.yml) so the OPA path is verified, not just the local
YAML fallback that the rest of the suite exercises by default.
"""
from __future__ import annotations

import os

import pytest

from gateway.identity.registry import registry
from gateway.models import ActionRequest, DataClassification, Decision
from gateway.policy.engine import PolicyEngine
from gateway.security.anomaly import AnomalyTracker

pytestmark = pytest.mark.skipif(not os.environ.get("OPA_URL"), reason="OPA_URL not set -- no live OPA server to test against")


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(identity_registry=registry, anomaly_tracker=AnomalyTracker())


def make_request(**overrides) -> ActionRequest:
    defaults = dict(
        human_id="h-jane-owner",
        agent_id="customer-support-agent",
        tool_id="customer_db_tool",
        action="read",
        resource="customer_db.profile",
        data_classification=DataClassification.INTERNAL,
        record_count=1,
        destination="internal",
    )
    defaults.update(overrides)
    return ActionRequest(**defaults)


def test_opa_allows_plain_read(engine: PolicyEngine):
    decision = engine.evaluate(make_request())
    assert decision.decision == Decision.ALLOW
    assert decision.matched_rules == []


def test_opa_denies_bulk_export(engine: PolicyEngine):
    request = make_request(
        action="export",
        resource="customer_db.bulk",
        record_count=50000,
        data_classification=DataClassification.SENSITIVE,
        destination="external_api",
    )
    decision = engine.evaluate(request)
    assert decision.decision == Decision.DENY
    assert "deny_bulk_export" in decision.matched_rules
    assert any(r.startswith("[opa]") for r in decision.reasons)


def test_opa_denies_secret_access(engine: PolicyEngine):
    decision = engine.evaluate(make_request(resource="secrets.api_key", data_classification=DataClassification.HIGHLY_SENSITIVE))
    assert decision.decision == Decision.DENY
    assert "deny_secret_access" in decision.matched_rules


def test_opa_requires_approval_for_prod_delete(engine: PolicyEngine):
    request = make_request(
        agent_id="data-ops-agent",
        tool_id="database_admin_tool",
        action="delete",
        resource="database.production_orders",
        data_classification=DataClassification.HIGHLY_SENSITIVE,
    )
    decision = engine.evaluate(request)
    assert decision.decision == Decision.HUMAN_APPROVAL
    assert "require_approval_prod_delete" in decision.matched_rules
