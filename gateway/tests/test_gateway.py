"""HTTP-level integration tests for the FastAPI gateway, using the
in-process TestClient so no server needs to be running."""
from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.main import app
from tests.conftest import auth_headers

client = TestClient(app)


def test_healthz():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_read_customer_profile_allowed():
    response = client.post(
        "/v1/agent-action",
        headers=auth_headers("customer-support-agent"),
        json={
            "human_id": "h-jane-owner",
            "agent_id": "customer-support-agent",
            "tool_id": "customer_db_tool",
            "action": "read",
            "resource": "customer_db.profile",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW"


def test_secret_access_denied():
    response = client.post(
        "/v1/agent-action",
        headers=auth_headers("customer-support-agent"),
        json={
            "human_id": "h-jane-owner",
            "agent_id": "customer-support-agent",
            "tool_id": "customer_db_tool",
            "action": "read",
            "resource": "secrets.api_key",
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"


def test_production_delete_creates_pending_approval():
    response = client.post(
        "/v1/agent-action",
        headers=auth_headers("data-ops-agent"),
        json={
            "human_id": "h-jane-owner",
            "agent_id": "data-ops-agent",
            "tool_id": "database_admin_tool",
            "action": "delete",
            "resource": "database.production_orders",
            "data_classification": "HIGHLY_SENSITIVE",
        },
    )
    body = response.json()
    assert body["decision"] == "HUMAN_APPROVAL"
    approval_id = body["approval_id"]
    assert approval_id is not None

    pending = client.get("/v1/approvals").json()
    assert any(r["approval_id"] == approval_id for r in pending)

    resolved = client.post(
        f"/v1/approvals/{approval_id}/decision",
        json={"approver": "h-jane-owner", "approved": True},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "APPROVED"

    # Resolving twice is rejected.
    second = client.post(
        f"/v1/approvals/{approval_id}/decision",
        json={"approver": "h-jane-owner", "approved": True},
    )
    assert second.status_code == 409


def test_metrics_endpoint_exposes_prometheus_format():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"aegisai_requests_total" in response.content


def test_missing_credential_is_rejected():
    response = client.post(
        "/v1/agent-action",
        json={
            "human_id": "h-jane-owner",
            "agent_id": "customer-support-agent",
            "tool_id": "customer_db_tool",
            "action": "read",
            "resource": "customer_db.profile",
        },
    )
    assert response.status_code == 401


def test_wrong_credential_is_rejected():
    response = client.post(
        "/v1/agent-action",
        headers={"Authorization": "Bearer not-the-right-key"},
        json={
            "human_id": "h-jane-owner",
            "agent_id": "customer-support-agent",
            "tool_id": "customer_db_tool",
            "action": "read",
            "resource": "customer_db.profile",
        },
    )
    assert response.status_code == 401


def test_credential_does_not_transfer_between_agents():
    # A valid key for one agent must not authenticate a request claiming a
    # different agent_id -- otherwise the identity chain is just decoration.
    response = client.post(
        "/v1/agent-action",
        headers=auth_headers("billing-agent"),
        json={
            "human_id": "h-jane-owner",
            "agent_id": "data-ops-agent",
            "tool_id": "database_admin_tool",
            "action": "delete",
            "resource": "database.production_orders",
        },
    )
    assert response.status_code == 401
