"""HTTP-level integration tests for the FastAPI gateway, using the
in-process TestClient so no server needs to be running."""
from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.main import app
from tests.conftest import approver_headers, auth_headers

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


def test_production_delete_creates_pending_approval(approver_configured):
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

    pending = client.get("/v1/approvals", headers=approver_headers()).json()
    assert any(r["approval_id"] == approval_id for r in pending)

    resolved = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=approver_headers(),
        json={"approved": True},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "APPROVED"

    # Resolving twice is rejected.
    second = client.post(
        f"/v1/approvals/{approval_id}/decision",
        headers=approver_headers(),
        json={"approved": True},
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


def _pending_approval_id() -> str:
    body = client.post(
        "/v1/agent-action",
        headers=auth_headers("data-ops-agent"),
        json={"human_id": "h-jane-owner", "agent_id": "data-ops-agent", "tool_id": "database_admin_tool",
              "action": "delete", "resource": "database.auth_test", "data_classification": "HIGHLY_SENSITIVE"},
    ).json()
    assert body["decision"] == "HUMAN_APPROVAL"
    return body["approval_id"]


def test_approvals_are_disabled_when_no_approver_key_is_set(monkeypatch):
    monkeypatch.delenv("GATEWAY_APPROVER_KEY", raising=False)
    monkeypatch.delenv("GATEWAY_APPROVER_KEYS", raising=False)
    approval_id = _pending_approval_id()
    assert client.get("/v1/approvals").status_code == 503
    assert client.get("/v1/approvals", headers=approver_headers()).status_code == 503
    r = client.post(f"/v1/approvals/{approval_id}/decision", headers=approver_headers(),
                    json={"approver": "x", "approved": True})
    assert r.status_code == 503


def test_an_agent_cannot_approve_its_own_request(approver_configured):
    approval_id = _pending_approval_id()
    for headers in ({}, auth_headers("data-ops-agent"), {"Authorization": "Bearer wrong"}):
        assert client.get("/v1/approvals", headers=headers).status_code == 401
        r = client.post(f"/v1/approvals/{approval_id}/decision", headers=headers,
                        json={"approver": "data-ops-agent", "approved": True})
        assert r.status_code == 401, headers
    # still pending: nothing above resolved it
    assert client.get(f"/v1/approvals/{approval_id}", headers=approver_headers()).json()["status"] == "PENDING"


def test_agent_can_read_only_its_own_approval_status(approver_configured):
    approval_id = _pending_approval_id()
    own = client.get(f"/v1/approvals/{approval_id}", headers=auth_headers("data-ops-agent"))
    assert own.status_code == 200 and own.json()["status"] == "PENDING"
    other = client.get(f"/v1/approvals/{approval_id}", headers=auth_headers("billing-agent"))
    assert other.status_code == 401
    assert client.get(f"/v1/approvals/{approval_id}").status_code == 401
    # an unknown id looks the same as a wrong credential
    assert client.get("/v1/approvals/nope", headers=auth_headers("data-ops-agent")).status_code == 401
    assert client.get("/v1/approvals/nope", headers=approver_headers()).status_code == 404


def test_audit_records_the_authenticated_approver_not_a_typed_name(approver_configured):
    approval_id = _pending_approval_id()
    # A name that does not match the credential is refused and changes nothing.
    r = client.post(f"/v1/approvals/{approval_id}/decision", headers=approver_headers("omar"),
                    json={"approver": "jane", "approved": True})
    assert r.status_code == 400
    assert client.get(f"/v1/approvals/{approval_id}", headers=approver_headers()).json()["status"] == "PENDING"
    # Without a name, the credential's owner is recorded.
    r = client.post(f"/v1/approvals/{approval_id}/decision", headers=approver_headers("omar"),
                    json={"approved": False})
    assert r.status_code == 200
    assert r.json()["resolved_by"] == "omar" and r.json()["status"] == "DENIED"


def test_each_approver_has_their_own_key(approver_configured):
    a, b = _pending_approval_id(), _pending_approval_id()
    assert client.post(f"/v1/approvals/{a}/decision", headers=approver_headers("jane"),
                       json={"approved": True}).json()["resolved_by"] == "jane"
    assert client.post(f"/v1/approvals/{b}/decision", headers=approver_headers("omar"),
                       json={"approved": True}).json()["resolved_by"] == "omar"


def test_legacy_single_key_is_one_identity_and_bad_entries_are_ignored(monkeypatch):
    monkeypatch.setenv("GATEWAY_APPROVER_KEY", "old-key")
    monkeypatch.setenv("GATEWAY_APPROVER_KEYS", "nokey:, :nameless, bad name:k, ok:good-key")
    approval_id = _pending_approval_id()
    old = client.post(f"/v1/approvals/{approval_id}/decision",
                      headers={"Authorization": "Bearer old-key"}, json={"approved": True})
    assert old.status_code == 200 and old.json()["resolved_by"] == "approver"
    other = _pending_approval_id()
    for bad in ("", "nokey", "nameless", "k"):
        r = client.post(f"/v1/approvals/{other}/decision", headers={"Authorization": f"Bearer {bad}"},
                        json={"approved": True})
        assert r.status_code == 401, bad
    ok = client.post(f"/v1/approvals/{other}/decision", headers={"Authorization": "Bearer good-key"},
                     json={"approved": True})
    assert ok.json()["resolved_by"] == "ok"
