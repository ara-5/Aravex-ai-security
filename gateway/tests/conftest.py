"""Shared pytest fixtures.

Seeds a known set of agent credentials directly into the in-process
CredentialStore singleton before every test, so HTTP-layer tests can
authenticate without depending on gitignored, locally-generated key files.
"""
from __future__ import annotations

import os

import pytest

from gateway.identity.credentials import hash_key, store

TEST_AGENT_KEYS = {
    "customer-support-agent": "test-support-key",
    "data-ops-agent": "test-dataops-key",
    "billing-agent": "test-billing-key",
}


@pytest.fixture(autouse=True)
def seed_test_credentials():
    for agent_id, plaintext_key in TEST_AGENT_KEYS.items():
        store.set_hash(agent_id, hash_key(plaintext_key))
    yield


@pytest.fixture(scope="session", autouse=True)
def reset_shared_redis_state():
    """Tests that go through the HTTP layer (test_gateway.py,
    test_opa_integration.py) exercise the real module-level `tracker` /
    `manager` singletons from gateway.security.anomaly and
    gateway.approvals.manager -- the same production Redis key namespace a
    live gateway uses, not an isolated per-test one (tests/test_redis_state.py
    covers those classes directly with their own throwaway key prefixes).

    Without this, running the suite twice within the anomaly tracker's 60s
    window against the same Redis leaves real state (e.g.
    "aegisai:anomaly:calls:customer-support-agent") that inflates the
    request count the *next* run sees, occasionally flipping an ALLOW into
    a HUMAN_APPROVAL and failing a deterministic test for no code reason.
    CI doesn't hit this (fresh service container every run) -- this is for
    running `pytest` twice in a row locally against a persistent Redis."""
    if os.environ.get("REDIS_URL"):
        import redis as redis_lib

        client = redis_lib.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
        for pattern in ("aegisai:anomaly:*", "aegisai:approval:*"):
            keys = client.keys(pattern)
            if keys:
                client.delete(*keys)
    yield


@pytest.fixture(scope="session", autouse=True)
def shutdown_tracer_provider():
    """OTel's BatchSpanProcessor exports spans on a background thread. If
    that thread is still alive when pytest tears down captured stdout, it
    raises "I/O operation on closed file" -- harmless, but noisy in CI logs.
    Flushing and shutting the provider down before the session ends avoids
    the race."""
    yield
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    shutdown = getattr(provider, "shutdown", None)
    if shutdown:
        shutdown()


def auth_headers(agent_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_AGENT_KEYS[agent_id]}"}
