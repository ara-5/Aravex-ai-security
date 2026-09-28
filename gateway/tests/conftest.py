"""Shared pytest fixtures.

Seeds a known set of agent credentials directly into the in-process
CredentialStore singleton before every test, so HTTP-layer tests can
authenticate without depending on gitignored, locally-generated key files.
"""
from __future__ import annotations

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


def auth_headers(agent_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_AGENT_KEYS[agent_id]}"}
