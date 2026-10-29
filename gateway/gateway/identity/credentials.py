"""Agent credential verification -- the missing half of zero-trust.

The IAM registry (registry.py) answers "what is this agent allowed to do."
This module answers the question that has to come first: "is the caller
actually that agent." Without it, `agent_id` in a request body is just an
unverified claim -- anything on the network could say `agent_id:
data-ops-agent` and inherit its permissions.

Each registered agent holds a bearer secret, provisioned out of band (see
scripts/generate_agent_keys.py). The gateway never stores the plaintext --
only a SHA-256 hash, loaded from gateway/identity/agent_credentials.yaml
(gitignored; generated locally, never committed). If that file is missing
or empty, every request is unauthenticated and gets rejected -- fail
closed, not fail open.
"""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import yaml

DEFAULT_CREDENTIALS_PATH = Path(__file__).parent / "agent_credentials.yaml"


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


class CredentialStore:
    def __init__(self, path: Path | str = DEFAULT_CREDENTIALS_PATH):
        self.path = Path(path)
        self._hashes: dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            self._hashes = {}
            return
        raw = yaml.safe_load(self.path.read_text()) or {}
        self._hashes = dict(raw.get("agents", {}))

    def set_hash(self, agent_id: str, key_hash: str) -> None:
        """Register a hash directly -- used by the key-generation script and
        by tests that need deterministic credentials without touching disk."""
        self._hashes[agent_id] = key_hash

    def is_configured(self) -> bool:
        return bool(self._hashes)

    def verify(self, agent_id: str, presented_key: str) -> bool:
        expected = self._hashes.get(agent_id)
        if not expected:
            return False
        # Constant-time comparison: this is an authentication check, and a
        # timing side-channel here would leak how much of the hash matched.
        return hmac.compare_digest(hash_key(presented_key), expected)


store = CredentialStore()
