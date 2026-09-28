"""Mint per-agent API credentials.

Run this once after cloning, before starting the gateway or the demo:

    python scripts/generate_agent_keys.py

For every agent in gateway/identity/agents.yaml, generates a random bearer
secret and:
  - writes only its SHA-256 hash to gateway/identity/agent_credentials.yaml
    (what the gateway loads to verify callers)
  - writes the plaintext key to .secrets/agent_keys.dev.yaml (what the demo
    agent/tests load to authenticate as that agent)

Both output files are gitignored. Re-running this script rotates every
agent's key -- the old ones stop working immediately, which is the point:
credentials are provisioned out of band, not checked into source.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from gateway.identity.credentials import DEFAULT_CREDENTIALS_PATH, hash_key
from gateway.identity.registry import registry

DEV_KEYS_PATH = Path(__file__).resolve().parent.parent / ".secrets" / "agent_keys.dev.yaml"


def main() -> None:
    plaintext_keys: dict[str, str] = {}
    hashes: dict[str, str] = {}

    for agent_id in sorted(registry.agents):
        key = f"aegis_{agent_id}_{secrets.token_urlsafe(24)}"
        plaintext_keys[agent_id] = key
        hashes[agent_id] = hash_key(key)

    DEFAULT_CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_CREDENTIALS_PATH.write_text(yaml.safe_dump({"agents": hashes}, sort_keys=True))

    DEV_KEYS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEV_KEYS_PATH.write_text(yaml.safe_dump({"agents": plaintext_keys}, sort_keys=True))

    print(f"Minted credentials for {len(hashes)} agent(s):")
    for agent_id in sorted(hashes):
        print(f"  - {agent_id}")
    print(f"\nHashes   -> {DEFAULT_CREDENTIALS_PATH} (gitignored -- regenerate per clone/deploy)")
    print(f"Dev keys -> {DEV_KEYS_PATH} (plaintext -- gitignored, never commit this)")


if __name__ == "__main__":
    main()
