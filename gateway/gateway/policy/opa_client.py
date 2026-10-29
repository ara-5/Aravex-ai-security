"""Client for the real Open Policy Agent server -- the production path for
declarative rule evaluation.

gateway/policy/engine.py prefers this over the local YAML rule matcher
(gateway/policy/engine.Rule) whenever OPA_URL is configured. If it isn't
configured, or the OPA server is unreachable, the engine falls back to the
local rules transparently -- so `uvicorn --reload` alone still works with
zero extra infrastructure, and docker-compose (which sets OPA_URL) gets the
policy-as-code path with a real, independently-testable Rego policy
(gateway/policy/rego/guardrails.rego, exercised by `opa test`).

Uses one persistent httpx.Client with a real connection pool, not the
`httpx.post()` module-level convenience function. That function opens (and
tears down) a brand-new TCP connection for every call -- fine at low
volume, but under concurrent load it's a fresh TCP handshake to OPA on
every single policy decision. A load test (scripts/loadtest.py) is what
surfaced this: it's the same class of bug the Postgres audit store had
before it got a connection pool (see gateway/audit/postgres_store.py).
"""
from __future__ import annotations

import os
import threading

import httpx

RESULT_PATH = "/v1/data/aegisai/guardrails/result"

_client: httpx.Client | None = None
_client_lock = threading.Lock()


class OPAUnavailable(Exception):
    """Raised when OPA is configured but couldn't be reached in time."""


def is_configured() -> bool:
    return bool(os.environ.get("OPA_URL"))


def _get_client(base_url: str) -> httpx.Client:
    global _client
    if _client is None or str(_client.base_url) != base_url:
        with _client_lock:
            if _client is None or str(_client.base_url) != base_url:
                if _client is not None:
                    _client.close()
                _client = httpx.Client(base_url=base_url)
    return _client


def evaluate(input_doc: dict, timeout: float = 2.0) -> dict:
    """Returns {"decision": "DENY"|"HUMAN_APPROVAL"|"NONE", "matched_rules": [...], "reasons": [...]}.

    Raises OPAUnavailable on any network/timeout/malformed-response error --
    callers are expected to fall back to the local rule engine on that.
    """
    base_url = os.environ.get("OPA_URL")
    if not base_url:
        raise OPAUnavailable("OPA_URL is not configured")

    try:
        client = _get_client(base_url)
        response = client.post(RESULT_PATH, json={"input": input_doc}, timeout=timeout)
        response.raise_for_status()
        body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OPAUnavailable(str(exc)) from exc

    result = body.get("result")
    if not isinstance(result, dict) or "decision" not in result:
        raise OPAUnavailable(f"unexpected OPA response shape: {body!r}")

    return result
