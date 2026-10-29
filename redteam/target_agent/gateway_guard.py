"""
Optional runtime-gateway guard for the target agent.

Off by default, so the target stays the deliberately vulnerable system under
test. With GATEWAY_MODE=enforce, every tool call is submitted to the Aravex
gateway (POST /v1/agent-action) *before* its handler runs, and only an ALLOW
decision lets it execute. This is the "protected" half of the
with/without-gateway comparison.

Fails closed: if the gateway is unreachable, rejects our credential, or
returns anything other than ALLOW (including HUMAN_APPROVAL, which parks the
action), the tool does not run.
"""
from __future__ import annotations

import json
import threading

import httpx

from target_agent.config import (
    GATEWAY_AGENT_ID,
    GATEWAY_API_KEY,
    GATEWAY_HUMAN_ID,
    GATEWAY_INTERNAL_DOMAINS,
    GATEWAY_MODE,
    GATEWAY_URL,
)

BLOCKED_PREFIX = "[blocked by gateway]"
BLOCKED_LOG: list[dict] = []  # tool calls the gateway refused, for the red-team report
_lock = threading.Lock()
_client: httpx.Client | None = None


def enabled() -> bool:
    return GATEWAY_MODE == "enforce"


def _http() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(base_url=GATEWAY_URL, timeout=10.0)
    return _client


def _is_external(address: str) -> bool:
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    return domain not in GATEWAY_INTERNAL_DOMAINS


def build_action(name: str, args: dict, memory_snapshot: str = "") -> dict:
    """Translate a target-agent tool call into a gateway ActionRequest.

    The mapping is deliberately literal: it says what the call *does*, and
    leaves judging whether that is acceptable to the gateway's policy.
    """
    base = {"human_id": GATEWAY_HUMAN_ID, "agent_id": GATEWAY_AGENT_ID}

    if name == "file_read":
        path = str(args.get("path", ""))
        return {**base, "tool_id": "filesystem_tool", "action": "read",
                "resource": f"filesystem.{path}"}
    if name == "file_write":
        return {**base, "tool_id": "filesystem_tool", "action": "write",
                "resource": f"filesystem.{args.get('path', '')}",
                "payload_preview": str(args.get("content", ""))[:2000]}
    if name == "send_email":
        to = str(args.get("to", ""))
        return {**base, "tool_id": "email_tool", "action": "send",
                "resource": f"email.{to}",
                "destination": "external_api" if _is_external(to) else "internal",
                "payload_preview": f"{args.get('subject', '')}\n{args.get('body', '')}"[:2000]}
    if name == "db_lookup":
        query = str(args.get("query", ""))
        broad = any(w in query.lower() for w in ("all", "*", "everyone", "every customer"))
        return {**base, "tool_id": "customer_db_tool",
                "action": "export" if broad else "read",
                "resource": "customer_db.records",
                "record_count": 3 if broad else 1,
                "data_classification": "SENSITIVE", "payload_preview": query[:2000]}
    if name == "cloud_metadata_fetch":
        return {**base, "tool_id": "secrets_tool", "action": "read",
                "resource": "secrets.cloud_metadata"}
    if name == "calendar_sync":
        # Advertised as a calendar sync; what it really ships out is memory.
        return {**base, "tool_id": "calendar_mcp_tool", "action": "send",
                "resource": "calendar.team_shared", "destination": "external_api",
                "data_classification": "SENSITIVE",
                "payload_preview": memory_snapshot[:2000]}
    if name == "request_integration_access":
        return {**base, "tool_id": "iam_tool", "action": "access",
                "resource": "iam.scope.admin"}
    if name == "get_service_token":
        return {**base, "tool_id": "secrets_tool", "action": "read",
                "resource": "secrets.service_token"}
    # Unknown tool: ask anyway so the gateway's identity check decides.
    return {**base, "tool_id": f"unknown_{name}", "action": "access", "resource": f"unknown.{name}"}


def check(name: str, args: dict, memory_snapshot: str = "") -> tuple[bool, str]:
    """Return (allowed, reason). Anything but an explicit ALLOW is a refusal."""
    action = build_action(name, args, memory_snapshot)
    try:
        resp = _http().post(
            "/v1/agent-action",
            json=action,
            headers={"Authorization": f"Bearer {GATEWAY_API_KEY}"} if GATEWAY_API_KEY else {},
        )
        if resp.status_code != 200:
            allowed, reason, rules = False, f"gateway returned HTTP {resp.status_code}", []
        else:
            body = resp.json()
            allowed = body.get("decision") == "ALLOW"
            reason = "; ".join(body.get("reasons", [])) or body.get("decision", "")
            rules = body.get("matched_rules", [])
            decision = body.get("decision", "UNKNOWN")
    except Exception as exc:  # unreachable, timeout, bad JSON: fail closed
        allowed, reason, rules = False, f"gateway unavailable ({type(exc).__name__})", []

    if not allowed:
        with _lock:
            BLOCKED_LOG.append({
                "tool_name": name,
                "arguments": json.dumps(args, default=str)[:500],
                "decision": locals().get("decision", "ERROR"),
                "reason": reason,
                "matched_rules": rules,
            })
    return allowed, reason


def reset() -> None:
    with _lock:
        BLOCKED_LOG.clear()
