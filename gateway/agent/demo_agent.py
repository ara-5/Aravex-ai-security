"""A thin client that stands in for "the AI agent" in the architecture
diagram. It never touches a tool directly -- every action is submitted to
the AegisAI gateway first, and the tool only actually runs if the response
is ALLOW.
"""
from __future__ import annotations

from typing import Any

import httpx

from agent.tools import customer_db, email_tool, filesystem, payments

TOOL_DISPATCH = {
    ("customer_db_tool", "read"): lambda ctx: customer_db.read_profile(ctx.get("customer_id", "cust_1001")),
    ("customer_db_tool", "write"): lambda ctx: customer_db.write_profile(
        ctx.get("customer_id", "cust_1001"), ctx.get("fields", {})
    ),
    ("customer_db_tool", "export"): lambda ctx: customer_db.export_records(ctx.get("record_count", 0)),
    ("email_tool", "send"): lambda ctx: email_tool.send(
        ctx.get("to", ""), ctx.get("subject", ""), ctx.get("body", "")
    ),
    ("payments_tool", "read"): lambda ctx: payments.read_account(ctx.get("account_id", "acct_1")),
    ("database_admin_tool", "delete"): lambda ctx: filesystem.delete_database(ctx.get("database", "unknown")),
}


class GatewayClient:
    """Talks to the AegisAI gateway over HTTP -- exactly what a real agent
    runtime would do, wired in as a tool-call middleware."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self._client = httpx.Client(base_url=base_url, timeout=10.0)

    def submit(self, action_request: dict) -> dict:
        response = self._client.post("/v1/agent-action", json=action_request)
        response.raise_for_status()
        return response.json()

    def resolve_approval(self, approval_id: str, approver: str, approved: bool) -> dict:
        response = self._client.post(
            f"/v1/approvals/{approval_id}/decision",
            json={"approver": approver, "approved": approved},
        )
        response.raise_for_status()
        return response.json()


class AegisAgent:
    """A minimal agent runtime: every attempted action goes through the
    gateway before (if ever) reaching a real tool."""

    def __init__(self, agent_id: str, human_id: str, gateway: GatewayClient | None = None):
        self.agent_id = agent_id
        self.human_id = human_id
        self.gateway = gateway or GatewayClient()

    def act(self, tool_id: str, action: str, resource: str, tool_context: dict[str, Any] | None = None, **kwargs) -> dict:
        tool_context = tool_context or {}
        action_request = {
            "human_id": self.human_id,
            "agent_id": self.agent_id,
            "tool_id": tool_id,
            "action": action,
            "resource": resource,
            **kwargs,
        }
        decision = self.gateway.submit(action_request)

        result: dict[str, Any] = {"decision": decision}
        if decision["decision"] == "ALLOW":
            handler = TOOL_DISPATCH.get((tool_id, action))
            result["tool_result"] = handler(tool_context) if handler else {"note": "no simulated handler for this tool/action"}
        elif decision["decision"] == "HUMAN_APPROVAL":
            result["tool_result"] = None
            result["note"] = f"action parked pending human approval: {decision.get('approval_id')}"
        else:
            result["tool_result"] = None
            result["note"] = "action blocked by AegisAI gateway"

        return result
