"""The proxy: an MCP server that fronts another MCP server.

Tool listing is passed through unchanged. Every tools/call is turned into a
gateway action first and reaches the upstream server only on ALLOW. Logging goes
to stderr; stdout belongs to the MCP protocol.
"""
from __future__ import annotations

import asyncio
import logging

from mcp import ClientSession, types
from mcp.server.lowlevel import Server

from aravex_mcp.gate import APPROVED, HUMAN_APPROVAL, Gate, Verdict
from aravex_mcp.mapping import Mapping
from aravex_mcp.scan import fingerprint

log = logging.getLogger("aravex_mcp")

BLOCKED_PREFIX = "[blocked by Aravex gateway]"


def refusal(verdict: Verdict, approval_outcome: str | None = None) -> types.CallToolResult:
    """The tool result the agent sees when a call is not allowed.

    Only the primary reason is shown. The rest of the gateway's reasons are risk-score
    arithmetic, which would let a probing agent tune its attempts against the
    thresholds; the operator still gets all of it in the proxy log."""
    detail = verdict.reasons[0] if verdict.reasons else verdict.decision
    text = f"{BLOCKED_PREFIX} {verdict.decision}: {detail}"
    if verdict.matched_rules:
        text += f" (rules: {', '.join(verdict.matched_rules)})"
    if verdict.decision == HUMAN_APPROVAL and verdict.approval_id:
        text += f" (approval id: {verdict.approval_id}"
        text += f", {approval_outcome.lower()})" if approval_outcome else ", pending)"
    return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=text)])


def unpinned(name: str) -> types.CallToolResult:
    text = (f"{BLOCKED_PREFIX} tool '{name}' is not pinned or its definition changed since it was pinned. "
            "Review it and re-run `aravex-mcp scan`.")
    return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=text)])


def build_server(upstream: ClientSession, gate: Gate, mapping: Mapping, *,
                 agent_id: str, human_id: str, name: str = "aravex-mcp-proxy",
                 pins: dict[str, str] | None = None) -> Server:
    """pins maps tool name -> fingerprint from `aravex-mcp scan`. When given, a tool that
    was not pinned, or whose name, description or input schema changed since, is hidden
    from the agent and refused, so a server cannot swap in a poisoned description later."""
    server = Server(name, instructions=(
        "Tool calls pass through the Aravex zero-trust gateway. A call the gateway "
        "does not allow returns an error result starting with '[blocked by Aravex gateway]'."))

    async def _upstream_tools() -> list[types.Tool]:
        tools: list[types.Tool] = []
        cursor: str | None = None
        while True:
            page = await upstream.list_tools(cursor)
            tools.extend(page.tools)
            cursor = page.nextCursor
            if not cursor:
                return tools

    def _pinned_ok(tool: types.Tool) -> bool:
        return pins is None or pins.get(tool.name) == fingerprint(tool)

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        tools = await _upstream_tools()
        shown = [t for t in tools if _pinned_ok(t)]
        for t in tools:
            if t not in shown:
                log.warning("hiding %s: not pinned or definition changed", t.name)
        return shown

    # The upstream server validates its own arguments; validating here as well
    # would only add a second, possibly stale, copy of its schema.
    @server.call_tool(validate_input=False)
    async def _call_tool(tool_name: str, arguments: dict) -> types.CallToolResult:
        if pins is not None:
            # Checked against the server's CURRENT definition, not the one the client saw earlier.
            current = next((t for t in await _upstream_tools() if t.name == tool_name), None)
            if current is None or not _pinned_ok(current):
                log.warning("blocked %s: not pinned or definition changed", tool_name)
                return unpinned(tool_name)
        action = mapping.build_action(tool_name, arguments, agent_id=agent_id, human_id=human_id)
        verdict = await asyncio.to_thread(gate.check, action)
        outcome: str | None = None

        if verdict.decision == HUMAN_APPROVAL and verdict.approval_id and gate.approval_wait > 0:
            log.info("%s waiting up to %.0fs for approval %s", tool_name, gate.approval_wait, verdict.approval_id)
            outcome = await asyncio.to_thread(gate.await_approval, verdict.approval_id)
            allowed = outcome == APPROVED
        else:
            allowed = verdict.allowed

        if not allowed:
            log.warning("blocked %s: %s %s %s", tool_name, verdict.decision, verdict.reasons, verdict.matched_rules)
            return refusal(verdict, outcome)

        log.info("allowed %s (%s)", tool_name, "approved by a person" if outcome == APPROVED else verdict.decision)
        return await upstream.call_tool(tool_name, arguments)

    return server
