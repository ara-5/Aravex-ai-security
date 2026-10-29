"""The MCP proxy puts the real gateway policy in front of an MCP server.

Setup: a fake upstream MCP server that records every call it actually receives,
the proxy in front of it, and the real gateway engine behind the proxy. Every
"blocked" test asserts that the upstream was never reached, not just that the
agent saw an error.

Everything runs in process over in-memory MCP transports.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session as connect

import gateway.main as gateway_main
from aravex_mcp import Gate, Mapping, MappingError, build_server
from aravex_mcp.mapping import _render
from aravex_mcp.proxy import BLOCKED_PREFIX
from gateway.policy.engine import PolicyEngine, Rule, load_rules
from gateway.security.anomaly import AnomalyTracker

ROOT = Path(__file__).resolve().parents[2]
APPROVED = (yaml.safe_load((ROOT / "policies" / "approved_rules.yaml").read_text(encoding="utf-8")) or {}).get("rules", [])
KEY = "proxy-test-key"
APPROVER = {"Authorization": "Bearer reviewer-key"}
HUMAN = "h-jane-owner"

MAPPING = Mapping.from_dict({
    "server": "demo",
    "internal_domains": ["example.com"],
    "tools": {
        "read_file": {"tool_id": "filesystem_tool", "action": "read", "resource": "filesystem.{path}"},
        "send_email": {"tool_id": "email_tool", "action": "send", "resource": "email.{to}",
                       "destination_from": "to", "payload_from": ["subject", "body"]},
        "get_secret": {"tool_id": "secrets_tool", "action": "read", "resource": "secrets.{name}"},
        "grant_scope": {"tool_id": "iam_tool", "action": "access", "resource": "iam.scope.{scope}"},
        "delete_records": {"tool_id": "database_admin_tool", "action": "delete", "resource": "database.{table}"},
        # shell_exec is deliberately left out of the mapping.
    },
})


def make_upstream():
    """A stand-in MCP server. `calls` lists what actually reached it."""
    calls: list[tuple[str, dict]] = []
    mcp = FastMCP("demo-upstream")

    @mcp.tool()
    def read_file(path: str) -> str:
        calls.append(("read_file", {"path": path}))
        return f"contents of {path}"

    @mcp.tool()
    def send_email(to: str, subject: str, body: str) -> str:
        calls.append(("send_email", {"to": to}))
        return f"sent to {to}"

    @mcp.tool()
    def get_secret(name: str) -> str:
        calls.append(("get_secret", {"name": name}))
        return "hunter2"

    @mcp.tool()
    def grant_scope(scope: str) -> str:
        calls.append(("grant_scope", {"scope": scope}))
        return f"granted {scope}"

    @mcp.tool()
    def delete_records(table: str) -> str:
        calls.append(("delete_records", {"table": table}))
        return f"deleted {table}"

    @mcp.tool()
    def shell_exec(cmd: str) -> str:
        calls.append(("shell_exec", {"cmd": cmd}))
        return "ran"

    return mcp, calls


def run(coro):
    return asyncio.run(coro)


@contextlib.asynccontextmanager
async def stack(gate_client, agent_id, *, approval_wait=0.0, mapping=MAPPING):
    upstream, calls = make_upstream()
    async with connect(upstream) as up_session:
        gate = Gate(gate_client, KEY, approval_wait=approval_wait, poll_interval=0.05)
        proxy = build_server(up_session, gate, mapping, agent_id=agent_id, human_id=HUMAN)
        async with connect(proxy) as client:
            yield client, calls, up_session


def text(result) -> str:
    return result.content[0].text


@pytest.fixture
def gateway(monkeypatch):
    """The real gateway app with the base rules (plus any extra rules a test sets)."""
    def install(extra=()):
        rules = load_rules() + [Rule(**r) for r in extra]
        monkeypatch.setattr(gateway_main, "engine", PolicyEngine(rules=rules, anomaly_tracker=AnomalyTracker()))

    monkeypatch.delenv("OPA_URL", raising=False)
    monkeypatch.setenv("GATEWAY_APPROVER_KEY", "reviewer-key")
    monkeypatch.setattr(gateway_main.credential_store, "verify", lambda *_: True)
    install()
    client = TestClient(gateway_main.app)
    client.install_rules = install
    return client


def fake_gateway(handler):
    return httpx.Client(base_url="http://gw.test", transport=httpx.MockTransport(handler))


# -- the proxy needs a control, or "blocked" proves nothing --------------------------------------
def test_control_the_dangerous_tools_do_run_without_the_proxy():
    async def scenario():
        upstream, calls = make_upstream()
        async with connect(upstream) as direct:
            await direct.call_tool("get_secret", {"name": "prod_db"})
            await direct.call_tool("shell_exec", {"cmd": "id"})
        return calls

    assert [c[0] for c in run(scenario())] == ["get_secret", "shell_exec"]


# -- allowed traffic passes through untouched ----------------------------------------------------
def test_allowed_call_reaches_upstream_and_result_is_unchanged(gateway):
    async def scenario():
        async with stack(gateway, "nova-assistant") as (client, calls, up):
            via_proxy = await client.call_tool("read_file", {"path": "notes/todo.txt"})
            direct = await up.call_tool("read_file", {"path": "notes/todo.txt"})
            return via_proxy, direct, calls

    via_proxy, direct, calls = run(scenario())
    assert not via_proxy.isError
    assert text(via_proxy) == text(direct) == "contents of notes/todo.txt"
    assert calls[0] == ("read_file", {"path": "notes/todo.txt"})


def test_tool_listing_is_passed_through(gateway):
    async def scenario():
        async with stack(gateway, "nova-assistant") as (client, _, up):
            return await client.list_tools(), await up.list_tools()

    via_proxy, direct = run(scenario())
    assert [t.name for t in via_proxy.tools] == [t.name for t in direct.tools]
    assert "shell_exec" in [t.name for t in via_proxy.tools]


# -- refusals ------------------------------------------------------------------------------------
@pytest.mark.parametrize("agent,tool,args", [
    ("nova-assistant", "get_secret", {"name": "prod_db"}),         # identity: tool not allowed
    ("nova-assistant-broad", "get_secret", {"name": "prod_db"}),   # identity ok, base rule denies
    ("nova-assistant", "grant_scope", {"scope": "admin"}),         # identity: iam_tool not allowed
    ("nova-assistant", "shell_exec", {"cmd": "id"}),               # no mapping entry
])
def test_refused_calls_never_reach_upstream(gateway, agent, tool, args):
    async def scenario():
        async with stack(gateway, agent) as (client, calls, _):
            return await client.call_tool(tool, args), calls

    result, calls = run(scenario())
    assert result.isError
    assert text(result).startswith(BLOCKED_PREFIX)
    assert "DENY" in text(result)
    assert calls == [], f"{tool} reached the upstream server despite the refusal"


def test_unmapped_tool_is_refused_by_the_gateway_and_says_why(gateway):
    async def scenario():
        async with stack(gateway, "nova-assistant-broad") as (client, calls, _):
            return await client.call_tool("shell_exec", {"cmd": "rm -rf /"}), calls

    result, calls = run(scenario())
    assert result.isError and calls == []
    assert "mcp_unmapped.demo.shell_exec" in text(result) and "not authorized" in text(result)


def test_agent_sees_the_rule_but_not_the_risk_arithmetic(gateway):
    async def scenario():
        async with stack(gateway, "nova-assistant-broad") as (client, _, _):
            return await client.call_tool("get_secret", {"name": "prod_db"})

    shown = text(run(scenario()))
    assert "deny_secret_access" in shown
    assert "base risk" not in shown and "+0.0" not in shown


@pytest.mark.parametrize("name,handler", [
    ("gateway down", lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused"))),
    ("bad credential (401)", lambda req: httpx.Response(401, json={"detail": "bad key"})),
    ("server error (500)", lambda req: httpx.Response(500, text="boom")),
    ("not json", lambda req: httpx.Response(200, text="<html>hi</html>")),
    ("no decision field", lambda req: httpx.Response(200, json={"request_id": "x"})),
    ("decision for another request", lambda req: httpx.Response(200, json={"request_id": "someone-else", "decision": "ALLOW"})),
    ("unknown decision", lambda req: httpx.Response(200, json={**json.loads(req.content), "decision": "MAYBE"})),
    ("lowercase allow", lambda req: httpx.Response(200, json={**json.loads(req.content), "decision": "allow"})),
])
def test_anything_but_a_clean_allow_fails_closed(name, handler):
    async def scenario():
        async with stack(fake_gateway(handler), "nova-assistant") as (client, calls, _):
            return await client.call_tool("read_file", {"path": "notes/todo.txt"}), calls

    result, calls = run(scenario())
    assert result.isError, name
    assert calls == [], f"upstream was reached when: {name}"


def test_a_clean_allow_from_a_stub_gateway_does_pass(gateway):
    """Guards the failure-mode table above: the stub path can say yes."""
    def handler(req):
        return httpx.Response(200, json={**json.loads(req.content), "decision": "ALLOW"})

    async def scenario():
        async with stack(fake_gateway(handler), "nova-assistant") as (client, calls, _):
            return await client.call_tool("read_file", {"path": "a"}), calls

    result, calls = run(scenario())
    assert not result.isError and calls == [("read_file", {"path": "a"})]


# -- human approval ------------------------------------------------------------------------------
def _pending(gateway, table):
    for rec in gateway.get("/v1/approvals", headers=APPROVER).json():
        if table in rec["request"]["resource"]:
            return rec["approval_id"]
    return None


async def _resolve_when_pending(gateway, table, approved):
    for _ in range(200):
        approval_id = await asyncio.to_thread(_pending, gateway, table)
        if approval_id:
            await asyncio.to_thread(
                gateway.post, f"/v1/approvals/{approval_id}/decision", json={"approved": approved},
                headers=APPROVER)
            return
        await asyncio.sleep(0.02)
    raise AssertionError("no approval request ever appeared")


def test_human_approval_refuses_at_once_by_default(gateway):
    async def scenario():
        async with stack(gateway, "data-ops-agent") as (client, calls, _):
            return await client.call_tool("delete_records", {"table": "prod_orders_a"}), calls

    result, calls = run(scenario())
    assert result.isError and "HUMAN_APPROVAL" in text(result) and "approval id" in text(result)
    assert calls == []


def test_human_approval_runs_only_after_a_person_approves(gateway):
    async def scenario():
        async with stack(gateway, "data-ops-agent", approval_wait=10) as (client, calls, _):
            call = asyncio.create_task(client.call_tool("delete_records", {"table": "prod_orders_b"}))
            await _resolve_when_pending(gateway, "prod_orders_b", True)
            return await call, calls

    result, calls = run(scenario())
    assert not result.isError, text(result)
    assert calls == [("delete_records", {"table": "prod_orders_b"})]


def test_human_approval_denied_by_a_person_does_not_run(gateway):
    async def scenario():
        async with stack(gateway, "data-ops-agent", approval_wait=10) as (client, calls, _):
            call = asyncio.create_task(client.call_tool("delete_records", {"table": "prod_orders_c"}))
            await _resolve_when_pending(gateway, "prod_orders_c", False)
            return await call, calls

    result, calls = run(scenario())
    assert result.isError and "denied" in text(result).lower()
    assert calls == []


def test_human_approval_timeout_does_not_run(gateway):
    async def scenario():
        async with stack(gateway, "data-ops-agent", approval_wait=0.3) as (client, calls, _):
            return await client.call_tool("delete_records", {"table": "prod_orders_d"}), calls

    result, calls = run(scenario())
    assert result.isError and "timeout" in text(result).lower()
    assert calls == []


# -- rules from the feedback loop apply at the MCP boundary --------------------------------------
def test_an_approved_loop_rule_blocks_at_the_mcp_boundary(gateway):
    """nova-assistant-broad may use iam_tool, so without the rule the call runs
    (control). With policies/approved_rules.yaml loaded, the rule from finding #9
    stops the same MCP tool call."""
    assert APPROVED, "policies/approved_rules.yaml has no rules, so this test would prove nothing"

    async def attempt():
        async with stack(gateway, "nova-assistant-broad") as (client, calls, _):
            return await client.call_tool("grant_scope", {"scope": "admin"}), calls

    control, control_calls = run(attempt())
    assert not control.isError and control_calls == [("grant_scope", {"scope": "admin"})]

    gateway.install_rules(APPROVED)
    result, calls = run(attempt())
    assert result.isError and calls == []
    assert APPROVED[0]["name"] in text(result)


# -- the mapping ---------------------------------------------------------------------------------
def action(tool, args, mapping=MAPPING):
    return mapping.build_action(tool, args, agent_id="a", human_id="h")


def test_mapping_builds_a_literal_action():
    a = action("send_email", {"to": "bob@example.com", "subject": "hi", "body": "text"})
    assert (a["tool_id"], a["action"], a["resource"]) == ("email_tool", "send", "email.bob@example.com")
    assert a["destination"] == "internal" and a["payload_preview"] == "hi\ntext"


@pytest.mark.parametrize("to,expected", [
    ("bob@example.com", "internal"),
    ("bob@example.com, jane@example.com", "internal"),
    ("bob@evil.com", "external_api"),
    ("jane@example.com, bob@evil.com", "external_api"),
    ("bob@evil.com, jane@example.com", "external_api"),   # an internal address last must not hide it
    (["jane@example.com", "bob@evil.com"], "external_api"),
    ("jane@sub.example.com", "external_api"),              # exact domain match only
    ("jane@example.com.evil.com", "external_api"),
    ("https://example.com/hook", "internal"),
    ("https://example.com@evil.com/hook", "external_api"),
    ("", "external_api"),
    (None, "external_api"),
    (42, "external_api"),
])
def test_destination_is_external_unless_every_address_is_internal(to, expected):
    assert action("send_email", {"to": to, "subject": "", "body": ""})["destination"] == expected


def test_unmapped_tool_gets_an_id_nobody_holds():
    a = action("shell_exec", {"cmd": "id"})
    assert a["tool_id"].startswith("mcp_unmapped.") and a["action"] == "access"
    weird = action("../../etc/passwd; rm", {})
    assert " " not in weird["tool_id"] and ";" not in weird["tool_id"]


def test_template_substitutes_plain_names_only():
    assert _render("filesystem.{path}", {"path": "a/b"}) == "filesystem.a/b"
    assert _render("x.{missing}", {}) == "x."
    assert _render("x.{path.__class__}", {"path": "a"}) == "x.{path.__class__}"
    assert _render("x.{items}", {"items": [1, 2]}) == "x.[1, 2]"


def test_record_count_from_list_or_number():
    m = Mapping.from_dict({"server": "s", "tools": {"export": {
        "tool_id": "customer_db_tool", "action": "export", "resource": "customer_db.records",
        "record_count_from": "ids"}}})
    assert action("export", {"ids": list(range(5000))}, m)["record_count"] == 5000
    assert action("export", {"ids": 7}, m)["record_count"] == 7
    assert action("export", {"ids": "lots"}, m)["record_count"] == 1
    assert action("export", {"ids": True}, m)["record_count"] == 1


@pytest.mark.parametrize("raw,fragment", [
    ({"server": "s", "tols": {}}, "unknown top-level"),
    ({"tools": {}}, "'server' is required"),
    ({"server": "bad name!", "tools": {}}, "'server'"),
    ({"server": "s", "tools": {"t": {"tool_id": "x", "action": "read", "resource": "fs.a", "acton": "x"}}}, "unknown keys"),
    ({"server": "s", "tools": {"t": {"tool_id": "x", "action": "nuke", "resource": "fs.a"}}}, "action must be one of"),
    ({"server": "s", "tools": {"t": {"tool_id": "x", "action": "read", "resource": "no-prefix"}}}, "category prefix"),
    ({"server": "s", "tools": {"t": {"tool_id": "x", "action": "read", "resource": "fs.a", "data_classification": "SECRET"}}}, "data_classification"),
    ({"server": "s", "tools": {"t": {"tool_id": "x", "action": "read", "resource": "fs.a", "destination": "d", "destination_from": "to"}}}, "not both"),
    ({"server": "s", "tools": {"t": {"tool_id": "x", "action": "read", "resource": "fs.a", "record_count": -1}}}, "record_count"),
    ({"server": "s", "tools": {"t": {"action": "read", "resource": "fs.a"}}}, "'tool_id' is required"),
])
def test_bad_mapping_is_rejected_at_load(raw, fragment):
    with pytest.raises(MappingError, match=fragment):
        Mapping.from_dict(raw)


@pytest.mark.parametrize("path", ["mapping.example.yaml", "examples/demo_mapping.yaml"])
def test_the_shipped_mappings_load(path):
    m = Mapping.load(ROOT / "mcp_proxy" / path)
    assert m.tools and m.server
