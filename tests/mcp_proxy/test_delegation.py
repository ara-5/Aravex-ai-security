"""Delegation through the MCP proxy: a sub-agent's calls are limited by the token it was handed.

An orchestrator holds a broad capability and hands a narrower one to a sub-agent, which
cannot widen it. Every refusal here is checked against a positive control (the same call
works with the broader token), so a broken token cannot pass for a working restriction.
"""
from __future__ import annotations

import time

import pytest
from mcp.shared.memory import create_connected_server_and_client_session as connect

from aravex_mcp import Gate, build_server
from gateway.capabilities import attenuate, mint
from test_mcp_proxy import HUMAN, KEY, MAPPING, gateway, make_upstream, run, text  # noqa: F401  (gateway is a fixture)

ROOT = b"root-key-for-proxy-tests-0123456789"
AGENT = "nova-assistant"


def c(kind, value):
    return {"kind": kind, "value": value}


@pytest.fixture(autouse=True)
def root_key(monkeypatch):
    monkeypatch.setenv("GATEWAY_CAPABILITY_ROOT_KEY", ROOT.decode())
    monkeypatch.delenv("GATEWAY_REQUIRE_CAPABILITY", raising=False)


def orchestrator_token():
    return mint(ROOT, identifier="orchestrator", caveats=[
        c("expires", time.time() + 600), c("agent_id", AGENT),
        c("tools", ["filesystem_tool", "email_tool"])])


async def calls_with(gateway_client, token, *requests):
    upstream, calls = make_upstream()
    async with connect(upstream) as up:
        proxy = build_server(up, Gate(gateway_client, KEY, capability=token), MAPPING, agent_id=AGENT, human_id=HUMAN)
        async with connect(proxy) as client:
            results = [await client.call_tool(name, args) for name, args in requests]
    return results, calls


READ_REPORT = ("read_file", {"path": "reports/q3.txt"})
READ_SECRET = ("read_file", {"path": "private/keys.txt"})
SEND = ("send_email", {"to": "bob@example.com", "subject": "hi", "body": "report"})


def test_control_without_a_capability_everything_policy_allows_runs(gateway):
    results, calls = run(calls_with(gateway, None, READ_REPORT, READ_SECRET, SEND))
    assert [r.isError for r in results] == [False, False, False]
    assert [c_[0] for c_ in calls] == ["read_file", "read_file", "send_email"]


def test_the_orchestrator_token_covers_its_tools(gateway):
    results, calls = run(calls_with(gateway, orchestrator_token(), READ_REPORT, SEND))
    assert [r.isError for r in results] == [False, False] and len(calls) == 2


def test_a_narrowed_token_limits_the_sub_agent_and_the_tool_never_runs(gateway):
    sub_agent = attenuate(attenuate(orchestrator_token(), c("tools", ["filesystem_tool"])),
                          c("resource_prefixes", ["filesystem.reports/"]))
    results, calls = run(calls_with(gateway, sub_agent, READ_REPORT, READ_SECRET, SEND))
    report, secret, send = results
    assert not report.isError, "the narrowed token must still cover what it was given"
    assert secret.isError and "does not cover this resource" in text(secret)
    assert send.isError and "does not cover tool" in text(send)
    assert calls == [("read_file", {"path": "reports/q3.txt"})], "refused calls must not reach the upstream server"


def test_a_sub_agent_cannot_widen_what_it_was_given(gateway):
    narrow = attenuate(orchestrator_token(), c("tools", ["filesystem_tool"]))
    greedy = attenuate(narrow, c("tools", ["filesystem_tool", "email_tool", "secrets_tool"]))
    results, calls = run(calls_with(gateway, greedy, READ_REPORT, SEND))
    assert not results[0].isError and results[1].isError
    assert [c_[0] for c_ in calls] == ["read_file"]


@pytest.mark.parametrize("make,fragment", [
    (lambda: mint(ROOT, identifier="x", caveats=[c("expires", time.time() - 5)]), "expired"),
    (lambda: mint(b"another-root-key-0123456789", identifier="x", caveats=[c("expires", time.time() + 600)]), "signature"),
    (lambda: orchestrator_token()[:-4] + "AAAA", "capability"),
])
def test_a_bad_or_expired_token_blocks_every_call(gateway, make, fragment):
    results, calls = run(calls_with(gateway, make(), READ_REPORT))
    assert results[0].isError and fragment in text(results[0]) and calls == []
