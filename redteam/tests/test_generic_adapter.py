"""
Proves the pluggable-target-adapter story is real: GenericChatAdapter
talks to the target agent over a REAL HTTP server (not the in-process
ASGI shortcut the other tests use) using nothing but its /chat endpoint,
as if it were a completely unrelated third-party agent. No AttackFamily
code changes; techniques needing introspection just correctly report
"not observable" instead of crashing.
"""
import socket
import threading
import time

import httpx
import uvicorn

import target_agent.main as target_main
from redteam_engine.adapters.generic_chat_adapter import GenericChatAdapter
from redteam_engine.attacks import FAMILY_BY_CATEGORY
from redteam_engine.attacks.base import AttackContext


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_server_in_background(app, port: int) -> uvicorn.Server:
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server


def test_generic_adapter_over_real_http():
    port = _free_port()
    server = _run_server_in_background(target_main.app, port)
    base = f"http://127.0.0.1:{port}"
    try:
        # Reset via the reference target's own admin route (allowed here
        # because we happen to own it for this test setup) -- the
        # adapter under test never uses it.
        httpx.post(f"{base}/admin/reset", timeout=10.0)

        adapter = GenericChatAdapter(
            chat_url=f"{base}/chat",
            known_secrets={"CANARY_API_KEY": "sk-canary-7f3a9c2e1b4d"},
            health_url=f"{base}/health",
        )
        assert adapter.health()

        # System-prompt extraction needs only response text -- works
        # unmodified against a black-box adapter.
        family = FAMILY_BY_CATEGORY["system_prompt_extraction"]
        ctx = AttackContext(client=adapter, canaries=adapter.get_canaries(), campaign_session_prefix="generic")
        seed = family.seeds(ctx)[0]
        response = family.execute(seed, "generic-session-1", ctx)
        target_state = adapter.get_state("generic-session-1")
        result = family.judge(seed, "generic-session-1", response, target_state, ctx)
        assert result.success, "system-prompt extraction should still be provable via response text alone"

        # MCP attacks need get_state() introspection the generic adapter
        # can't provide -- must degrade to "not observable", not crash.
        mcp_family = FAMILY_BY_CATEGORY["mcp_attacks"]
        mcp_seed = mcp_family.seeds(ctx)[0]
        mcp_response = mcp_family.execute(mcp_seed, "generic-session-2", ctx)
        mcp_state = adapter.get_state("generic-session-2")
        mcp_result = mcp_family.judge(mcp_seed, "generic-session-2", mcp_response, mcp_state, ctx)
        assert mcp_result.success is False
        assert mcp_state == {}
    finally:
        server.should_exit = True
        time.sleep(0.2)
