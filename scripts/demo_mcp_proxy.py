"""End-to-end check of the MCP proxy with real processes.

Starts the real gateway over HTTP, then drives the real `python -m aravex_mcp` over
stdio in front of mcp_proxy/examples/demo_upstream.py. It makes the same tool calls
twice: straight at the upstream server (control), then through the proxy.

    python scripts/demo_mcp_proxy.py

Exits non-zero if anything differs from the expected outcome, so it doubles as a
smoke test. Uses gateway port 8010 and a throwaway call log.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_defense import mint_key, wait_for  # noqa: E402

PORT = 8010
AGENT = "nova-assistant"
UPSTREAM = ROOT / "mcp_proxy" / "examples" / "demo_upstream.py"
MAPPING = ROOT / "mcp_proxy" / "examples" / "demo_mapping.yaml"

CALLS = [
    ("read_file", {"path": "notes/todo.txt"}, "run"),
    ("send_email", {"to": "jane@example.com", "subject": "hi", "body": "lunch?"}, "run"),
    ("get_secret", {"name": "prod_db"}, "blocked"),
    ("shell_exec", {"cmd": "cat /etc/passwd"}, "blocked"),
    ("env_probe", {}, "run"),
]


async def drive(params: StdioServerParameters) -> list[tuple[str, bool, str]]:
    out = []
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            for name, args, _ in CALLS:
                res = await session.call_tool(name, args)
                out.append((name, bool(res.isError), res.content[0].text if res.content else ""))
    return out


def reached(log: Path) -> list[str]:
    return [json.loads(line)["tool"] for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


def main() -> int:
    key = mint_key()
    gateway = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "gateway.main:app", "--port", str(PORT), "--log-level", "warning"],
        cwd=ROOT / "gateway", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failures: list[str] = []
    try:
        wait_for(f"http://127.0.0.1:{PORT}/healthz", gateway, "gateway")
        with tempfile.TemporaryDirectory() as t:
            direct_log, proxy_log = Path(t) / "direct.jsonl", Path(t) / "proxy.jsonl"

            print("Control: the same calls straight at the upstream server")
            direct = asyncio.run(drive(StdioServerParameters(
                command=sys.executable, args=[str(UPSTREAM)], env={"DEMO_CALL_LOG": str(direct_log)})))
            for name, is_err, txt in direct:
                print(f"  {name:<11} {'ERROR' if is_err else 'ok':<6} {txt[:60]}")
            if reached(direct_log) != [c[0] for c in CALLS]:
                failures.append(f"control: expected every call to run, got {reached(direct_log)}")

            print("\nThrough the Aravex MCP proxy")
            proxy = asyncio.run(drive(StdioServerParameters(
                command=sys.executable,
                args=["-m", "aravex_mcp", "--gateway-url", f"http://127.0.0.1:{PORT}", "--agent-id", AGENT,
                      "--mapping", str(MAPPING), "--upstream-env", "DEMO_CALL_LOG", "--",
                      sys.executable, str(UPSTREAM)],
                env={"ARAVEX_API_KEY": key, "DEMO_CALL_LOG": str(proxy_log)},
                cwd=str(ROOT / "mcp_proxy"))))
            for name, is_err, txt in proxy:
                print(f"  {name:<11} {'ERROR' if is_err else 'ok':<6} {txt[:100]}")

            ran = reached(proxy_log)
            for (name, _, expect), (_, is_err, txt) in zip(CALLS, proxy):
                if expect == "blocked":
                    if not (is_err and txt.startswith("[blocked by Aravex gateway]")):
                        failures.append(f"{name} should be blocked, agent saw: {txt[:80]}")
                    if name in ran:
                        failures.append(f"{name} was refused but still reached the upstream server")
                elif is_err or name not in ran:
                    failures.append(f"{name} should have run, got error={is_err}: {txt[:80]}")
            probe = next((txt for n, _, txt in proxy if n == "env_probe"), "")
            if probe != "ARAVEX_API_KEY not visible":
                failures.append(f"gateway key leaked into the upstream process: {probe!r}")
            print(f"\nReached the upstream through the proxy: {ran}")
    finally:
        gateway.terminate()
        gateway.wait(timeout=15)

    if failures:
        print("\nFAILED:\n  " + "\n  ".join(failures))
        return 1
    print("\nOK: allowed calls ran, refused calls never reached the upstream server, the key stayed out of it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
