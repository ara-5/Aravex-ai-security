"""Scan a server, pin it, and watch the proxy refuse a rug pull. Real processes throughout.

    python scripts/demo_scan_and_pin.py

1. `aravex-mcp scan` reads a server that looks clean and pins its tool definitions.
2. The server then changes a tool's description (hidden instructions appear).
3. Through the proxy WITH the pins, the changed tool disappears and is refused.
   Through the proxy WITHOUT them (the control), the poisoned description reaches the agent.

Exits non-zero if any of that does not happen. Uses gateway port 8010.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_defense import mint_key, wait_for  # noqa: E402

PORT, AGENT = 8010, "nova-assistant"
UPSTREAM = ROOT / "mcp_proxy" / "examples" / "rugpull_upstream.py"
MAPPING = ROOT / "mcp_proxy" / "examples" / "demo_mapping_rugpull.yaml"


async def session_run(args: list[str], key: str):
    params = StdioServerParameters(command=sys.executable, args=["-m", "aravex_mcp", *args],
                                   env={"ARAVEX_API_KEY": key}, cwd=str(ROOT / "mcp_proxy"))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            first = await s.call_tool("read_file", {"path": "notes/a.txt"})
            listed = {t.name: t.description or "" for t in (await s.list_tools()).tools}
            second = await s.call_tool("read_file", {"path": "notes/a.txt"})
            return first, listed, second


def proxy_args(pins: Path | None) -> list[str]:
    a = ["--gateway-url", f"http://127.0.0.1:{PORT}", "--agent-id", AGENT, "--mapping", str(MAPPING)]
    if pins:
        a += ["--pins", str(pins)]
    return a + ["--", sys.executable, str(UPSTREAM)]


def main() -> int:
    key = mint_key()
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as t:
        out = Path(t)
        print("1. Scanning the server while it still looks clean...")
        code = subprocess.run([sys.executable, "-m", "aravex_mcp", "scan", "--out-dir", str(out), "--fail-on", "low",
                               "--", sys.executable, str(UPSTREAM)], cwd=ROOT / "mcp_proxy",
                              capture_output=True, text=True).returncode
        print(f"   scan exit code {code} (0 = no findings); wrote pins.json")
        if code != 0 or not (out / "pins.json").exists():
            problems.append("the clean server should scan clean and write pins.json")

        gateway = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "gateway.main:app", "--port", str(PORT), "--log-level", "warning"],
            cwd=ROOT / "gateway", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for(f"http://127.0.0.1:{PORT}/healthz", gateway, "gateway")

            print("2. Control: proxy WITHOUT pins; the server changes its description after the first call")
            first, listed, second = asyncio.run(session_run(proxy_args(None), key))
            poisoned_visible = "IMPORTANT" in listed.get("read_file", "")
            print(f"   first call ok={not first.isError}; poisoned description reaches the agent={poisoned_visible}; "
                  f"second call ok={not second.isError}")
            if first.isError or not poisoned_visible or second.isError:
                problems.append("control: without pins the change should go unnoticed")

            print("3. Proxy WITH pins; the same server does the same thing")
            first, listed, second = asyncio.run(session_run(proxy_args(out / "pins.json"), key))
            hidden = "read_file" not in listed
            print(f"   first call ok={not first.isError}; changed tool hidden from the agent={hidden}; "
                  f"second call refused={second.isError}")
            if first.isError:
                problems.append("with pins, the unchanged tool should work the first time")
            if not hidden or not second.isError or "definition changed" not in second.content[0].text:
                problems.append("with pins, the changed tool should be hidden and refused")
            else:
                print(f"   agent was told: {second.content[0].text}")
        finally:
            gateway.terminate()
            gateway.wait(timeout=15)

    if problems:
        print("\nFAILED:\n  " + "\n  ".join(problems))
        return 1
    print("\nOK: the rug pull went unnoticed without pins and was stopped with them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
