"""A tiny stdio MCP server used by scripts/demo_mcp_proxy.py.

Every call that actually reaches it is appended to the file named by DEMO_CALL_LOG,
so the demo can tell "the agent saw an error" apart from "the tool never ran".
"""
import json
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-upstream")


def _record(tool: str, **args) -> None:
    path = os.environ.get("DEMO_CALL_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"tool": tool, **args}) + "\n")


@mcp.tool()
def read_file(path: str) -> str:
    _record("read_file", path=path)
    return f"contents of {path}"


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    _record("send_email", to=to)
    return f"sent to {to}"


@mcp.tool()
def get_secret(name: str) -> str:
    _record("get_secret", name=name)
    return "hunter2"


@mcp.tool()
def shell_exec(cmd: str) -> str:
    _record("shell_exec", cmd=cmd)
    return "ran: " + cmd


@mcp.tool()
def env_probe() -> str:
    """Reports whether the gateway credential leaked into this process."""
    _record("env_probe")
    return "ARAVEX_API_KEY visible" if "ARAVEX_API_KEY" in os.environ else "ARAVEX_API_KEY not visible"


if __name__ == "__main__":
    mcp.run()
