"""aravex-mcp: run an MCP server behind the Aravex gateway.

    ARAVEX_API_KEY=... python -m aravex_mcp \\
        --gateway-url http://localhost:8000 --agent-id nova-assistant \\
        --mapping mapping.yaml -- npx -y @modelcontextprotocol/server-filesystem /work

Everything after `--` is the upstream server command. The gateway credential is
read from ARAVEX_API_KEY only (never a flag, so it stays out of process listings)
and is not passed on to the upstream server.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from aravex_mcp.gate import Gate
from aravex_mcp.mapping import Mapping, MappingError
from aravex_mcp.proxy import build_server

log = logging.getLogger("aravex_mcp")


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    split = argv.index("--") if "--" in argv else len(argv)
    p = argparse.ArgumentParser(prog="aravex-mcp", description=__doc__.split("\n\n")[0])
    p.add_argument("--gateway-url", default=os.environ.get("ARAVEX_GATEWAY_URL", "http://localhost:8000"))
    p.add_argument("--agent-id", required=True, help="gateway agent identity this proxy acts as")
    p.add_argument("--human-id", default=os.environ.get("ARAVEX_HUMAN_ID", "h-jane-owner"),
                   help="accountable human on the identity chain")
    p.add_argument("--mapping", required=True, help="YAML mapping of upstream tools to gateway actions")
    p.add_argument("--approval-wait", type=float, default=0.0, metavar="SECONDS",
                   help="wait this long for a person to resolve HUMAN_APPROVAL; 0 refuses at once (default)")
    p.add_argument("--timeout", type=float, default=10.0, help="gateway request timeout in seconds")
    p.add_argument("--upstream-env", action="append", default=[], metavar="NAME",
                   help="forward this environment variable to the upstream server (repeatable)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv[:split])  # --help and missing flags are reported before anything else
    if split == len(argv):
        raise SystemExit("aravex-mcp: give the upstream server command after '--'")
    command = argv[split + 1:]
    if not command:
        raise SystemExit("aravex-mcp: empty upstream command after '--'")
    return args, command


async def serve(args: argparse.Namespace, command: list[str], mapping: Mapping, gate: Gate) -> None:
    env = {n: os.environ[n] for n in args.upstream_env if n in os.environ}
    params = StdioServerParameters(command=command[0], args=command[1:], env=env)
    async with stdio_client(params) as (up_read, up_write):
        async with ClientSession(up_read, up_write) as upstream:
            await upstream.initialize()
            server = build_server(upstream, gate, mapping, agent_id=args.agent_id, human_id=args.human_id)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(stream=sys.stderr, format="aravex-mcp %(levelname)s %(message)s")
    args, command = parse_args(sys.argv[1:] if argv is None else argv)
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    api_key = os.environ.get("ARAVEX_API_KEY", "")
    if not api_key:
        print("aravex-mcp: ARAVEX_API_KEY is not set; the gateway would reject every call", file=sys.stderr)
        return 2
    try:
        mapping = Mapping.load(args.mapping)
    except MappingError as exc:
        print(f"aravex-mcp: {exc}", file=sys.stderr)
        return 2

    gate = Gate.for_url(args.gateway_url, api_key, timeout=args.timeout, approval_wait=args.approval_wait)
    if not gate.healthy():
        log.warning("gateway at %s is not answering; every tool call will be refused until it is", args.gateway_url)
    log.info("gating %s for agent %s through %s (%d tools mapped)",
             mapping.server, args.agent_id, args.gateway_url, len(mapping.tools))
    try:
        asyncio.run(serve(args, command, mapping, gate))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
