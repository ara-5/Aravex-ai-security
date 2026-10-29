# aravex-mcp

Puts the Aravex gateway in front of a stdio MCP server: every tool call is checked
first and reaches the server only if the gateway allows it.

```bash
pip install ./mcp_proxy
ARAVEX_API_KEY=... aravex-mcp --gateway-url http://localhost:8000 \
    --agent-id nova-assistant --mapping mapping.example.yaml -- <upstream server command>
```

Full documentation, the mapping format and the limits are in
[docs/MCP_PROXY.md](../docs/MCP_PROXY.md). Proprietary; all rights reserved.
