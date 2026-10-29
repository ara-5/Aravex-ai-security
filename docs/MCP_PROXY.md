# MCP proxy: the gateway in front of any MCP server

```
 MCP client / agent ──stdio──▶ aravex-mcp proxy ──stdio──▶ upstream MCP server
                                     │
                                     └─ POST /v1/agent-action ─▶ Aravex gateway ─▶ ALLOW / DENY / HUMAN_APPROVAL
```

The proxy is an MCP server that fronts another MCP server. To the client it looks
like the upstream server. `tools/list` is passed through unchanged. Every
`tools/call` is first turned into a gateway action and reaches the upstream server
only if the gateway answers `ALLOW`.

## Run it

```bash
pip install -r mcp_proxy/requirements.txt -r gateway/requirements.txt
ARAVEX_API_KEY=... python -m aravex_mcp \
    --gateway-url http://localhost:8000 --agent-id nova-assistant \
    --mapping mcp_proxy/mapping.example.yaml \
    -- <upstream server command and args>
```

Run it from `mcp_proxy/` (or put that folder on `PYTHONPATH`). In an MCP client's
config, the proxy replaces the upstream server's entry, and the real command moves
after `--`.

| Flag / variable | Meaning |
|---|---|
| `ARAVEX_API_KEY` (env only) | The agent's gateway bearer key. Never a flag, so it stays out of process listings. Required. |
| `--agent-id` | Gateway identity the proxy acts as. One proxy process is one identity. |
| `--mapping` | YAML mapping of upstream tools to gateway actions (below). |
| `--human-id` | Accountable human on the identity chain (default `h-jane-owner`). |
| `--approval-wait SECONDS` | Wait this long for a person to resolve `HUMAN_APPROVAL`. Default `0`: refuse at once. |
| `--upstream-env NAME` | Forward this environment variable to the upstream server. Repeatable. |

The upstream server gets only a small default environment plus the variables you
forward by name. It does **not** inherit `ARAVEX_API_KEY`.

## The mapping

An MCP server only says "tool X, these arguments". The gateway reasons about an
identity, a tool it is allowed to use, an action and a resource. The mapping is where
you say what each tool does. See [`mapping.example.yaml`](../mcp_proxy/mapping.example.yaml).

- It describes the call literally. The gateway's rules and permissions do the judging.
- **A tool with no entry is not skipped.** It is sent to the gateway under an id
  nobody holds (`mcp_unmapped.<server>.<tool>`), so it is refused and the refusal is
  audited. Forgetting a tool fails closed.
- Unknown keys and bad values are load-time errors, because a typo in a security
  config must not be silently ignored.
- `destination_from` marks a call `external_api` unless **every** address or URL host
  is exactly one of `internal_domains`. One external recipient among several makes
  the whole call external, and a missing value counts as external.
- `{arg}` placeholders substitute plain argument values only.

## What the agent sees, what the operator sees

A refused call returns an MCP error result:

```
[blocked by Aravex gateway] DENY: rule 'deny_secret_access': Agents may never read or export secrets/credentials through the gateway. (rules: deny_secret_access)
```

The agent gets the primary reason and the rule names. The gateway's risk-score
arithmetic stays in the proxy's stderr log, because showing it would let a probing
agent tune its attempts against the thresholds. Every decision is also in the
gateway's audit log.

## Fails closed

Only an HTTP 200 whose body says exactly `ALLOW`, for the request id that was sent,
lets a call through. These all refuse and the upstream server is never called:
gateway down or timing out, 401/403/5xx, unreadable JSON, a decision for a different
request, a lowercase or unknown decision, `DENY`, and `HUMAN_APPROVAL` (unless a
person approves within `--approval-wait`).

## Tested

`tests/mcp_proxy` (run by [MCP Proxy CI](../.github/workflows/mcp-proxy-ci.yml)) uses
the real gateway engine behind the proxy and a stand-in upstream server that records
every call it actually receives. Each refusal test asserts the upstream was not
reached, not only that the agent saw an error. A control test shows the same tools do
run when the proxy is bypassed. One test loads `policies/approved_rules.yaml` and shows
the rule from the feedback loop stopping an MCP tool call that is allowed without it.

`scripts/demo_mcp_proxy.py` repeats the check with real processes: the gateway over
HTTP and the proxy CLI over stdio. It also confirms the gateway key does not reach the
upstream process.

The tests were checked by breaking the proxy four ways (forward everything, treat
unknown decisions as allowed, skip the request-id check, judge a recipient list by its
last address). Each was caught.

## Limits

- **Only calls are gated.** The proxy sees `tools/call` requests. It does not read
  tool *descriptions* (a malicious server can plant instructions in them), and it does
  not inspect tool *results* (prompt injection or leaked data coming back). Those need
  separate checks.
- **The mapping is trusted.** If a destructive tool is mapped as `read`, the gateway
  will judge it as a read. The proxy cannot verify what a tool really does.
- **Tools only.** Only `tools/list` and `tools/call` are served. Resources, prompts and
  sampling are not proxied, so a client asking for them gets "method not found".
- **stdio only,** on both sides. No HTTP/SSE transport yet.
- **One identity per proxy process,** and no session context: each call is judged on
  its own, apart from what the gateway's anomaly tracker sees for that agent.
- **Approval waiting is only as strong as the gateway's approval endpoints, which have
  no authentication today.** Anything that can reach the gateway could approve its own
  request. That is why waiting is off by default; fix the endpoint before enabling it.
- **Not yet run against a real third-party server.** It is tested against stand-in
  servers built on the official Python SDK. The first run against, for example, the
  reference filesystem server will likely need a mapping written for its tool names.
