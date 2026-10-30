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
pip install ./mcp_proxy          # installs the `aravex-mcp` command
ARAVEX_API_KEY=... aravex-mcp \
    --gateway-url http://localhost:8000 --agent-id nova-assistant \
    --mapping mcp_proxy/mapping.example.yaml \
    -- <upstream server command and args>
```

The package is marked "Private :: Do Not Upload", so `twine upload` refuses it. In an
MCP client's config, the proxy replaces the upstream server's entry, and the real
command moves after `--`. From a source checkout without installing, run
`python -m aravex_mcp ...` from inside `mcp_proxy/`.

| Flag / variable | Meaning |
|---|---|
| `ARAVEX_API_KEY` (env only) | The agent's gateway bearer key. Never a flag, so it stays out of process listings. Required. |
| `--agent-id` | Gateway identity the proxy acts as. One proxy process is one identity. |
| `--mapping` | YAML mapping of upstream tools to gateway actions (below). |
| `--human-id` | Accountable human on the identity chain (default `h-jane-owner`). |
| `--approval-wait SECONDS` | Wait this long for a person to resolve `HUMAN_APPROVAL`. Default `0`: refuse at once. |
| `--pins FILE` | `pins.json` from `aravex-mcp scan`. Tools that were not pinned, or whose definition changed since, are hidden and refused. |
| `--upstream-env NAME` | Forward this environment variable to the upstream server. Repeatable. |

The upstream server gets only a small default environment plus the variables you
forward by name. It does **not** inherit `ARAVEX_API_KEY`.

## Scan a server before you trust it

```bash
aravex-mcp scan --out-dir aravex-scan -- <server command and args>
```

Connects to the server, reads its tool list, and writes three files. No model, no network:

| File | What it is |
|---|---|
| `report.md` | Each tool with what it appears to do (read/write/send/delete on files, email, secrets...), a risk rating, and findings. |
| `mapping.suggested.yaml` | A starting point for the mapping below, guessed from tool names and parameters. Review every entry. Tools it cannot classify, and tools with a high-severity finding, are left out, so the proxy refuses them until a person decides. |
| `pins.json` | A fingerprint (hash of name, description and input schema) of every tool. |

It looks for the patterns used in tool-poisoning attacks: hidden `<IMPORTANT>`-style
instruction blocks, "don't tell the user", "ignore previous instructions", invisible
characters, credential or key-file references combined with an instruction to move data,
descriptions that steer the model to another tool, outbound-URL instructions, and
parameters that invite the agent to pass file or conversation contents. A description
flagged as hostile is not allowed to decide what the tool is classified as.
`--fail-on high` makes the command exit 1 on a finding, so it can gate CI. Ordinary tool
descriptions (file, email, calendar, SQL) produce no findings in the tests.

**Pinning.** Run the proxy with `--pins pins.json` and a server cannot swap in a poisoned
description after you reviewed it (a "rug pull"). The proxy checks the server's *current*
definition on every call and hides and refuses any tool that is new or changed.
`scripts/demo_scan_and_pin.py` runs this with real processes: a server passes the scan,
then alters a description; without pins the poisoned text reaches the agent, with pins the
tool disappears and the call is refused.

This is a static, heuristic check. It will miss poison it has no pattern for and may flag
innocent text. A clean scan is not proof a server is safe, and a finding is a reason to
read the description, not proof of an attack.

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

- **Calls and definitions are gated, results are not.** The proxy gates `tools/call`
  requests, and with `--pins` it refuses tools whose definition changed. It does not
  inspect tool *results* (prompt injection or leaked data coming back). The first scan
  of a server also relies on heuristics, so a description poisoned in a way no pattern
  covers will be pinned as-is.
- **The mapping is trusted.** If a destructive tool is mapped as `read`, the gateway
  will judge it as a read. The proxy cannot verify what a tool really does.
- **Tools only.** Only `tools/list` and `tools/call` are served. Resources, prompts and
  sampling are not proxied, so a client asking for them gets "method not found".
- **stdio only,** on both sides. No HTTP/SSE transport yet.
- **One identity per proxy process,** and no session context: each call is judged on
  its own, apart from what the gateway's anomaly tracker sees for that agent.
- **Approval waiting depends on approver keys staying with people.** The gateway
  now requires an approver key (`GATEWAY_APPROVER_KEYS`, one per person) to list or
  resolve approvals, and the proxy only
  polls with the agent's own key, which can read that agent's approval status and
  nothing more. If the approver key is set on the agent's machine, the protection is
  gone. Waiting is still off by default.
- **Not yet run against a real third-party server.** It is tested against stand-in
  servers built on the official Python SDK. The first run against, for example, the
  reference filesystem server will likely need a mapping written for its tool names.
