# AegisAI Architecture

## The question this project answers

Not "can I stop a prompt injection" but: **if an agent is already compromised
-- jailbroken, fed a malicious tool result, or simply buggy -- can it still
do damage?** AegisAI's answer is to never let the agent's own judgment be the
last line of defense. Every action it wants to take is re-checked, from
scratch, against an external policy engine that the agent cannot see or
influence.

## Request flow

```
USER
  |
  v
AI Gateway  (gateway/main.py -- FastAPI, the only network-reachable service)
  |
  v
Security Policy Engine  (gateway/policy/engine.py)
  |  1. resolve identity chain (Human -> Agent -> Tool)
  |  2. evaluate declarative rules (gateway/policy/rules.yaml) -- hard guardrails
  |  3. check IAM permission grant (gateway/identity/agents.yaml)
  |  4. run DLP / prompt-injection / anomaly detectors
  |  5. compute composite risk score, threshold into a decision
  v
ALLOW / DENY / HUMAN_APPROVAL
  |
  v
AI Agent  (agent/demo_agent.py)  -- only executes the tool call on ALLOW
  |
  +--> RAG / customer_db
  +--> Tools / email, payments
  +--> MCP / external APIs
```

Nothing after the gateway is trusted implicitly. The agent process itself
holds no standing credentials to the database, email provider, or payments
system -- it can only ask the gateway, and the gateway decides.

## Identity chain (Agent IAM)

```
Human (h-jane-owner)
  -> Agent Identity (customer-support-agent)
       -> Tool Identity (customer_db_tool, email_tool)
            -> Resource (customer_db.profile, email.send)
```

Every `ActionRequest` carries all four links. The registry
(`gateway/identity/registry.py`, backed by `gateway/identity/agents.yaml`)
resolves each one and rejects the request outright if the agent is unknown
or the tool isn't in that agent's `allowed_tools` list -- before any policy
or risk logic even runs.

Permissions are scoped per resource category, not "the agent can use this
tool":

```yaml
agent: customer-support-agent
permissions:
  customer_db: { read: true, write: false, export: false }
  email:       { send: true }
  payments:    { read: false, write: false }
  filesystem:  { access: false }
```

A compromised customer-support-agent cannot escalate into writing the
customer DB or touching payments no matter what it's told to do -- the grant
simply isn't there.

## Policy engine

Two layers, evaluated in order:

1. **Declarative rules** (`gateway/policy/rules.yaml`) -- explicit,
   auditable, first-match-wins guardrails such as "never allow secret
   access" or "production deletes require a human." These override
   everything else.
2. **Risk-score fallback** (`gateway/policy/risk.py`) -- for everything not
   already covered by a hard rule, a weighted score combines action
   severity, data classification, record volume, destination, and live
   security findings (DLP hits, prompt-injection indicators, behavioral
   anomalies) into a single 0-1 score, thresholded into ALLOW (<0.4),
   HUMAN_APPROVAL (0.4-0.75), or DENY (>=0.75).

Every decision returns a full reasoning trail (`reasons`, `matched_rules`,
`findings`) -- nothing is a black box.

## Runtime security detectors (`gateway/security/`)

- `dlp.py` -- regex-based scan for secrets, API keys, credit cards, SSNs in
  any payload the agent is about to move.
- `prompt_injection.py` -- heuristic pattern matching for jailbreak/override
  markers in tool inputs or retrieved content.
- `anomaly.py` -- sliding-window tracker per agent for excessive call rate
  and repeated failed authorization (both classic exfiltration/probing
  signals).

These feed the risk score; they are signals, not the enforcement mechanism
itself -- the IAM permission check and declarative rules are what actually
gate access.

## Human-in-the-loop approvals

A `HUMAN_APPROVAL` decision does not execute anything. It's parked in
`gateway/approvals/manager.py` as a pending record; the action only runs
after an authorized human calls `POST /v1/approvals/{id}/decision`. The
gateway enforces this by construction -- the demo agent only invokes the
tool on an `ALLOW` response, never on `HUMAN_APPROVAL`.

## Observability

- **Structured audit log** (`gateway/audit/logger.py`) -- every decision is
  one JSON line in `logs/audit.log`, with `DENY`s driven by a security rule
  or high risk score tagged `security_alert`. Point a SIEM's log shipper at
  this file (or swap the handler for syslog/HTTP) and you have alerting
  with no extra glue code.
- **OpenTelemetry** (`gateway/telemetry/otel.py`) -- every gateway request
  is a span carrying the identity chain and decision as attributes.
  Defaults to console export; set `OTEL_EXPORTER_OTLP_ENDPOINT` to ship to
  Jaeger/Tempo/etc.
- **Prometheus** (`gateway/telemetry/metrics.py`, served at `/metrics`) --
  request counts by decision, rule-match counts, risk-score distribution,
  security-finding counts, pending-approval gauge. `docker-compose.yml`
  wires up Prometheus + Grafana to scrape and visualize it.

## Why this is a deeper problem than prompt filtering

A prompt-injection filter tries to stop the *input* from corrupting the
agent's behavior. AegisAI assumes that will sometimes fail and asks a
different question at the *output* side: even if the agent's behavior is
fully corrupted, is there still a hard boundary -- identity, permission,
declarative policy, human sign-off -- that keeps it from causing damage?
That's Agent IAM and zero-trust, not content filtering.
