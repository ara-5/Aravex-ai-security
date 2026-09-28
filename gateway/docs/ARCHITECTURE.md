# AegisAI Architecture

## The question this project answers

Not "can I stop a prompt injection" but: **if an agent is already compromised
-- jailbroken, fed a malicious tool result, or simply buggy -- can it still
do damage?** AegisAI's answer is to never let the agent's own judgment be the
last line of defense. Every action it wants to take is re-checked, from
scratch, against an external policy engine that the agent cannot see or
influence -- and it has to prove who it is before any of that even starts.

## Request flow

```mermaid
sequenceDiagram
    participant U as User
    participant A as AI Agent
    participant GW as AI Gateway
    participant PE as Policy Engine
    participant T as Tool / RAG / MCP

    U->>A: instruction
    A->>GW: POST /v1/agent-action<br/>Authorization: Bearer <agent key>
    GW->>GW: authenticate_agent()<br/>(AuthN -- is this really the agent?)
    alt bad or missing credential
        GW--)A: 401 Unauthenticated
    else credential verified
        GW->>PE: evaluate(request)
        PE->>PE: 1. resolve identity chain
        PE->>PE: 2. declarative rules (rules.yaml)
        PE->>PE: 3. IAM permission check
        PE->>PE: 4. DLP / injection / anomaly scan
        PE->>PE: 5. composite risk score
        PE--)GW: ALLOW / DENY / HUMAN_APPROVAL
        GW--)A: decision + reasoning trail
        alt ALLOW
            A->>T: execute tool call
        else HUMAN_APPROVAL
            A->>A: parked, not executed
        else DENY
            A->>A: blocked, not executed
        end
    end
```

Nothing after the gateway is trusted implicitly. The agent process itself
holds no standing credentials to the database, email provider, or payments
system -- it can only ask the gateway, and the gateway decides.

## Identity chain (Agent IAM)

```mermaid
flowchart LR
    H["Human\nh-jane-owner"] --> AG["Agent Identity\ncustomer-support-agent"]
    AG --> TL["Tool Identity\ncustomer_db_tool, email_tool"]
    TL --> R["Resource\ncustomer_db.profile, email.send"]
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

## Authentication vs. authorization

These are deliberately two separate layers, because conflating them is the
gap that makes an IAM system decorative:

- **AuthN** (`gateway/identity/credentials.py`, enforced in
  `gateway/main.py`'s `authenticate_agent` dependency) -- proves the caller
  actually *is* the `agent_id` it claims to be, via a bearer credential
  whose SHA-256 hash the gateway holds. This runs first, before the request
  body is handed to anything else. No credentials configured -> every
  request is rejected (fail closed).
- **AuthZ** (the policy engine, described below) -- once identity is
  proven, decides what that specific, verified agent is allowed to do.

Without the first layer, `agent_id` in a request body is just an unverified
string -- anything on the network could claim to be `data-ops-agent` and
inherit its permissions. A failed authentication attempt is itself a
security signal: it's logged as a `security_alert` and counted by the same
anomaly tracker that watches for repeated policy denials, so credential
spraying against a known agent ID shows up as `repeated_failed_authorization`
just like probing for a permission it doesn't have.

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
  and repeated failures (denied policy checks *and* failed authentication --
  both classic exfiltration/probing signals).

These feed the risk score; they are signals, not the enforcement mechanism
itself -- verified identity, the IAM permission check, and declarative rules
are what actually gate access.

## Human-in-the-loop approvals

A `HUMAN_APPROVAL` decision does not execute anything. It's parked in
`gateway/approvals/manager.py` as a pending record; the action only runs
after an authorized human calls `POST /v1/approvals/{id}/decision`. The
gateway enforces this by construction -- the demo agent only invokes the
tool on an `ALLOW` response, never on `HUMAN_APPROVAL`.

## Observability

- **Structured audit log** (`gateway/audit/logger.py`) -- every decision is
  one JSON line in `logs/audit.log`, with `DENY`s driven by a security rule
  or high risk score (and every authentication failure) tagged
  `security_alert`. Point a SIEM's log shipper at this file (or swap the
  handler for syslog/HTTP) and you have alerting with no extra glue code.
- **OpenTelemetry** (`gateway/telemetry/otel.py`) -- every gateway request
  is a span carrying the identity chain and decision as attributes.
  Defaults to console export; set `OTEL_EXPORTER_OTLP_ENDPOINT` to ship to
  Jaeger/Tempo/etc.
- **Prometheus** (`gateway/telemetry/metrics.py`, served at `/metrics`) --
  request counts by decision, rule-match counts, risk-score distribution,
  security-finding counts, pending-approval gauge. `docker-compose.yml`
  wires up Prometheus to scrape it and Grafana to visualize it, with the
  data source and an overview dashboard auto-provisioned from
  `grafana/provisioning/` and `grafana/dashboards/` -- no manual setup.

## Why this is a deeper problem than prompt filtering

A prompt-injection filter tries to stop the *input* from corrupting the
agent's behavior. AegisAI assumes that will sometimes fail and asks a
different question at the *output* side: even if the agent's behavior is
fully corrupted, is there still a hard boundary -- verified identity,
permission, declarative policy, human sign-off -- that keeps it from
causing damage? That's Agent IAM and zero-trust, not content filtering.

## Roadmap / Future-Proofing

What's here is deliberately a working, testable core, not a finished
product. Ranked roughly by how much it would change the story if you
picked one to build next:

### Identity & auth
- **SPIFFE/SPIRE workload identity** instead of static bearer-key hashes --
  short-lived, automatically-rotated X.509 SVIDs per agent process, the
  standard primitive for zero-trust service-to-service auth. This is the
  single highest-leverage upgrade: it turns "a secret the agent holds" into
  "a cryptographic identity the platform issues and revokes."
- Watch the **emerging "agent identity" standards** space -- it's forming
  right now: Microsoft Entra Agent ID, Okta/Auth0 cross-app access for
  GenAI, the IETF WIMSE (Workload Identity in Multi-System Environments)
  draft. Being able to say "this maps to WIMSE" is a strong signal you
  understand where the industry is headed, not just where it is.
- mTLS between the agent runtime and the gateway as a lower-effort
  intermediate step before a full workload-identity system.

### Policy engine
- **Open Policy Agent (OPA) / Rego**, or **AWS Cedar**, or **Oso**, in
  place of the hand-rolled YAML rule DSL. All three are purpose-built,
  battle-tested policy languages with unit-testing tooling, a conformance
  suite, and (for Rego) a WASM compile target -- meaning the same policy
  bundle could run centrally in the gateway *and* as a low-latency local
  pre-check embedded in the agent runtime, with the gateway as the
  authoritative fallback. This is the same edge+central pattern Envoy +
  OPA uses in a service mesh.

### Protocol-level integration
- Wrap **real MCP (Model Context Protocol) servers** so the gateway
  intercepts actual MCP tool-call requests/responses instead of the
  simulated `agent/tools/`. Makes the demo map 1:1 onto how agents built on
  Claude (or anything else speaking MCP) actually call tools today.
- Front a real agent runtime -- Anthropic's Agent SDK / Tool Runner,
  LangGraph, CrewAI -- instead of the toy `AegisAgent` class, with AegisAI
  as the tool-call middleware every framework already has a hook for.

### Detection quality
- Regex DLP/prompt-injection are an honest v1 signal, not the enforcement
  mechanism -- but they're easy to evade by anyone who knows the patterns.
  Natural upgrades: **Microsoft Presidio** for proper NER-based PII/DLP
  detection, or an **LLM-as-judge** pattern (a small, fast model classifies
  payload risk) behind the same `scan(text) -> (hits, score)` contract, or
  a guardrails framework (NeMo Guardrails, Llama Guard).

### State, scale, and durability
- Redis for the `AnomalyTracker` and `ApprovalManager` once the gateway
  runs as more than one replica -- both are in-memory singletons today,
  correct for a single instance, wrong for a fleet.
- Postgres for a durable, queryable audit trail (dual-written alongside the
  JSON log) so approvals and analytics don't depend on tailing a file.
- An event bus (Kafka/NATS) publishing every decision, so a SIEM, an
  analytics pipeline, and a live dashboard all subscribe independently
  instead of each tailing the same log.

### Defense in depth beyond the decision
- Execute tool calls that get an `ALLOW` inside an isolated sandbox
  (gVisor, Firecracker microVMs, or WASM) so a bug in a tool's own
  implementation can't itself become an escalation path -- the gateway's
  decision shouldn't be the only thing standing between an agent and
  damage.
- eBPF-based runtime monitoring (e.g., Falco) as an OS-level layer beneath
  the application-level gateway, for the case where an agent gets to
  execute code directly rather than going through a tool call.

### Standards alignment
- Map AegisAI's controls against the **OWASP Agentic AI / LLM Top 10**
  (excessive agency, tool poisoning, insecure output handling, etc.) and
  the **NIST AI RMF**. A short compliance-mapping doc is cheap to write and
  signals you're building against a known threat model, not just intuition.

None of this changes what's already here -- the current gateway, tests, and
demo stand on their own. This section is a map of what "production-hardened"
would look like next, roughly in the order it would change the project's
story.
