# AegisAI -- Runtime Security Gateway for Autonomous AI Agents

[![CI](https://github.com/ara-5/AI-Runtime-Security-Zero-Trust-Agent-Platform/actions/workflows/ci.yml/badge.svg)](https://github.com/ara-5/AI-Runtime-Security-Zero-Trust-Agent-Platform/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](requirements.txt)
[![OPA](https://img.shields.io/badge/policy--engine-OPA%2FRego-7d9fff.svg)](gateway/policy/rego/guardrails.rego)
[![Docker Compose](https://img.shields.io/badge/docker--compose-ready-2496ED.svg)](docker-compose.yml)

A zero-trust security layer that sits between AI agents and everything they
can touch (databases, tools, external APIs), so that a compromised or
misbehaving agent is still bounded by verified identity, IAM permissions,
declarative policy, risk scoring, and human sign-off -- not by its own
judgment.

**The question this answers:** *"Can I prevent a compromised AI agent from
doing damage?"* See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the
full design writeup.

```mermaid
flowchart LR
    U[User] --> A[AI Agent]
    A -- "1 . authenticate\n(bearer credential)" --> GW[AI Gateway]
    GW -- "2 . authorize" --> PE[Security Policy Engine]
    PE -- rules.yaml --> PE
    PE -- risk score --> PE
    PE --> D{ALLOW / DENY /\nHUMAN_APPROVAL}
    D -- ALLOW --> A
    D -- HUMAN_APPROVAL --> H[Human approver]
    H -- resolves --> D
    A -- "only on ALLOW" --> RAG[(RAG / DB)]
    A -- "only on ALLOW" --> T[Tools]
    A -- "only on ALLOW" --> MCP[External APIs / MCP]

    style D fill:#f8b400,stroke:#333,color:#000
```

For every action: **who's calling** (verified, not claimed)? Which agent?
What permissions? What resource? What data? What's the risk? -> **ALLOW /
DENY / HUMAN_APPROVAL**.

**Contents:** [Screenshots](#screenshots) &middot;
[What's here](#whats-here) &middot;
[Two ways to run it](#two-ways-to-run-it) &middot;
[Quickstart](#quickstart) &middot;
[Full stack](#run-the-full-stack-gateway--opa--redis--postgres--prometheus--grafana) &middot;
[Tests](#tests) &middot;
[Performance](#performance) &middot;
[Try your own policy](#try-your-own-policy) &middot;
[Extending toward production](#extending-toward-production) &middot;
[Architecture](docs/ARCHITECTURE.md) &middot;
[Compliance mapping](docs/COMPLIANCE_MAPPING.md)

## Screenshots

**`scripts/demo.py` against a live gateway** -- every scenario from the design brief, decided in real time: ALLOW, DENY, a HUMAN_APPROVAL that gets resolved mid-run, a prompt-injection payload raising the risk score, an anomaly-triggered escalation, and a forged credential rejected before policy evaluation ever runs. This is the real captured output of a real run, not a mockup:

![Terminal recording of scripts/demo.py running against the live AegisAI gateway, showing ALLOW, DENY, HUMAN_APPROVAL, and UNAUTHENTICATED decisions with full reasoning traces](docs/screenshots/demo-terminal.gif)

**The auto-provisioned Grafana dashboard**, live against real traffic -- request volume, ALLOW/DENY/HUMAN_APPROVAL split, deny rate, average risk score, security findings by category, which policy rules fired, and per-agent breakdown, all populated with zero manual dashboard setup. Captured as an actual screen recording while traffic was flowing, not staged:

![Animated capture of the AegisAI Grafana dashboard updating live as request volume, decision split, risk score, security findings, and policy rule matches all climb in real time](docs/screenshots/grafana-dashboard.gif)

**The gateway's API surface** (FastAPI's auto-generated docs at `/docs`) -- the agent-action endpoint, the human-approval queue endpoints, and the full request/response schema, generated directly from the Pydantic models in `gateway/models.py`, never hand-written or allowed to drift from the code:

![AegisAI Gateway OpenAPI docs listing the /v1/agent-action, /v1/approvals, and /healthz endpoints with their schemas](docs/screenshots/api-docs.png)

## What's here

- **Agent authentication** (`gateway/identity/credentials.py`) -- every
  agent holds a bearer secret; the gateway verifies it before any policy
  logic runs. Fails closed: no credentials configured means every request
  is rejected.
- **Agent IAM** (`gateway/identity/`) -- Human -> Agent -> Tool identity
  chain with per-resource permission grants (`agents.yaml`).
- **Security Policy Engine** (`gateway/policy/`) -- real policy-as-code:
  declarative guardrails as Rego, evaluated by a live **OPA** server
  (`gateway/policy/rego/`, independently testable with `opa test`), plus a
  composite risk-scoring fallback. No OPA running? It falls back to an
  equivalent local YAML rule matcher automatically -- see
  [Two ways to run it](#two-ways-to-run-it) below.
- **Runtime detectors** (`gateway/security/`) -- DLP, prompt-injection
  heuristics, behavioral anomaly detection (call-rate, repeated denials --
  including repeated *authentication* failures).
- **Human-approval workflow** (`gateway/approvals/`) -- `HUMAN_APPROVAL`
  actions are parked, not executed, until a human resolves them.
- **Shared, multi-instance-safe state** -- the anomaly tracker and approval
  queue are backed by **Redis** when `REDIS_URL` is set (in-memory
  otherwise), so a fleet of gateway replicas shares one view of both.
- **Durable, queryable audit trail** -- every decision is dual-written to
  **Postgres** when `DATABASE_URL` is set, alongside the JSON log that stays
  the audit-of-record.
- **Observability** (`gateway/audit/`, `gateway/telemetry/`) -- structured
  JSON audit log (SIEM-ready), OpenTelemetry tracing, Prometheus metrics,
  an auto-provisioned Grafana dashboard.
- **AI Gateway** (`gateway/main.py`) -- the FastAPI service everything above
  is wired into.
- **Demo agent + tools** (`agent/`) -- a small agent runtime that calls the
  gateway before ever touching a (simulated) tool.
- **[Compliance mapping](docs/COMPLIANCE_MAPPING.md)** against the OWASP
  LLM Top 10 and NIST AI RMF -- including an honest list of what's *not*
  covered.

## Two ways to run it

**Zero-infrastructure** -- `uvicorn` alone. Declarative rules run through
the local YAML matcher, anomaly/approval state is in-memory, and the audit
trail is just the JSON log. This is the fastest path and what the Quickstart
below uses.

**Production-shaped** -- `docker compose up` (further down). The exact same
code path now runs against a real OPA server, shared Redis state, and a
durable Postgres audit trail, because the gateway detects `OPA_URL` /
`REDIS_URL` / `DATABASE_URL` and switches backends automatically -- no code
or config changes, no separate branch. That switch is itself the point: the
simple path and the production path are provably the same system, not two
different demos.

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# once, mints a bearer credential per registered agent
python scripts\generate_agent_keys.py

# terminal 1
uvicorn gateway.main:app --reload

# terminal 2
python scripts\demo.py
```

The demo walks through every scenario from the design brief against the
live gateway:

| # | Action | Expected decision |
|---|--------|--------------------|
| 1 | customer-support-agent reads a customer profile | ALLOW |
| 2 | customer-support-agent sends an email | ALLOW |
| 3 | customer-support-agent exports 50,000 records | DENY (bulk-export rule) |
| 4 | customer-support-agent reads `secrets.api_key` | DENY (secret-access rule) |
| 5 | data-ops-agent deletes the production database | HUMAN_APPROVAL -> then approved |
| 6 | (bonus) prompt-injection payload in a tool input | risk score spikes, findings logged |
| 7 | (bonus) 26 rapid calls from one agent | anomaly detector flags excessive call rate |
| 8 | (bonus) caller claims to be data-ops-agent with a forged key | 401, rejected before policy even runs |

Then check:
- `logs/audit.log` -- every decision as a structured JSON line
- `http://127.0.0.1:8000/metrics` -- Prometheus metrics
- `http://127.0.0.1:8000/v1/approvals` -- pending human-approval queue
- `http://127.0.0.1:8000/v1/agents` -- the registered agent identities and their permissions

## Run the full stack (gateway + OPA + Redis + Postgres + Prometheus + Grafana)

```bash
python scripts/generate_agent_keys.py   # required before first `up`
docker compose up --build
```

Six services come up: the gateway; a real **OPA** server loaded with
`gateway/policy/rego/guardrails.rego`; **Redis** for shared anomaly/approval
state; **Postgres** for the durable audit trail; **Prometheus**; and
**Grafana**. The gateway's env (`OPA_URL`, `REDIS_URL`, `DATABASE_URL`) is
already wired to all three in `docker-compose.yml`.

- Gateway: http://localhost:8000
- OPA: http://localhost:8181 -- query it directly, e.g.
  `curl -X POST localhost:8181/v1/data/aegisai/guardrails/result -d '{"input": {...}}'`
- Postgres: `localhost:5432` (`aegisai`/`aegisai`) -- `SELECT decision, count(*) FROM decisions GROUP BY decision;`
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 -- the Prometheus data source and the
  **AegisAI — Zero-Trust Gateway Overview** dashboard are both auto-provisioned
  (`grafana/provisioning/`, `grafana/dashboards/`), so it's populated on first
  load with no manual setup: request volume and deny rate, ALLOW/DENY/HUMAN_APPROVAL
  split, average risk score, security findings by category, policy rule matches,
  and pending approvals. Anonymous viewer access is enabled for the demo; log in
  as admin/admin to edit.

  Run `python scripts\demo.py` (or hit the gateway however you like) while the
  stack is up and the dashboard fills in live. Decisions in this mode carry a
  `[opa]` prefix in their `reasons`, confirming OPA -- not the local fallback
  -- made the call.

## Tests

```bash
pytest
```

24 tests always run (policy engine, risk scoring, HTTP layer including
authentication -- all against the zero-infrastructure fallback paths, no
external services needed). 11 more are live integration tests against OPA,
Redis, and Postgres, and skip automatically unless `OPA_URL` / `REDIS_URL`
/ `DATABASE_URL` are set:

```bash
# with the docker-compose stack (or standalone containers) running:
OPA_URL=http://localhost:8181 REDIS_URL=redis://localhost:6379/0 \
  DATABASE_URL=postgresql://aegisai:aegisai@localhost:5432/aegisai \
  pytest -q --cov=gateway --cov-report=term
```

35 tests, ~90% statement coverage of the `gateway` package. CI runs the
suite twice on every push -- once with no services configured, once with
real OPA/Redis/Postgres containers, plus a load-test smoke step (below) --
so the fallback path, the production-shaped path, and concurrent behavior
are all actually verified, not just the happy path (see badge above, and
`.github/workflows/ci.yml`).

## Performance

```bash
python scripts/loadtest.py --requests 300 --concurrency 20
```

Fires a realistic weighted mix of scenarios (mostly cheap reads, a
sprinkling of denies and escalations) at the gateway and reports latency
percentiles and throughput. It exists so this project has a real,
reproducible number instead of an assumed one -- and it's also what found
two genuine bugs during development:

| | Before | After |
|---|---|---|
| p50 latency (concurrency 20) | 2,403 ms | **243 ms** |
| p95 latency (concurrency 20) | 4,255 ms | **563 ms** |
| Throughput | 8.8 req/s | **69 req/s** |

**What was actually wrong**, found by instrumenting the request path and
reading the numbers, not by guessing:

1. `gateway/policy/opa_client.py` called `httpx.post()` -- the module-level
   convenience function, which opens a brand-new TCP connection for every
   single call. Fixed with one persistent, pooled `httpx.Client`.
2. `gateway/audit/postgres_store.py` opened a new Postgres connection (full
   TCP + auth handshake) for every decision. Fixed with a real connection
   pool (`psycopg_pool`).
3. **The big one:** `RedisApprovalManager.pending_count()` -- called on
   every `HUMAN_APPROVAL` decision to update a Prometheus gauge -- worked
   by calling `list_pending()`, which fetched and deserialized *every*
   pending approval with a separate Redis round trip each, just to `len()`
   the result. Harmless at low volume; with ~1,300 pending approvals
   accumulated from repeated demo runs, that's 1,300 sequential network
   round trips on the hot path of a single request. Fixed by making
   `pending_count()` a single `SCARD` call (O(1) instead of O(N)) and
   batching `list_pending()`'s reads into one pipelined round trip instead
   of N sequential ones. See `gateway/approvals/manager.py` and the
   regression tests in `tests/test_redis_state.py`.

Also fixed along the way: `gateway/telemetry/otel.py` used
`SimpleSpanProcessor` for the console trace exporter, which exports
synchronously in the request-handling thread. Switched to
`BatchSpanProcessor` (the correct choice for any exporter, not just OTLP).

**Honesty about the numbers:** these were measured on a single Windows
laptop running all six `docker-compose` services simultaneously (gateway,
OPA, Redis, Postgres, Prometheus, Grafana) -- not a dedicated benchmark
rig, and not tuned for a good number. The point isn't "AegisAI does 69
req/s," which says more about this laptop than the software; it's that the
methodology is real and reproducible, and that real measurement found real
bugs a benchmark-free "it feels fast enough" pass would have shipped. Run
it yourself and you'll get different absolute numbers on different
hardware -- that's expected.

## Try your own policy

Add or edit a rule in `gateway/policy/rules.yaml` -- no code change needed:

```yaml
- name: block_weekend_admin_actions
  when:
    action: admin
  then: HUMAN_APPROVAL
  reason: "Admin-level actions always require a human, regardless of risk score."
```

Or register a new agent with scoped permissions in
`gateway/identity/agents.yaml`, then re-run
`python scripts/generate_agent_keys.py` to mint its credential.

## Extending toward production

Already done: policy-as-code via real OPA, Redis-backed shared state, and a
durable Postgres audit trail (all above). See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#roadmap--future-proofing) for
the longer brainstorm; what's deliberately still open:

- Replace bearer-key auth with mTLS or SPIFFE/SPIRE workload identity for
  cryptographic, short-lived, auto-rotated agent credentials -- the highest-
  leverage remaining gap.
- Point `OTEL_EXPORTER_OTLP_ENDPOINT` at a real collector (Jaeger/Tempo).
- Ship `logs/audit.log` to your SIEM (Splunk/Elastic) via its standard
  log-forwarding agent -- the JSON schema is already flat and queryable.
- Replace the regex-based DLP/prompt-injection detectors with a classifier,
  Presidio, or an LLM-judge model behind the same `scan(text) -> (hits,
  score)` contract.
- Wrap real MCP servers instead of the simulated tools in `agent/tools/`.
