# Aravex AI Security

**Attack. Defend. Verify.**

[![Red-team CI](https://github.com/ara-5/Aravex-ai-security/actions/workflows/redteam-ci.yml/badge.svg)](https://github.com/ara-5/Aravex-ai-security/actions/workflows/redteam-ci.yml)
[![Gateway CI](https://github.com/ara-5/Aravex-ai-security/actions/workflows/gateway-ci.yml/badge.svg)](https://github.com/ara-5/Aravex-ai-security/actions/workflows/gateway-ci.yml)
[![Contracts CI](https://github.com/ara-5/Aravex-ai-security/actions/workflows/contracts-ci.yml/badge.svg)](https://github.com/ara-5/Aravex-ai-security/actions/workflows/contracts-ci.yml)
[![MCP Proxy CI](https://github.com/ara-5/Aravex-ai-security/actions/workflows/mcp-proxy-ci.yml/badge.svg)](https://github.com/ara-5/Aravex-ai-security/actions/workflows/mcp-proxy-ci.yml)
[![Verification Gate](https://github.com/ara-5/Aravex-ai-security/actions/workflows/verification-gate.yml/badge.svg)](https://github.com/ara-5/Aravex-ai-security/actions/workflows/verification-gate.yml)
![License: All rights reserved](https://img.shields.io/badge/License-All%20rights%20reserved-lightgrey.svg)

Aravex secures AI agents end to end. A red-team engine attacks an agent system
and records what worked. A zero-trust gateway sits between the agent and
everything it can touch, deciding allow, deny or human approval for each tool
call. A feedback loop turns findings into draft gateway rules, a person
approves them, and the attacks are replayed to prove the rules hold.

```
                     ┌──────────────── findings ────────────────┐
                     ▼                                          │
 red-team engine ──attacks──▶ target agent ──tool calls──▶ gateway ──▶ tools, data, MCP
                                                              │
        draft rules ◀── human approval ◀── rule synthesis ◀───┘
              │
              └──▶ active rules ──▶ replay every attack ──▶ VerificationResult
```

## What is measured so far

All results are from the deterministic offline stand-in model that the target
agent ships with, not a real LLM, and each is a single run. Treat them as a
demonstration that the mechanism works, not as an effectiveness claim.

| Experiment | Result |
|---|---|
| Same 11-category campaign, bare vs. behind the gateway (least-privilege identity) | **19 successful attacks → 6.** Every gateway-addressable category went to zero; the 6 left are model-level or partly visible ones. [Details](docs/DEFENSE_COMPARISON.md) |
| Feedback loop on an over-permissioned identity | 10 open findings → 1 draft rule → approved → **1 finding verified blocked**, 5 of 5 benign actions still allowed. The other 9 are model-level, have no tool call to act on, or look identical to legitimate use. [Details](docs/FEEDBACK_LOOP.md) |

The gateway cannot stop everything. Jailbreaks and system-prompt extraction
happen inside the model, and a rule that stops an attack by also stopping
normal work is rejected rather than shipped. The repo tracks which categories a
gateway can address (`schemas/aravex_schemas/coverage.py`) separately from what
was actually measured.

## Repository layout

| Path | What it is |
|---|---|
| [`redteam/`](redteam/) | Red-team engine (from AgentShield): planner, 11 attack families, ground-truth judges, scorecard, dashboard, regression runner. Also holds `target_agent/`, a deliberately vulnerable multi-agent assistant, with an optional gateway guard (`GATEWAY_MODE=enforce`). |
| [`gateway/`](gateway/) | Runtime gateway (from AegisAI): agent identity and IAM, rule engine (local YAML or OPA/Rego), risk scoring, DLP and injection detectors, human-approval queue, audit log, Prometheus/Grafana. |
| [`schemas/`](schemas/) | Shared contracts: `AgentAction`, `PolicyDecision`, `Finding`, `PolicyProposal`, `VerificationResult`, and the category-to-defense-layer map. |
| [`mcp_proxy/`](mcp_proxy/) | MCP proxy: puts the gateway in front of any stdio MCP server. Every tool call is checked first and reaches the server only on `ALLOW`. [Docs](docs/MCP_PROXY.md) |
| [`loop/`](loop/) | The feedback loop: rule synthesis, benign-action check, proposal store, verification records. |
| [`policies/`](policies/) | Approved, verified gateway rules, who approved them, and the findings they must keep blocked. |
| [`scripts/`](scripts/) | `compare_defense.py` (bare vs. protected) and `run_loop.py` (propose / verify / demo / promote). |
| [`tests/`](tests/) | Contract tests, loop tests, and the verification gate (`tests/gate`). |
| [`docs/`](docs/) | [Defense comparison](docs/DEFENSE_COMPARISON.md), [feedback loop](docs/FEEDBACK_LOOP.md), [MCP proxy](docs/MCP_PROXY.md). |

`redteam/` and `gateway/` were imported with their full git history and each
keeps its own README with setup details.

## Try it

You need Python 3.11+. Install the dependencies of both services in one
environment:

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r redteam/requirements.txt -r gateway/requirements.txt -r mcp_proxy/requirements.txt
```

**Tests**

```bash
pytest tests/schemas tests/integration tests/loop   # contracts + loop (repo root)
pytest tests/gate               # verification gate; the OPA backend needs OPA_URL (CI sets REQUIRE_OPA=1)
pytest tests/mcp_proxy          # MCP proxy against the real gateway engine
python scripts/demo_mcp_proxy.py   # same checks with real processes (uses port 8010)
(cd redteam && pytest tests)    # red-team engine and target agent
(cd gateway && python scripts/generate_agent_keys.py && pytest)   # OPA/Redis/Postgres tests skip if absent
```

**Bare vs. behind the gateway.** Starts the gateway and target on local ports,
runs the same campaign twice, and prints a per-category table:

```bash
python scripts/compare_defense.py --out report.md
```

**The feedback loop.** Attacks an over-permissioned identity, drafts rules, and
waits for you to approve before anything is applied:

```bash
python scripts/run_loop.py propose --work .aravex-loop      # writes proposals.json
python scripts/run_loop.py verify  --work .aravex-loop --approve prop-9-1 --reviewer you
# or, for demos only, approve every draft:
python scripts/run_loop.py demo    --work .aravex-loop
```

Both scripts create throwaway databases and use ports 8000 and 8001.

**Gate any MCP server.** The proxy sits between an MCP client and a stdio MCP
server. Tool calls reach the server only if the gateway allows them; anything else,
including a gateway that cannot be reached, is refused. [Setup and mapping](docs/MCP_PROXY.md):

```bash
ARAVEX_API_KEY=... python -m aravex_mcp --gateway-url http://localhost:8000 \
    --agent-id nova-assistant --mapping mcp_proxy/mapping.example.yaml -- <upstream command>
```

## How the pieces connect

- **Target behind the gateway.** With `GATEWAY_MODE=enforce`, every tool call
  the target agent makes is sent to the gateway first and runs only on `ALLOW`.
  If the gateway is unreachable, the call is refused. Refused calls are not
  recorded as executed, so they cannot count as successful attacks. The guard is
  off by default, so the vulnerable baseline is unchanged.
- **Identities.** `nova-assistant` is least-privilege. `nova-assistant-broad`
  is deliberately over-permissioned and exists only as the loop's starting point.
- **Approved rules** live in `policies/` and load through `ARAVEX_EXTRA_RULES`
  after the base rules, so they cannot override them. They apply under both the
  local YAML matcher and OPA: the gateway converts them to Rego and installs them
  on the OPA server at startup.
- **The verification gate** (`tests/gate`, run by `verification-gate.yml`) replays
  each promoted finding's attack against both backends on every change and fails
  if it succeeds again. It also fails if a control run without the rules stops
  showing the attack succeeding, so the gate cannot pass vacuously.
- **Success is ground truth.** The red-team judges read the target's actual
  state (outbox, MCP exfiltration log, granted scopes, executed tool calls), not
  the reply text.

## Status and known limits

Working: both services, the shared contracts, the protected-target mode, the
comparison, the propose / approve / verify loop, and the MCP proxy, all under CI.

Not done yet:

- The gate replays each seed attack plus the engine's five deterministic rephrasings,
  not the model-written mutations a live campaign would try. A rule could still miss
  an attack phrased in a way none of those cover.
- The benign-action set is a small hand-written list; a rule is only as safe as
  that list is complete.
- Measurements use the offline stand-in model. Real-model results are untested.
- The MCP proxy gates tool calls only (not tool descriptions or results), handles
  stdio only, and has not been run against a real third-party server yet. See its
  [limits](docs/MCP_PROXY.md#limits).
- Human approvals need approver keys (`GATEWAY_APPROVER_KEYS="name:key,..."`, separate
  from agent keys; none configured means the approval endpoints are disabled). The
  audit trail records the person whose key was used. Keys sit in an environment
  variable, so there is no rotation, expiry or login; this is key-per-person, not SSO.
- The dashboards of the two services are still separate; there is no unified one.
- `test_cli_unreachable_target_fails_cleanly` assumes port 1 is closed and fails
  on machines where something listens there. It passes in CI.

## Security note

`redteam/target_agent` is intentionally vulnerable (plaintext secrets in its
prompt, weak tool sandboxing, unauthenticated MCP-style tools). Never deploy it
or its configuration pattern. Its `/admin/*` routes exist for the authorized
red-team judge and must not be exposed beyond localhost.

## License

Proprietary. Copyright (c) 2026 ara-5. All rights reserved. See [LICENSE](LICENSE).
Earlier versions that were published under the MIT License remain available
under those terms to anyone who obtained them then.
