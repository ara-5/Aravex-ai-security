# AgentShield

**An autonomous AI agent red-team & security platform.** AgentShield builds a
realistic, intentionally-vulnerable multi-agent AI system (LLM + RAG +
long-term memory + tools + MCP + a 3-agent pipeline), then attacks it with
its own agentic red-team engine — a planner that generates attacks, executes
them, observes what happened, judges success, mutates the attack, and
repeats, closing the loop from **Attack → Evidence → Impact → Remediation →
Regression Test**.

```
                    ┌─ Prompt Injection
                    ├─ Jailbreak
                    ├─ RAG Poisoning
                    ├─ Memory Poisoning
                    ├─ Tool Poisoning
                    ├─ MCP Attacks
User ──→ Agent ─────┼─ Data Exfiltration
                    ├─ Privilege Escalation
                    ├─ System Prompt Extraction
                    ├─ Excessive Agency
                    └─ Agent-to-Agent Attack
                              │
                              ▼
                     Security Evaluation
                              │
                              ▼
                     Risk / Severity
                              │
                              ▼
                     Security Report
```

## Why this exists

Most "AI red-teaming" demos are a list of jailbreak prompts pasted into a
chat box. AgentShield is a working **attack-generation engine**: an agentic
loop that plans techniques, generates payloads, executes them against a real
multi-agent system, inspects tool calls / memory / MCP state to judge
success objectively (not just "does the text look bad"), and mutates failed
attempts into stronger variants — up to 3 escalation rounds per technique,
using a real local LLM as the adversarial generator when one's available.

```
Attack Planner
      │
      ▼
Generate attack ──────────────┐
      │                       │
      ▼                       │
Execute against agent          │
      │                       │
      ▼                       │
Observe response/tool calls    │
      │                       │
      ▼                       │
Determine success? ──No───────┘  (mutate & retry, up to N rounds)
      │
     Yes
      │
      ▼
Open Finding: Attack → Evidence → Impact → Remediation → Regression Test
```

## Architecture

Two independent FastAPI services:

| Service | Port | Role |
|---|---|---|
| `target_agent/` | 8001 | The system under test — a **deliberately vulnerable** multi-agent assistant ("Nova"): LLM, RAG (FAISS/numpy), long-term memory, tools (file/db/email), a simulated MCP tool server, and a 3-agent LangGraph-style pipeline (Router → Researcher → Executor). |
| `redteam_engine/` | 8002 | **AgentShield** — the attack planner, 11 attack families, judge logic, scorecard, regression runner, and dashboard. |

The two never share code or state except over HTTP — the same boundary a
real red-team engagement would have against someone else's deployed agent.

### The target agent's vulnerability surface (all intentional)

- **System prompt** carries secrets in plaintext and explicitly tells the
  model to trust retrieved documents/tool output as instructions — this one
  line is the root cause behind most of the findings below.
- **RAG**: any document ingested into the corpus can carry an embedded
  instruction the agent will act on purely because it was retrieved.
- **Memory**: `"remember that..."` is written verbatim, no sanitization, and
  re-injected as trusted context on every future turn — a one-time
  injection can become a persistent backdoor.
- **Tools**: `file_read`/`file_write` have naive path-traversal guards,
  `send_email` has no DLP/allow-list, `db_lookup` returns the full table on
  a broad query, `cloud_metadata_fetch` simulates the classic SSRF→cloud-
  credentials pattern.
- **MCP**: a `calendar_sync` tool that's advertised as harmless but
  silently exfiltrates memory (tool poisoning), a permission-grant tool
  with no auth workflow, and a token-issuing tool with no caller check.
- **Multi-agent**: the Executor agent trusts the Researcher agent's
  "research note" the same way it trusts a document — a poisoned document
  can make one agent manipulate another into unauthorized action.

Nothing here calls a real external network — email is a simulated outbox,
MCP tools are in-process, cloud-metadata is canned. Safe to run and attack
freely.

### Why it's genuinely agentic, not a prompt list

`redteam_engine/planner.py` runs every attack family through
plan → generate → execute → observe → judge → mutate → repeat. Failed
attempts are handed to `redteam_engine/llm_adversary.py`, which asks a local
LLM (or a deterministic escalation-template fallback with zero
dependencies) to produce a stronger variant of the same technique, up to
`MAX_MUTATIONS_PER_TECHNIQUE` rounds. Success is judged from **ground
truth** — canary secrets, actual tool calls, MCP exfiltration logs, granted
scopes — not string-matching the reply text.

## Quickstart

```bash
cp .env.example .env
python -m venv .venv && . .venv/Scripts/activate   # or source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt

# terminal 1
uvicorn target_agent.main:app --port 8001
# terminal 2
uvicorn redteam_engine.main:app --port 8002
```

Open **http://localhost:8002** for the dashboard, click **Run Full Attack
Campaign**, and watch the scorecard and findings populate in real time.

Or with Docker:

```bash
docker compose up --build
```

By default both services use a deterministic, offline LLM stand-in (see
[Two LLM backends](#two-llm-backends-by-design)) so a full campaign
finishes in **seconds**, with zero external dependencies.

### Run the test suite

```bash
pytest tests/ -v
```

## The dashboard

- **AI Security Scorecard** — a 0–10 score per category (Prompt Injection,
  RAG Security, Memory Security, Tool Security, MCP Security, Data
  Protection, Agent Authorization), computed live from open findings.
- **Findings by Severity** — Critical / High / Medium / Low counts.
- **Findings table** — click any row to expand its full **Attack → Evidence
  → Impact → Remediation → Regression Test** report, and run the regression
  test right from the browser.

## The killer feature: prove a fix actually works

Every open finding stores the *exact* payload (and any setup steps — a
poisoned document, a planted memory entry) that triggered it. Regression
testing replays that exact attack against the target:

```
Attack → FAIL ❌   (vulnerability confirmed)

...apply a real fix to target_agent...

Attack → re-run regression → PASS ✅   (vulnerability no longer reproduces)
```

This is validated end-to-end in `tests/test_redteam_engine.py`
(`test_regression_flips_to_pass_after_a_real_fix`), which patches the MCP
credential-exposure vulnerability at runtime and proves the same finding
flips from `FAIL` to `PASS`.

**CI gate**: `security_baseline.json` lists techniques that have been fixed
and must never reproduce. `tests/test_security_baseline.py` replays every
listed technique on every CI run and fails the build on any regression —
the fix-and-verify loop, wired permanently into the pipeline instead of a
one-time manual check. (Proven with a temporary local test that pretends
`mcp_credential_exposure` is fixed while it still isn't — the gate failed
the build correctly, exactly as it should on a real regression.)

## Pluggable everything: LLM, embeddings, target, judge

Every seam that would otherwise hard-code "this repo's reference target,
Ollama, and a canary-based judge" is behind a small interface instead —
each proven with a real test, not just declared:

| Interface | Implementations | Proof |
|---|---|---|
| `target_agent/llm_providers.py` — `LLMProvider` | `naive` (default, deterministic, zero deps) · `ollama` · `openai_compatible` (OpenAI, Azure OpenAI, vLLM, LM Studio, Groq, ...) | Same `TOOL_CALL: {...}` convention across all three — swap `LLM_PROVIDER` and every attack family works unmodified |
| `target_agent/vectorstore.py` — `EmbeddingProvider` | `hash` (default, zero deps) · `ollama` (real embedding model, auto-fallback if unreachable) | RAG-poisoning tests pass unchanged under either |
| `redteam_engine/target_adapter.py` — `TargetAdapter` | `TargetClient` (this repo's fully-introspectable reference target) · `GenericChatAdapter` (any black-box agent with nothing but a chat endpoint) | `tests/test_generic_adapter.py` spins up a **real HTTP server** and red-teams it through nothing but `GenericChatAdapter`, with zero changes to any attack family — techniques needing introspection correctly report "not observable" instead of crashing |
| Judging | Deterministic ground-truth judges (always on) + optional `redteam_engine/llm_judge.py` LLM-judge second opinion (`ENABLE_LLM_JUDGE=true`) | Never overrides the deterministic verdict — stored alongside it on every `AttackAttempt` |

Naive LLM vs. a real model, concretely:

| | Naive LLM (default) | Ollama / OpenAI-compatible |
|---|---|---|
| Speed | Instant, deterministic | Realistic but slower (~10–20s/call observed with `llama3.2:3b` on CPU) |
| Dependencies | None | A running model backend |
| What it proves | The platform's mechanics: attack generation, judging, scoring, regression | Whether a **real model** falls for these techniques given this system prompt |

The naive backend isn't a toy — it's a compact model of "an agent that
follows instructions wherever it finds them," which is the exact failure
class this platform is built to catch, and it's what makes the whole
project runnable and demoable with zero setup. Set `LLM_PROVIDER` (or
`USE_OLLAMA=true`) and the matching model/URL in `.env` to red-team a real
model instead — same attack engine, same scorecard, same regression tests.

## Tech stack

Python, FastAPI, LangGraph (with a same-shaped local fallback so the
3-agent pipeline runs even without the package installed), SQLAlchemy
(SQLite by default, tuned with WAL + busy-timeout for the planner's
concurrent workers; Postgres via `DATABASE_URL` — see `docker-compose.yml`'s
`postgres` profile), FAISS when available / numpy cosine-similarity
otherwise, Ollama and any OpenAI-compatible endpoint for real models,
OpenTelemetry (opt-in), Docker, pytest, GitHub Actions (including a
reusable composite Action — see below).

**By design, this is a hand-built attack engine, not a wrapper around
PyRIT/Garak/Promptfoo/DeepEval** — those stay documented, additive
integration points rather than dependencies.

## Concurrency

`redteam_engine/planner.py` runs independent (family, seed-technique)
jobs across a thread pool (`REDTEAM_MAX_WORKERS`, default 4) — a full
23-seed, 11-category campaign completes in single-digit seconds against
the naive backend. Each worker owns its own DB session (SQLAlchemy
sessions aren't thread-safe to share); `httpx.Client` is documented safe
for concurrent use. This surfaced and fixed a real bug along the way: the
target agent's RAG vector store is a process-wide singleton, and FastAPI
runs sync route handlers in a thread pool too, so concurrent chat
requests were racing on `VectorStore._rebuild()` and intermittently
500-ing unrelated attempts. Fixed with an `RLock` around every mutation
and read (`target_agent/vectorstore.py`) — verified with three
consecutive concurrent campaigns and zero errors in the logs.

## Optional auth

Both services are open by default (the point of `/admin/*` is that
AgentShield introspects a target it's authorized to attack). Set
`ADMIN_API_KEY` on the target and matching `TARGET_ADMIN_API_KEY` /
`REDTEAM_API_KEY` on the engine before exposing either beyond localhost —
gates `target_agent`'s `/admin/*` routes and `redteam_engine`'s write
endpoints (`/campaigns/run`, `/findings/*/regression`,
`/regression/run-all`) via a `X-API-Key` header; read-only endpoints stay
open so the dashboard remains viewable. The dashboard has a small **API
Key** button (stored in `localStorage`) for setting it from the browser.

## Observability

Set `ENABLE_OTEL=true` for OpenTelemetry tracing across both services —
`observability.py` auto-instruments every HTTP route (FastAPIInstrumentor)
and `redteam_engine/planner.py` adds a fine-grained `attack_attempt` span
per attempt with category/technique/success attributes. Exports to the
console with zero setup, or to any OTLP/HTTP collector (Jaeger, Tempo,
Honeycomb, ...) via `OTEL_EXPORTER_OTLP_ENDPOINT`. Every import is
defensive — disabled or uninstalled, both services run exactly as before.

## CI regression gate as a reusable Action

`.github/actions/regression-gate/` packages the fix-and-verify loop as a
composite Action, referenced locally in `ci.yml` (`uses:
./.github/actions/regression-gate`) as its own CI check, separate from the
general test run — so a real regression shows up as its own red X on a
PR. Takes `baseline-file`/`working-directory` inputs, so it's a short
step away from publishing standalone (`agentshield/regression-gate@v1`)
for any other repo running an AgentShield-adapted target.

## Repo layout

```
observability.py       shared opt-in OpenTelemetry setup (both services)

target_agent/          the vulnerable system under test
  config.py               system prompt, canary secrets, feature flags
  llm.py                  thin dispatcher over llm_providers.py
  llm_providers.py         pluggable LLMProvider: naive | ollama | openai_compatible
  agents.py                Router → Researcher → Executor pipeline
  tools.py, mcp_tools.py    tool + MCP registries and handlers
  vectorstore.py            pluggable EmbeddingProvider RAG store (thread-safe)
  seed_data.py, db.py, main.py   RAG seed docs, persistence, FastAPI app + /admin

redteam_engine/         AgentShield itself
  attacks/                  one AttackFamily per category (11 total)
  planner.py                 the agentic attack loop (concurrent across techniques)
  llm_adversary.py            attack mutation/generation
  llm_judge.py                 optional LLM-judge second opinion
  target_adapter.py             the TargetAdapter protocol
  adapters/generic_chat_adapter.py   black-box-agent adapter
  target_client.py               reference adapter for this repo's own target
  judge helpers in attacks/base.py, scorecard.py, report.py, regression.py
  main.py, static/dashboard.html   API + dashboard (optional API-key auth)

tests/                  pytest suite, incl. the CI regression gate
.github/actions/regression-gate/   the gate packaged as a reusable Action
security_baseline.json    techniques that must never reproduce
```

## What's still genuinely open

Honest gaps, not yet closed:

- **Full multi-tenant auth/RBAC.** The shared-secret gate above is real
  but deliberately minimal — no user accounts, no per-route roles. Fine
  for local/CI/single-team use; a hosted multi-tenant version needs more.
- **Qdrant/pgvector.** `EmbeddingProvider` makes the embedding model
  swappable; the vector *store* itself is still in-process
  FAISS/numpy. A `Qdrant`/`pgvector` backend behind the same interface
  would be the natural next step for a genuinely multi-worker deployment
  (Postgres itself is already supported for the relational data, via the
  `postgres` `docker-compose.yml` profile).
- **True async, not threads.** The planner's concurrency is a
  `ThreadPoolExecutor` (simple, and enough to turn a 23-seed campaign
  into single-digit seconds) rather than `asyncio`/`httpx.AsyncClient`.
  Real PyRIT/Garak-scale fuzzing (thousands of payloads) would want the
  latter for lower per-task overhead.
- **The regression-gate Action is local-only.** It's a real composite
  Action (`.github/actions/regression-gate`) and already runs as its own
  CI check here, but hasn't been extracted to its own published repo yet.

## Authorized-use note

AgentShield attacks a system it owns, for the purpose of evaluating and
improving that system's security. Point it only at agents you have explicit
authorization to test.
