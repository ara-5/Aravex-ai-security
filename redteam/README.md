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

## Two LLM backends, by design

| | Naive LLM (default) | Ollama (`USE_OLLAMA=true`) |
|---|---|---|
| Speed | Instant, deterministic | Realistic but slow on CPU (~10–20s/call observed with `llama3.2:3b`) |
| Dependencies | None | A running Ollama daemon + pulled model |
| What it proves | The platform's mechanics: attack generation, judging, scoring, regression | Whether a **real model** falls for these techniques given this system prompt |

The naive backend isn't a toy — it's a compact model of "an agent that
follows instructions wherever it finds them," which is the exact failure
class this platform is built to catch, and it's what makes the whole
project runnable and demoable with zero setup. Flip `USE_OLLAMA=true` and
point `OLLAMA_MODEL` at a pulled model (`.env.example`) to red-team a real
model instead — same attack engine, same scorecard, same regression tests.

## Tech stack

Python, FastAPI, LangGraph (with a same-shaped local fallback so the
3-agent pipeline runs even without the package installed), SQLAlchemy
(SQLite by default, Postgres via `DATABASE_URL` — see `docker-compose.yml`'s
`postgres` profile), FAISS when available / numpy cosine-similarity
otherwise, Ollama for local models, Docker, pytest, GitHub Actions.

**By design, this is a hand-built attack engine, not a wrapper around
PyRIT/Garak/Promptfoo/DeepEval** — see [Roadmap](#roadmap--future-proofing)
for how those fit in as optional, additive integrations rather than the
core.

## Repo layout

```
target_agent/         the vulnerable system under test
  config.py             system prompt, canary secrets, feature flags
  llm.py                Ollama client + the offline "naive" LLM
  agents.py              Router → Researcher → Executor pipeline
  tools.py, mcp_tools.py  tool + MCP registries and handlers
  vectorstore.py, seed_data.py   RAG
  db.py, main.py          persistence, FastAPI app + /admin introspection

redteam_engine/        AgentShield itself
  attacks/               one AttackFamily per category (11 total)
  planner.py              the agentic attack loop
  llm_adversary.py         attack mutation/generation
  judge helpers in attacks/base.py, scorecard.py, report.py, regression.py
  main.py, static/dashboard.html   API + dashboard

tests/                 pytest suite, incl. the CI regression gate
security_baseline.json   techniques that must never reproduce
```

## Roadmap / future-proofing

Things I'd reach for next, roughly in order of leverage:

1. **Pluggable target adapter.** Right now AgentShield speaks a fixed
   contract (`/chat`, `/admin/state`, `/admin/documents`, ...) to one
   reference target. The highest-leverage next step is a thin adapter
   interface so AgentShield can red-team *any* agent — a different
   LangGraph app, an OpenAI Assistants-based bot, a hosted product — by
   implementing a small adapter instead of matching this exact API. Turns
   this from "a demo with its own target" into a general-purpose tool.
2. **Pluggable model/embedding providers.** `llm.py` and `vectorstore.py`
   are intentionally small and swappable, but not yet behind a formal
   interface. Adding a `Provider` protocol (Ollama, OpenAI, Anthropic,
   Bedrock / sentence-transformers, Qdrant, pgvector) makes the platform
   useful for red-teaming whatever stack a team actually runs in
   production, not just a local Ollama model.
3. **LLM-judge for free-text success criteria.** Current judging is
   ground-truth-based (canaries, real tool calls, MCP logs) — robust, but
   blind to attacks whose "success" is a subtler behavioral shift (tone,
   partial compliance, subtle policy erosion) rather than a discrete
   action. A DeepEval/PyRIT-style LLM-judge pass as a *second opinion*
   alongside the deterministic judges would close that gap without giving
   up the reliability of ground-truth checks for the attacks that have one.
4. **Concurrency.** The planner runs attacks sequentially; running
   independent techniques concurrently (asyncio/httpx.AsyncClient) turns a
   multi-minute large-scale campaign (think PyRIT/Garak-scale fuzzing, or
   dozens of mutation rounds) into a much shorter one.
5. **OpenTelemetry tracing** across both services — a span per attack
   attempt/chat turn/tool call — would make campaigns debuggable at scale
   and is a natural fit given the platform already logs everything
   structurally.
6. **Persistent, shared infrastructure profile.** `docker-compose.yml`
   already supports a Postgres profile for real persistence; a natural
   next step is a Qdrant/pgvector profile behind the same vectorstore
   interface from #2, for a genuinely multi-worker, production-shaped
   deployment.
7. **Auth + RBAC on the dashboard/API.** Fine for local/CI use now; a
   hosted multi-tenant version would need real authentication before the
   `/admin/*` introspection routes could ever be exposed beyond localhost.
8. **CI regression gate as a reusable GitHub Action.** The mechanism in
   `tests/test_security_baseline.py` already works; packaging it as a
   standalone Action (`uses: agentshield/regression-gate@v1`) would let any
   repo running an AgentShield-adapted target drop the gate into their own
   CI without vendoring the test file.

## Authorized-use note

AgentShield attacks a system it owns, for the purpose of evaluating and
improving that system's security. Point it only at agents you have explicit
authorization to test.
