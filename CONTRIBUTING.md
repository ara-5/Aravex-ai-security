# Working on Aravex

Notes for anyone (or any new session) picking this up. The code is proprietary; see
[LICENSE](LICENSE).

## Setup

Python 3.11+. One environment for everything:

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r redteam/requirements.txt -r gateway/requirements.txt -r mcp_proxy/requirements.txt
```

## Tests

| Command | Covers |
|---|---|
| `pytest` (repo root) | contracts, loop, verification gate, MCP proxy |
| `(cd redteam && pytest tests)` | red-team engine and target agent |
| `(cd gateway && python scripts/generate_agent_keys.py && pytest)` | gateway; OPA/Redis/Postgres tests skip if absent |
| `python scripts/demo_mcp_proxy.py` | MCP proxy with real processes (port 8010) |

CI is one workflow per area under `.github/workflows/`, each with path filters.

**OPA tests** skip without `OPA_URL`; CI sets `REQUIRE_OPA=1`. To run them locally, start
an OPA server on the rego folder, for example
`opa run --server --addr 127.0.0.1:8181 gateway/gateway/policy/rego`, then
`OPA_URL=http://127.0.0.1:8181 REQUIRE_OPA=1 pytest tests/gate`.

## Ports and state

`scripts/compare_defense.py` uses 8000 (gateway) and 8001 (target); `run_loop.py` uses the
same; `demo_mcp_proxy.py` uses 8010. They create throwaway databases and rotate the dev
agent keys in `gateway/.secrets/` (gitignored, never commit it).

## Real-model runs

`LLM_PROVIDER=ollama OLLAMA_MODEL=<model> TARGET_TIMEOUT=<s> OLLAMA_TIMEOUT=<s>`. A slow model
needs generous timeouts; `compare_defense.py` refuses to report a run where an attempt timed
out or a model call fell back to the stand-in. `MAX_MUTATIONS_PER_TECHNIQUE=0` keeps a
campaign to the seed attacks. Run long jobs detached; a foreground tool call can time out.

## Rules of the house

- Every gate or guard needs a control (it passes only because the thing it guards is
  actually stopped) and should be checked by breaking the code on purpose.
- Fail closed. Anything unexpected is a refusal.
- Do not report a number without saying which model, how many runs, and what it does not
  show.
- Keep docs in step: [README](README.md) known limits, [EVIDENCE](docs/EVIDENCE.md),
  [CHANGELOG](CHANGELOG.md).

## Known quirks

- `test_cli_unreachable_target_fails_cleanly` assumes port 1 is closed and fails on a
  machine where something listens there. It passes in CI.
- On Windows Git Bash, long multi-line heredocs can be truncated and backslash escapes
  mangled; write files with an editor tool instead.
- The IDE's import warnings for `aravex_mcp`, `gateway` and `redteam_engine` are false
  positives; pytest's `pythonpath` in `pytest.ini` resolves them.
