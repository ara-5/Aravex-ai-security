# Changelog

Newest first. Each entry says what changed and what was checked. See
[docs/EVIDENCE.md](docs/EVIDENCE.md) for measurements and their limits.

## Unreleased

- **`aravex-mcp scan`**: reads a stdio MCP server's tool definitions and writes a report,
  a suggested mapping and `pins.json`. Flags known tool-poisoning patterns (hidden
  instruction blocks, invisible characters, key-file grabs with exfiltration wording,
  tool steering, outbound-URL instructions, side-channel parameters) and does not let a
  flagged description decide how its tool is classified. `--fail-on` for CI.
- **Definition pinning**: `aravex-mcp --pins pins.json` hides and refuses any tool that
  is new or whose name, description or schema changed since the scan, checked against the
  server's current definition on every call. Demonstrated with real processes
  (`scripts/demo_scan_and_pin.py`): a rug pull goes unnoticed without pins and is stopped
  with them. The tests were checked by breaking the scanner and the pin check seven ways.
  The scanner is heuristic and has only been tried on servers written in this repo.

## 0.1.0 (2026-10-30)

First tagged state of the merged platform.

### 2026-10-30
- **Real-model comparisons can be trusted.** A first run against a local model reported
  zero successes because replies timed out and a failed model call silently fell back to
  the stand-in. Timeouts are now settings (`TARGET_TIMEOUT`, `OLLAMA_TIMEOUT`), the
  target counts model calls and fallbacks, and `compare_defense.py` refuses to print a
  table from an invalid run. The first valid real-model run is recorded, with the
  conclusion that it does not show the gateway helping (nothing it could block
  succeeded). `6b5c63b`
- Added `SECURITY.md`, this changelog, `docs/DECISIONS.md`, `docs/ROADMAP.md`,
  `CONTRIBUTING.md`.

### 2026-10-29
- **Verification gate replays rephrased attacks**, not just the seed: five fixed
  rephrasings under both policy backends, with a control that at least one succeeds
  without the rules. `5e2a216`
- **MCP proxy installable** as the `aravex-mcp` command; marked "Private :: Do Not
  Upload"; `--help` fixed. Checked in a fresh virtualenv from outside the repo. `73b6a14`
- **Per-approver keys.** `GATEWAY_APPROVER_KEYS="name:key,..."`; the audit trail records
  the person whose key was used, and a mismatched name in the request is refused. `9334b11`
- **Approval endpoints require an approver credential** (they were unauthenticated).
  Disabled, not open, when no key is configured. `a58d366`
- **MCP proxy** that puts the gateway in front of any stdio MCP server. Refuses unless
  the gateway answers an exact `ALLOW`; unmapped tools are refused and audited; the
  gateway key is kept out of the upstream process. Tests use the real gateway engine and
  assert refused calls never reach the upstream. Not yet run against a third-party
  server. `6535f5f`
- **Approved rules apply under OPA** (Rego emitted and installed at startup, 3,840
  YAML-vs-OPA comparisons agree) and a **CI verification gate** replays promoted
  findings under both backends. `66e7480`
- README rewritten with measured results and known limits. `7960bac`
- **Feedback loop**: finding → draft rule → human approval → replay verification.
  `eba1e84`
- **Target behind the gateway** and a bare-vs-protected comparison (stand-in model: 19
  successful attacks bare, 6 behind the gateway). `641ab44`
- Shared schemas and contract tests (`85632b2`); CI moved to the repo root with path
  filters (`e70e940`); proprietary license for new work (`e77a1c1`); root README and
  LICENSE (`8ba1946`).
- Imported the AgentShield red-team engine and the AegisAI gateway with their git
  history preserved (`redteam/`, `gateway/`).
