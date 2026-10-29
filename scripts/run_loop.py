"""Run the Aravex feedback loop: attack -> propose rules -> human approval -> verify.

    python scripts/run_loop.py propose --work DIR            # find gaps, write draft rules
    python scripts/run_loop.py verify  --work DIR --approve all|id,id [--reviewer NAME]
    python scripts/run_loop.py demo    --work DIR            # both, approving every draft (demo only)

The subject is the deliberately over-permissioned identity ``nova-assistant-broad``,
so there are real gaps to close. ``propose`` attacks the target behind the
gateway and turns each successful, gateway-visible attack into a draft rule
(rules that would also block benign work are rejected). Nothing is applied
until a person approves it. ``verify`` activates only approved rules, replays
every finding's attack, and records whether each one is now blocked.

Needs the dependencies of both redteam/ and gateway/ in the current environment.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
for sub in ("schemas", "loop", "redteam", "gateway"):
    sys.path.insert(0, str(ROOT / sub))

from compare_defense import GATEWAY_PORT, TARGET_PORT, mint_key, wait_for  # noqa: E402
from aravex_loop import store, synthesize, verify  # noqa: E402
from aravex_loop.benign import BENIGN_ACTIONS  # noqa: E402
from aravex_schemas import PolicyDecision, ProposalStatus  # noqa: E402

AGENT_ID = "nova-assistant-broad"
IGNORED_RESULT_PREFIX = "[blocked by gateway]"


class Stack:
    """Gateway + target agent for one phase. Stops both on exit."""

    def __init__(self, work: Path, key: str, extra_rules: Path | None = None):
        self.work, self.key, self.extra_rules = work, key, extra_rules
        self.procs: list[subprocess.Popen] = []
        self.env = {
            **os.environ,
            "TARGET_PORT": str(TARGET_PORT),
            "TARGET_DATABASE_URL": f"sqlite:///{(work / 'target.db').as_posix()}",
            "REDTEAM_DATABASE_URL": f"sqlite:///{(work / 'redteam.db').as_posix()}",
            "TARGET_AGENT_URL": f"http://127.0.0.1:{TARGET_PORT}",
            "GATEWAY_MODE": "enforce", "GATEWAY_URL": f"http://127.0.0.1:{GATEWAY_PORT}",
            "GATEWAY_AGENT_ID": AGENT_ID, "GATEWAY_API_KEY": key,
        }

    def __enter__(self):
        gw_env = {**os.environ, "ANOMALY_RATE_THRESHOLD": "1000000", "ANOMALY_FAIL_THRESHOLD": "1000000"}
        if self.extra_rules:
            gw_env["ARAVEX_EXTRA_RULES"] = str(self.extra_rules)
        gw = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "gateway.main:app", "--port", str(GATEWAY_PORT), "--log-level", "warning"],
            cwd=ROOT / "gateway", env=gw_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(gw)
        wait_for(f"http://127.0.0.1:{GATEWAY_PORT}/healthz", gw, "gateway")
        tg = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "target_agent.main:app", "--port", str(TARGET_PORT), "--log-level", "warning"],
            cwd=ROOT / "redteam", env=self.env)
        self.procs.append(tg)
        wait_for(f"http://127.0.0.1:{TARGET_PORT}/health", tg, "target agent")
        return self

    def __exit__(self, *exc):
        for p in reversed(self.procs):
            p.terminate()
        for p in self.procs:
            p.wait(timeout=15)

    def redteam(self, *args: str) -> None:
        subprocess.run([sys.executable, "-m", "redteam_engine.cli", *args],
                       cwd=ROOT / "redteam", env=self.env, check=True, capture_output=True)

    def gateway_decision(self, action: dict) -> PolicyDecision:
        r = httpx.post(f"http://127.0.0.1:{GATEWAY_PORT}/v1/agent-action",
                       json={"human_id": "h-jane-owner", "agent_id": AGENT_ID, **action},
                       headers={"Authorization": f"Bearer {self.key}"}, timeout=10)
        r.raise_for_status()
        return PolicyDecision.model_validate(r.json())


def _rows(db: Path, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        return con.execute(sql, params).fetchall()
    finally:
        con.close()


def _allowed_actions(db: Path, attempt_id: int) -> list[dict]:
    """Gateway-visible actions the attack got executed (blocked calls are never recorded)."""
    from target_agent.gateway_guard import build_action

    row = _rows(db, "SELECT tool_calls_json FROM attack_attempts WHERE id = ?", (attempt_id,))[0]
    keep = ("tool_id", "action", "resource", "destination", "data_classification", "record_count")
    actions = []
    for call in json.loads(row["tool_calls_json"] or "[]"):
        a = build_action(call["name"], call.get("arguments") or {})
        actions.append({k: a[k] for k in keep if k in a})
    return actions


def cmd_propose(work: Path) -> int:
    work.mkdir(parents=True, exist_ok=True)
    for f in ("redteam.db", "target.db"):
        (work / f).unlink(missing_ok=True)
    key = mint_key(AGENT_ID, rotate=True)

    print("Attacking the target behind the gateway (over-permissioned identity)...", flush=True)
    with Stack(work, key) as stack:
        stack.redteam("campaign", "run", "--name", "loop-baseline", "--workers", "1")

    db = work / "redteam.db"
    findings = _rows(db, "SELECT id, attempt_id, category, technique, title FROM findings WHERE status = 'open' ORDER BY id")
    proposals, notes = [], []
    for f in findings:
        props, n = synthesize.propose(str(f["id"]), f["title"], f["category"], AGENT_ID,
                                      _allowed_actions(db, f["attempt_id"]), BENIGN_ACTIONS)
        proposals += props
        notes += [f"finding #{f['id']} ({f['category']}): {m}" for m in n]
    store.save(work / "proposals.json", proposals)

    print(f"\n{len(findings)} open findings -> {len(proposals)} draft rules\n")
    for p in proposals:
        print(f"  [{p.status.value}] {p.id}  {p.effect.value:<14} finding #{p.finding_id}\n"
              f"      {p.rationale}")
    if notes:
        print("\nNo rule proposed:")
        for m in notes:
            print(f"  - {m}")
    print(f"\nDrafts written to {work / 'proposals.json'}. Review, then run `verify --approve ...`.")
    return 0


def cmd_verify(work: Path, approve: str, reviewer: str) -> int:
    proposals = store.load(work / "proposals.json")
    ids = None if approve == "all" else {i.strip() for i in approve.split(",") if i.strip()}
    store.approve(proposals, ids, reviewer)
    store.save(work / "proposals.json", proposals)
    active = work / "active_rules.yaml"
    rule_ids = store.export_active_rules(proposals, active)
    print(f"{len(rule_ids)} approved rule(s) active: {', '.join(rule_ids) or 'none'}", flush=True)

    key = mint_key(AGENT_ID, rotate=False)
    results = []
    benign_blocked = []
    with Stack(work, key, extra_rules=active) as stack:
        for b in BENIGN_ACTIONS:
            d = stack.gateway_decision(b)
            if d.decision.value != "ALLOW":
                benign_blocked.append((b, d))
        stack.redteam("regression", "run-all")

    db = work / "redteam.db"
    by_finding: dict[str, list[str]] = {}
    for p in proposals:
        if p.status in (ProposalStatus.APPROVED, ProposalStatus.ACTIVE):
            by_finding.setdefault(p.finding_id, []).append(p.rule_id)
    for f in _rows(db, "SELECT id, category, title, status, last_regression_result FROM findings ORDER BY id"):
        policy_ids = by_finding.get(str(f["id"]), [])
        note = None if policy_ids else "no rule applied to this finding"
        results.append((f, verify.verification(str(f["id"]), policy_ids, f["last_regression_result"] or "FAIL", note=note)))
    (work / "verification.json").write_text(
        json.dumps([r.model_dump(mode="json") for _, r in results], indent=2), encoding="utf-8")

    blocked = sum(r.outcome.value == "blocked" for _, r in results)
    print(f"\nVerification: {blocked} of {len(results)} findings now blocked\n")
    for f, r in results:
        print(f"  #{f['id']:<3} {r.outcome.value:<15} {f['category']:<22} rules={r.policy_ids or '-'}")
    print(f"\nBenign actions still allowed: {len(BENIGN_ACTIONS) - len(benign_blocked)} of {len(BENIGN_ACTIONS)}")
    for b, d in benign_blocked:
        print(f"  BLOCKED {b['action']} on {b['resource']}: {d.decision.value} {d.matched_rules}")
    return 0 if not benign_blocked else 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("propose", "verify", "demo"):
        p = sub.add_parser(name)
        p.add_argument("--work", type=Path, default=Path(".aravex-loop"))
        if name != "propose":
            p.add_argument("--reviewer", default="unspecified")
        if name == "verify":
            p.add_argument("--approve", required=True, help="'all' or comma-separated proposal ids")
    a = ap.parse_args()
    work = a.work.resolve()
    if a.cmd == "propose":
        return cmd_propose(work)
    if a.cmd == "verify":
        return cmd_verify(work, a.approve, a.reviewer)
    rc = cmd_propose(work)
    return rc or cmd_verify(work, "all", f"{a.reviewer} (demo auto-approve)")


if __name__ == "__main__":
    raise SystemExit(main())
