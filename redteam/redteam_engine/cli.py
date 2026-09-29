"""
AgentShield CLI — scripted access to everything the dashboard does, for
CI pipelines, cron jobs, or anyone who'd rather not click through a UI.

Talks to the target agent over HTTP (TARGET_AGENT_URL) exactly like the
dashboard does, and reads/writes the same database -- run this alongside
a running redteam_engine server, or standalone against just the target
agent; either way you're looking at the same findings either place shows.

Usage:
    python -m redteam_engine.cli campaign run [--categories cat1,cat2] [--name NAME] [--no-reset] [--workers N]
    python -m redteam_engine.cli scorecard
    python -m redteam_engine.cli findings list [--status open|resolved|regressed]
    python -m redteam_engine.cli findings show <id>
    python -m redteam_engine.cli regression run <finding_id>
    python -m redteam_engine.cli regression run-all
    python -m redteam_engine.cli report export [--scope all|open] [--out FILE]
"""
from __future__ import annotations

import argparse
import sys

from redteam_engine.config import CATEGORY_LABELS
from redteam_engine.db import init_db, SessionLocal, Finding
from redteam_engine.planner import AttackPlanner
from redteam_engine.regression import run_regression, run_all_regressions
from redteam_engine.report import generate_security_report_markdown
from redteam_engine.scorecard import compute_scorecard
from redteam_engine.target_client import TargetClient

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _bar(score: float, width: int = 24) -> str:
    filled = max(0, min(width, round(score / 10 * width)))
    return "#" * filled + "-" * (width - filled)


def cmd_campaign_run(args):
    client = TargetClient()
    if not client.health():
        print(f"error: target agent unreachable at {client.base_url}", file=sys.stderr)
        return 1
    if not args.no_reset:
        client.reset()

    categories = args.categories.split(",") if args.categories else None
    if categories:
        unknown = [c for c in categories if c not in CATEGORY_LABELS]
        if unknown:
            print(f"error: unknown categories {unknown}. Choose from: {list(CATEGORY_LABELS)}", file=sys.stderr)
            return 1

    print(f"Running campaign '{args.name}'" + (f" ({', '.join(categories)})" if categories else " (all categories)") + "...")
    planner = AttackPlanner(client)
    campaign_id = planner.run_campaign(args.name, categories=categories, max_workers=args.workers)
    print(f"Campaign #{campaign_id} completed.\n")
    return cmd_scorecard(args)


def cmd_scorecard(_args):
    sc = compute_scorecard()
    print(f"AI SECURITY SCORECARD - overall {sc['overall_score']}/10\n")
    for row in sc["rows"]:
        print(f"  {row['row']:<22} [{_bar(row['score'])}] {row['score']:>4.1f}/10  ({row['open_findings']} open)")
    sev = sc["severity_counts"]
    print(f"\n  Critical: {sev.get('critical', 0):<4} High: {sev.get('high', 0):<4} Medium: {sev.get('medium', 0):<4} Low: {sev.get('low', 0)}")
    return 0


def cmd_findings_list(args):
    db = SessionLocal()
    try:
        q = db.query(Finding)
        if args.status:
            q = q.filter(Finding.status == args.status)
        findings = q.all()
    finally:
        db.close()
    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))
    if not findings:
        print("No findings.")
        return 0
    print(f"{'ID':<5}{'SEV':<10}{'STATUS':<12}{'REGRESSION':<12}TITLE")
    for f in findings:
        print(f"{f.id:<5}{f.severity:<10}{f.status:<12}{(f.last_regression_result or '-'):<12}{f.title}")
    return 0


def cmd_findings_show(args):
    db = SessionLocal()
    try:
        f = db.query(Finding).filter(Finding.id == args.id).first()
    finally:
        db.close()
    if not f:
        print(f"error: finding #{args.id} not found", file=sys.stderr)
        return 1
    print(f"#{f.id} [{f.severity.upper()}] {f.title} ({f.status})\n")
    print("ATTACK\n" + f.attack_payload + "\n")
    print("EVIDENCE\n" + f.evidence + "\n")
    print("IMPACT\n" + f.impact + "\n")
    print("REMEDIATION\n" + f.remediation + "\n")
    print(f"REGRESSION: {f.last_regression_result or 'not yet run'}")
    return 0


def cmd_regression_run(args):
    result = run_regression(args.finding_id, TargetClient())
    if "error" in result:
        print(f"error: {result['error']}", file=sys.stderr)
        return 1
    icon = "PASS" if result["outcome"] == "PASS" else "FAIL"
    print(f"[{icon}] finding #{result['finding_id']} -> {result['status']}")
    print(result["evidence"])
    return 0


def cmd_regression_run_all(_args):
    results = run_all_regressions(client=TargetClient())
    passed = sum(1 for r in results if r.get("outcome") == "PASS")
    failed = sum(1 for r in results if r.get("outcome") == "FAIL")
    for r in results:
        if "error" in r:
            continue
        print(f"[{r['outcome']:<4}] finding #{r['finding_id']} -> {r['status']}")
    print(f"\n{passed} PASS, {failed} FAIL, {len(results)} total")
    return 0


def cmd_report_export(args):
    md = generate_security_report_markdown(scope=args.scope)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"wrote {args.out} ({len(md)} bytes)")
    else:
        print(md)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m redteam_engine.cli", description="AgentShield CLI")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("campaign", help="run attack campaigns")
    csub = c.add_subparsers(dest="subcommand", required=True)
    run = csub.add_parser("run", help="run a full or partial attack campaign")
    run.add_argument("--categories", help="comma-separated category list (default: all 11)")
    run.add_argument("--name", default="cli campaign")
    run.add_argument("--no-reset", action="store_true", help="don't reset target state first")
    run.add_argument("--workers", type=int, default=None, help="override REDTEAM_MAX_WORKERS")
    run.set_defaults(func=cmd_campaign_run)

    sc = sub.add_parser("scorecard", help="print the current AI Security Scorecard")
    sc.set_defaults(func=cmd_scorecard)

    f = sub.add_parser("findings", help="list/show findings")
    fsub = f.add_subparsers(dest="subcommand", required=True)
    flist = fsub.add_parser("list")
    flist.add_argument("--status", choices=["open", "resolved", "regressed"])
    flist.set_defaults(func=cmd_findings_list)
    fshow = fsub.add_parser("show")
    fshow.add_argument("id", type=int)
    fshow.set_defaults(func=cmd_findings_show)

    r = sub.add_parser("regression", help="run regression tests")
    rsub = r.add_subparsers(dest="subcommand", required=True)
    rrun = rsub.add_parser("run")
    rrun.add_argument("finding_id", type=int)
    rrun.set_defaults(func=cmd_regression_run)
    rall = rsub.add_parser("run-all")
    rall.set_defaults(func=cmd_regression_run_all)

    rep = sub.add_parser("report", help="export the security report")
    repsub = rep.add_subparsers(dest="subcommand", required=True)
    repexport = repsub.add_parser("export")
    repexport.add_argument("--scope", choices=["all", "open"], default="all")
    repexport.add_argument("--out", help="write to file instead of stdout")
    repexport.set_defaults(func=cmd_report_export)

    return p


def main(argv=None) -> int:
    # Findings/reports contain real typography (em dashes, middle dots).
    # Windows consoles default to a legacy codepage that mangles it on
    # print(); force UTF-8 stdout rather than degrading that text.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    init_db()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
