"""Aggregates open Findings into the AI Security Scorecard."""
from __future__ import annotations

from redteam_engine.config import SCORECARD_ROWS
from redteam_engine.db import SessionLocal, Finding

SCORE_PENALTY = {"critical": 4.0, "high": 2.5, "medium": 1.2, "low": 0.5}


def compute_scorecard() -> dict:
    db = SessionLocal()
    try:
        open_findings = db.query(Finding).filter(Finding.status == "open").all()
    finally:
        db.close()

    by_category: dict[str, list[Finding]] = {}
    for f in open_findings:
        by_category.setdefault(f.category, []).append(f)

    rows = []
    for row_name, categories in SCORECARD_ROWS.items():
        findings = [f for c in categories for f in by_category.get(c, [])]
        penalty = sum(SCORE_PENALTY.get(f.severity, 0.5) for f in findings)
        score = max(0.0, 10.0 - penalty)
        rows.append({
            "row": row_name,
            "score": round(score, 1),
            "open_findings": len(findings),
            "categories": categories,
        })

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in open_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    overall = round(sum(r["score"] for r in rows) / len(rows), 1) if rows else 10.0

    return {
        "rows": rows,
        "severity_counts": severity_counts,
        "overall_score": overall,
        "total_open_findings": len(open_findings),
    }
