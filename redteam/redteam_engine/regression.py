"""
Regression testing: replay the EXACT attack behind a Finding against the
(presumably now-patched) target agent.

    Attack -> FAIL (vuln confirmed)
    ... fix applied to target agent ...
    Attack -> re-run regression -> PASS (vuln no longer reproduces)

A finding whose regression flips back to FAIL after previously PASSing is
marked "regressed" so a real CI pipeline can gate on it.
"""
from __future__ import annotations

import json
import uuid

from redteam_engine.attacks import FAMILY_BY_CATEGORY
from redteam_engine.attacks.base import Attack, AttackContext
from redteam_engine.db import SessionLocal, Finding, now
from redteam_engine.scorecard import record_snapshot
from redteam_engine.target_adapter import TargetAdapter
from redteam_engine.target_client import TargetClient


def run_regression(finding_id: int, client: TargetAdapter | None = None) -> dict:
    client = client or TargetClient()
    db = SessionLocal()
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            return {"error": "finding not found"}

        family = FAMILY_BY_CATEGORY.get(finding.category)
        if not family:
            return {"error": f"unknown category {finding.category}"}

        canaries = client.get_canaries()
        ctx = AttackContext(client=client, canaries=canaries, campaign_session_prefix="regression")
        metadata = json.loads(finding.attack_metadata_json or "{}")
        attack = Attack(category=finding.category, technique=finding.technique, payload=finding.attack_payload, metadata=metadata)

        session_id = f"regression-{finding.id}-{uuid.uuid4().hex[:6]}"
        response = family.execute(attack, session_id, ctx)
        target_state = client.get_state(session_id)
        result = family.judge(attack, session_id, response, target_state, ctx)

        outcome = "FAIL" if result.success else "PASS"
        finding.last_regression_result = outcome
        finding.last_regression_at = now()
        if outcome == "PASS":
            finding.status = "resolved"
        else:
            finding.status = "regressed" if finding.status == "resolved" else "open"
        db.commit()
        record_snapshot("regression", finding.id)

        return {
            "finding_id": finding.id,
            "outcome": outcome,
            "status": finding.status,
            "evidence": result.evidence,
            "response_text": result.response_text,
        }
    finally:
        db.close()


def run_all_regressions(statuses: list[str] | None = None) -> list[dict]:
    statuses = statuses or ["open", "resolved", "regressed"]
    db = SessionLocal()
    try:
        finding_ids = [f.id for f in db.query(Finding).filter(Finding.status.in_(statuses)).all()]
    finally:
        db.close()
    return [run_regression(fid) for fid in finding_ids]
