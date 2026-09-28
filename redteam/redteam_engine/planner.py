"""
The Attack Planner — the agentic loop that makes AgentShield more than a
prompt library:

    plan family -> generate attack -> execute against target -> observe
    -> judge success -> generate next attack (mutation) -> repeat

Runs every registered attack family against the target agent, persists
every attempt (successful or not) and opens a Finding for each confirmed
success, complete with an Attack -> Evidence -> Impact -> Remediation
report and a replayable regression-test spec.
"""
from __future__ import annotations

import json
import uuid

from redteam_engine.attacks import ALL_FAMILIES, FAMILY_BY_CATEGORY
from redteam_engine.attacks.base import AttackContext
from redteam_engine.config import MAX_MUTATIONS_PER_TECHNIQUE
from redteam_engine.db import SessionLocal, Campaign, AttackAttempt, Finding
from redteam_engine.report import build_finding_fields
from redteam_engine.target_client import TargetClient


class AttackPlanner:
    def __init__(self, client: TargetClient | None = None):
        self.client = client or TargetClient()

    def run_campaign(self, name: str, categories: list[str] | None = None) -> int:
        db = SessionLocal()
        try:
            families = [FAMILY_BY_CATEGORY[c] for c in categories] if categories else ALL_FAMILIES
            campaign = Campaign(name=name, status="running", categories=json.dumps([f.category for f in families]))
            db.add(campaign)
            db.commit()
            db.refresh(campaign)

            canaries = self.client.get_canaries()
            ctx = AttackContext(client=self.client, canaries=canaries, campaign_session_prefix=f"c{campaign.id}")

            for family in families:
                for seed in family.seeds(ctx):
                    self._run_technique(db, campaign.id, family, seed, ctx)

            campaign.status = "completed"
            from redteam_engine.db import now
            campaign.finished_at = now()
            db.commit()
            return campaign.id
        finally:
            db.close()

    def _run_technique(self, db, campaign_id: int, family, seed_attack, ctx: AttackContext):
        attack = seed_attack
        generation = 0
        while True:
            session_id = f"{ctx.campaign_session_prefix}-{family.category}-{attack.technique}-{generation}-{uuid.uuid4().hex[:6]}"
            try:
                response = family.execute(attack, session_id, ctx)
                target_state = self.client.get_state(session_id)
                result = family.judge(attack, session_id, response, target_state, ctx)
            except Exception as e:
                # Target unreachable / errored — record as a failed, non-blocking attempt.
                db.add(AttackAttempt(
                    campaign_id=campaign_id, session_id=session_id, category=family.category,
                    technique=attack.technique, generation=generation, payload=attack.payload,
                    metadata_json=json.dumps(attack.metadata),
                    response_text=f"[error contacting target: {e}]", tool_calls_json="[]",
                    success=False, severity="low", confidence=0.0, evidence="",
                ))
                db.commit()
                return

            db.add(AttackAttempt(
                campaign_id=campaign_id,
                session_id=session_id,
                category=family.category,
                technique=attack.technique,
                generation=generation,
                payload=attack.payload,
                metadata_json=json.dumps(attack.metadata),
                response_text=result.response_text,
                tool_calls_json=json.dumps(result.tool_calls),
                success=result.success,
                severity=result.severity,
                confidence=result.confidence,
                evidence=result.evidence,
            ))
            db.commit()

            if result.success:
                fields = build_finding_fields(result)
                db.add(Finding(
                    campaign_id=campaign_id,
                    attempt_id=db.query(AttackAttempt).order_by(AttackAttempt.id.desc()).first().id,
                    category=family.category,
                    technique=attack.technique,
                    severity=result.severity,
                    title=fields["title"],
                    attack_payload=attack.payload,
                    attack_metadata_json=json.dumps(attack.metadata),
                    evidence=result.evidence,
                    impact=fields["impact"],
                    remediation=fields["remediation"],
                    status="open",
                ))
                db.commit()
                return

            if generation >= MAX_MUTATIONS_PER_TECHNIQUE:
                return

            next_attack = family.mutate(attack, result, ctx)
            if next_attack is None:
                return
            attack = next_attack
            generation += 1
