"""
The Attack Planner — the agentic loop that makes AgentShield more than a
prompt library:

    plan family -> generate attack -> execute against target -> observe
    -> judge success -> generate next attack (mutation) -> repeat

Runs every registered attack family against the target agent, persists
every attempt (successful or not) and opens a Finding for each confirmed
success, complete with an Attack -> Evidence -> Impact -> Remediation
report and a replayable regression-test spec.

Independent (family, seed-technique) runs execute concurrently across a
thread pool (config.MAX_WORKERS): each mutation chain is inherently
sequential (round 2 depends on round 1's result), but the ~15-20 seed
techniques across 11 families are fully independent, so this is where the
parallelism actually pays off on a large campaign.
"""
from __future__ import annotations

import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from redteam_engine.attacks import ALL_FAMILIES, FAMILY_BY_CATEGORY
from redteam_engine.attacks.base import AttackContext
from redteam_engine.config import MAX_MUTATIONS_PER_TECHNIQUE, MAX_WORKERS
from redteam_engine.db import SessionLocal, Campaign, AttackAttempt, Finding, now
from redteam_engine.llm_judge import get_llm_opinion
from redteam_engine.report import build_finding_fields
from redteam_engine.scorecard import record_snapshot
from redteam_engine.target_adapter import TargetAdapter
from redteam_engine.target_client import TargetClient

import observability

_tracer = observability.get_tracer("redteam_engine.planner")


class AttackPlanner:
    def __init__(self, client: TargetAdapter | None = None):
        # Defaults to this repo's reference adapter; pass any other
        # TargetAdapter implementation (see adapters/generic_chat_adapter.py)
        # to point the exact same attack families at a different agent.
        self.client = client or TargetClient()

    def run_campaign(self, name: str, categories: list[str] | None = None, max_workers: int | None = None) -> int:
        db = SessionLocal()
        try:
            families = [FAMILY_BY_CATEGORY[c] for c in categories] if categories else ALL_FAMILIES
            campaign = Campaign(name=name, status="running", categories=json.dumps([f.category for f in families]))
            db.add(campaign)
            db.commit()
            db.refresh(campaign)
            campaign_id = campaign.id

            canaries = self.client.get_canaries()
            ctx = AttackContext(client=self.client, canaries=canaries, campaign_session_prefix=f"c{campaign_id}")
        finally:
            db.close()

        jobs = [(family, seed) for family in families for seed in family.seeds(ctx)]
        workers = max(1, max_workers or MAX_WORKERS)

        if workers == 1:
            for family, seed in jobs:
                self._run_technique(campaign_id, family, seed, ctx)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(self._run_technique, campaign_id, family, seed, ctx) for family, seed in jobs]
                for f in as_completed(futures):
                    f.result()  # surface any unexpected exception rather than swallowing it

        db = SessionLocal()
        try:
            campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
            campaign.status = "completed"
            campaign.finished_at = now()
            db.commit()
        finally:
            db.close()

        record_snapshot("campaign", campaign_id)
        return campaign_id

    def _run_technique(self, campaign_id: int, family, seed_attack, ctx: AttackContext):
        # Each concurrent task owns its own DB session -- SQLAlchemy
        # sessions are not thread-safe to share across worker threads.
        db = SessionLocal()
        try:
            attack = seed_attack
            generation = 0
            while True:
                session_id = f"{ctx.campaign_session_prefix}-{family.category}-{attack.technique}-{generation}-{uuid.uuid4().hex[:6]}"
                try:
                    with _tracer.start_as_current_span("attack_attempt") as span:
                        span.set_attribute("agentshield.category", family.category)
                        span.set_attribute("agentshield.technique", attack.technique)
                        span.set_attribute("agentshield.generation", generation)
                        response = family.execute(attack, session_id, ctx)
                        target_state = ctx.client.get_state(session_id)
                        result = family.judge(attack, session_id, response, target_state, ctx)
                        span.set_attribute("agentshield.success", result.success)
                        span.set_attribute("agentshield.severity", result.severity)
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

                llm_opinion = get_llm_opinion(family.category, attack.technique, attack.payload, result.response_text, result.tool_calls)

                attempt = AttackAttempt(
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
                    llm_judge_verdict=llm_opinion["llm_judge_verdict"] if llm_opinion else None,
                    llm_judge_rationale=llm_opinion["llm_judge_rationale"] if llm_opinion else None,
                )
                db.add(attempt)
                db.commit()  # populates attempt.id via the PK, no re-query needed

                if result.success:
                    fields = build_finding_fields(result)
                    db.add(Finding(
                        campaign_id=campaign_id,
                        attempt_id=attempt.id,
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
        finally:
            db.close()
