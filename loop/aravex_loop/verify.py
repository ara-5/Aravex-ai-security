"""Build the record that proves (or fails to prove) a mitigation worked."""
from __future__ import annotations

from datetime import datetime, timezone

from aravex_schemas import PolicyDecision, VerificationResult, classify


def verification(finding_id: str, policy_ids: list[str], regression_outcome: str,
                 decisions: list[PolicyDecision] | None = None, note: str | None = None) -> VerificationResult:
    """``regression_outcome`` is the red-team engine's replay verdict: FAIL means
    the attack still succeeds, PASS means it no longer reproduces. The finding
    existed, so the baseline (without this defense) succeeded by definition."""
    still_succeeds = regression_outcome == "FAIL"
    return VerificationResult(
        finding_id=str(finding_id), policy_ids=policy_ids,
        success_without_defense=True, success_with_defense=still_succeeds,
        outcome=classify(True, still_succeeds), decisions=decisions or [],
        verified_at=datetime.now(timezone.utc), note=note)
