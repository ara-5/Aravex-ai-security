import pytest
from pydantic import ValidationError

from aravex_schemas import (
    CATEGORY_LAYER, AgentAction, DefenseLayer, Decision, Finding, FindingStatus,
    PolicyDecision, Severity, VerificationOutcome, classify, layer_for,
)


def test_defaults_and_unique_request_ids():
    kw = dict(human_id="h", agent_id="a", tool_id="t", action="read", resource="r")
    assert AgentAction(**kw).request_id != AgentAction(**kw).request_id


def test_decision_rejects_unknown_value():
    with pytest.raises(ValidationError):
        PolicyDecision(request_id="1", agent_id="a", action="x", resource="r",
                       decision="MAYBE", risk_score=0.1)


def test_negative_risk_score_rejected():
    with pytest.raises(ValidationError):
        PolicyDecision(request_id="1", agent_id="a", action="x", resource="r",
                       decision=Decision.DENY, risk_score=-1)


def test_finding_defaults_are_conservative():
    f = Finding(id="1", category="jailbreak", technique="t", severity="high", title="x")
    assert f.status is FindingStatus.OPEN
    assert f.defense_layer is DefenseLayer.MODEL
    assert f.severity is Severity.HIGH


@pytest.mark.parametrize("without,with_,expected", [
    (True, False, VerificationOutcome.BLOCKED),
    (True, True, VerificationOutcome.STILL_SUCCEEDS),
    (False, False, VerificationOutcome.INCONCLUSIVE),
    (False, True, VerificationOutcome.INCONCLUSIVE),
])
def test_classify(without, with_, expected):
    assert classify(without, with_) is expected


def test_unknown_category_never_claims_gateway_coverage():
    assert layer_for("brand_new_attack") is DefenseLayer.MODEL


def test_all_eleven_attack_families_are_classified():
    assert len(CATEGORY_LAYER) == 11
