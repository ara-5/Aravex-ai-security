import yaml
import pytest

from aravex_loop import store, synthesize, verify
from aravex_loop.benign import BENIGN_ACTIONS
from aravex_schemas import Decision, ProposalStatus, VerificationOutcome

AGENT = "nova-assistant-broad"

EXTERNAL_EMAIL = {"tool_id": "email_tool", "action": "send", "resource": "email.x@evil.test",
                  "destination": "external_api", "data_classification": "INTERNAL"}
IAM_GRANT = {"tool_id": "iam_tool", "action": "access", "resource": "iam.scope.admin"}
EXPORT = {"tool_id": "customer_db_tool", "action": "export", "resource": "customer_db.records",
          "record_count": 3}
# A legitimate-looking external sync that carries sensitive data: indistinguishable
# by rule from the benign internal sync only via destination, so it is a valid rule.
CAL_EXTERNAL = {"tool_id": "calendar_mcp_tool", "action": "send", "resource": "calendar.team_shared",
                "destination": "external_api", "data_classification": "SENSITIVE"}


def test_credentials_and_privilege_changes_are_denied_not_parked():
    assert synthesize.effect_for(IAM_GRANT) is Decision.DENY
    assert synthesize.effect_for(EXPORT) is Decision.DENY
    assert synthesize.effect_for({"action": "read", "resource": "secrets.x"}) is Decision.DENY


def test_ambiguous_actions_ask_a_human():
    assert synthesize.effect_for(EXTERNAL_EMAIL) is Decision.HUMAN_APPROVAL


def test_rule_is_scoped_to_agent_action_and_category():
    rule = synthesize.rule_from_action(IAM_GRANT, AGENT, "r1", "why")
    assert rule["when"] == {"agent_id": AGENT, "action": "access", "resource_matches": "^iam\\."}


def test_external_destination_is_part_of_the_rule():
    rule = synthesize.rule_from_action(EXTERNAL_EMAIL, AGENT, "r1", "why")
    assert rule["when"]["destination"] == "external_api"


def test_proposal_blocks_the_attack_but_not_benign_work():
    props, notes = synthesize.propose("7", "Export", "data_exfiltration", AGENT, [EXPORT], BENIGN_ACTIONS)
    assert len(props) == 1 and notes == []
    rule = yaml.safe_load(props[0].yaml_rule)
    assert synthesize.matches(rule, EXPORT, AGENT)
    assert not any(synthesize.matches(rule, b, AGENT) for b in BENIGN_ACTIONS)


def test_rule_that_would_block_benign_work_is_rejected():
    overbroad = {"tool_id": "email_tool", "action": "send", "resource": "email.alice@example.com",
                 "destination": "internal"}
    props, notes = synthesize.propose("8", "Mail", "data_exfiltration", AGENT, [overbroad], BENIGN_ACTIONS)
    assert props == []
    assert "rejected" in notes[0] and "benign" in notes[0]


def test_model_level_categories_get_no_rule():
    props, notes = synthesize.propose("9", "Leak", "system_prompt_extraction", AGENT, [EXPORT], BENIGN_ACTIONS)
    assert props == [] and "inside the model" in notes[0]


def test_attack_with_no_gateway_visible_action_gets_no_rule():
    props, notes = synthesize.propose("10", "x", "prompt_injection", AGENT, [], BENIGN_ACTIONS)
    assert props == [] and "without any gateway-visible action" in notes[0]


def test_duplicate_actions_yield_one_proposal():
    props, _ = synthesize.propose("11", "x", "data_exfiltration", AGENT, [EXPORT, dict(EXPORT)], BENIGN_ACTIONS)
    assert len(props) == 1


def test_only_approved_proposals_are_exported(tmp_path):
    props, _ = synthesize.propose("12", "x", "privilege_escalation", AGENT, [IAM_GRANT, EXPORT], BENIGN_ACTIONS)
    assert all(p.status is ProposalStatus.DRAFT for p in props)

    out = tmp_path / "rules.yaml"
    assert store.export_active_rules(props, out) == []  # nothing approved yet

    store.approve(props, {props[0].id}, reviewer="ara")
    assert store.export_active_rules(props, out) == [props[0].rule_id]
    assert props[0].reviewed_by == "ara" and props[1].status is ProposalStatus.DRAFT


def test_proposals_round_trip(tmp_path):
    props, _ = synthesize.propose("13", "x", "privilege_escalation", AGENT, [IAM_GRANT], BENIGN_ACTIONS)
    store.save(tmp_path / "p.json", props)
    assert store.load(tmp_path / "p.json") == props


@pytest.mark.parametrize("regression,expected", [
    ("PASS", VerificationOutcome.BLOCKED),
    ("FAIL", VerificationOutcome.STILL_SUCCEEDS),
])
def test_verification_follows_the_replay_verdict(regression, expected):
    assert verify.verification("1", ["r1"], regression).outcome is expected


def test_generated_rules_load_in_the_real_gateway_engine(tmp_path, monkeypatch):
    props, _ = synthesize.propose("14", "x", "privilege_escalation", AGENT, [IAM_GRANT], BENIGN_ACTIONS)
    store.approve(props, None, reviewer="ara")
    path = tmp_path / "rules.yaml"
    store.export_active_rules(props, path)

    from gateway.models import ActionRequest
    from gateway.policy.engine import PolicyEngine, load_active_rules
    from gateway.security.anomaly import AnomalyTracker

    monkeypatch.setenv("ARAVEX_EXTRA_RULES", str(path))
    engine = PolicyEngine(rules=load_active_rules(), anomaly_tracker=AnomalyTracker())
    d = engine.evaluate(ActionRequest(human_id="h-jane-owner", agent_id=AGENT, **IAM_GRANT))
    assert d.decision.value == "DENY" and props[0].rule_id in d.matched_rules
