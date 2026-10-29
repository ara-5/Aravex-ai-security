"""Generated Rego must agree with the local YAML matcher on every rule.

The parity tests need a live OPA (OPA_URL). Locally they skip without one; in CI
set REQUIRE_OPA=1 so a missing OPA fails the build instead of skipping silently.
"""
from __future__ import annotations

import itertools
import os

import pytest

from gateway.models import ActionRequest
from gateway.policy import opa_client, rego_export
from gateway.policy.engine import Rule

RULES = [
    {"name": "r_iam", "when": {"agent_id": "a1", "action": "access", "resource_matches": "^iam\\."},
     "then": "DENY", "reason": "no iam"},
    {"name": "r_ext_send", "when": {"action": "send", "destination": "external_api",
                                    "data_classification": "SENSITIVE"},
     "then": "HUMAN_APPROVAL", "reason": "external sensitive send"},
    {"name": "r_multi", "when": {"action": ["export", "delete"], "record_count_gt": 10},
     "then": "DENY", "reason": "bulk"},
    {"name": "r_case", "when": {"resource_matches": "Secrets\\.|API_KEY"}, "then": "DENY", "reason": "case"},
]

AGENTS = ["a1", "a2"]
ACTIONS = ["access", "send", "export", "delete", "read"]
RESOURCES = ["iam.scope.admin", "email.x@y.test", "customer_db.records", "secrets.token", "my_api_key.txt", "calendar.team"]
CLASSES = ["INTERNAL", "SENSITIVE"]
DESTS = ["internal", "external_api"]
COUNTS = [1, 10, 11, 5000]


def _inputs():
    for ag, ac, res, cl, de, n in itertools.product(AGENTS, ACTIONS, RESOURCES, CLASSES, DESTS, COUNTS):
        yield dict(agent_id=ag, action=ac, resource=res, data_classification=cl, destination=de, record_count=n)


def test_rule_renders_expected_rego():
    text = rego_export.rule_to_rego(RULES[0])
    assert 'generated_deny contains "r_iam" if {' in text
    assert 'input.agent_id == "a1"' in text
    assert 'regex.match("(?i)^iam\\\\.", input.resource)' in text
    assert 'generated_reasons["r_iam"] := "no iam"' in text


def test_approval_rules_go_to_the_approval_set():
    assert "generated_approval contains" in rego_export.rule_to_rego(RULES[1])


def test_empty_rule_list_is_a_valid_noop_module():
    assert rego_export.rules_to_rego([]).startswith("package aegisai.guardrails")


@pytest.mark.parametrize("bad", [
    {"name": "x", "when": {"bogus": 1}, "then": "DENY"},
    {"name": "x", "when": {}, "then": "DENY"},
    {"name": "x", "when": {"action": "read"}, "then": "ALLOW"},
    {"name": "bad name!", "when": {"action": "read"}, "then": "DENY"},
])
def test_unsupported_rules_are_refused_not_guessed(bad):
    with pytest.raises(rego_export.UnsupportedRule):
        rego_export.rule_to_rego(bad)


def test_quotes_and_backslashes_in_reasons_cannot_break_the_module():
    rule = {"name": "q", "when": {"action": "read"}, "then": "DENY", "reason": 'say "hi" \\ and\nnewline'}
    assert '\\"hi\\"' in rego_export.rule_to_rego(rule)


def _opa_or_skip():
    if not opa_client.is_configured():
        if os.environ.get("REQUIRE_OPA"):
            pytest.fail("REQUIRE_OPA is set but OPA_URL is not")
        pytest.skip("OPA_URL not set")
    try:
        opa_client.evaluate({"agent_id": "x", "action": "read", "resource": "x", "record_count": 1,
                             "data_classification": "INTERNAL", "destination": "internal"})
    except opa_client.OPAUnavailable as exc:
        if os.environ.get("REQUIRE_OPA"):
            pytest.fail(f"REQUIRE_OPA is set but OPA is unreachable: {exc}")
        pytest.skip(f"OPA unreachable: {exc}")


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r["name"])
def test_opa_and_yaml_matcher_agree(rule):
    _opa_or_skip()
    opa_client.put_policy(rego_export.POLICY_ID, rego_export.rules_to_rego([rule]))
    try:
        compared = 0
        for doc in _inputs():
            expected = Rule(**rule).matches(ActionRequest(human_id="h", tool_id="t", **doc))
            got = rule["name"] in opa_client.evaluate(doc)["matched_rules"]
            assert got == expected, f"disagreement on {doc}: yaml={expected} opa={got}"
            compared += 1
        assert compared == len(AGENTS) * len(ACTIONS) * len(RESOURCES) * len(CLASSES) * len(DESTS) * len(COUNTS)
    finally:
        opa_client.put_policy(rego_export.POLICY_ID, rego_export.rules_to_rego([]))


def test_opa_applies_effect_and_reason():
    _opa_or_skip()
    opa_client.put_policy(rego_export.POLICY_ID, rego_export.rules_to_rego(RULES[:2]))
    try:
        deny = opa_client.evaluate(dict(agent_id="a1", action="access", resource="iam.x", record_count=1,
                                        data_classification="INTERNAL", destination="internal"))
        assert deny["decision"] == "DENY" and any("no iam" in r for r in deny["reasons"])
        park = opa_client.evaluate(dict(agent_id="a2", action="send", resource="email.x", record_count=1,
                                        data_classification="SENSITIVE", destination="external_api"))
        assert park["decision"] == "HUMAN_APPROVAL"
    finally:
        opa_client.put_policy(rego_export.POLICY_ID, rego_export.rules_to_rego([]))


def test_a_module_opa_refuses_raises_policy_rejected():
    _opa_or_skip()
    with pytest.raises(opa_client.PolicyRejected):
        opa_client.put_policy("aravex_broken", "package aegisai.guardrails\nthis is not rego {{")
