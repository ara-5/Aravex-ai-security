"""Verification gate: approved rules must keep their findings blocked.

For every entry in policies/gate_baseline.json the exact seed attack is replayed
against the target agent running behind the gateway, with only the approved
rules in policies/approved_rules.yaml added to the base policy. The build fails
if any of them succeeds again.

Four properties keep the gate honest:
  * it runs under both policy backends (local YAML and a live OPA);
  * a control run WITHOUT the approved rules must show each attack succeeding,
    so a gate that can never fail is itself a failure;
  * benign actions must still be allowed;
  * every approved rule needs a named reviewer on record.

OPA runs need OPA_URL. Locally they skip without one; CI sets REQUIRE_OPA=1 so a
missing OPA fails the build instead of skipping silently.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

# The target agent builds its database path at import time.
os.environ.setdefault("TARGET_DATABASE_URL", f"sqlite:///{Path(tempfile.mkdtemp()).as_posix()}/gate_target.db")

import pytest
import yaml
from fastapi.testclient import TestClient

import gateway.main as gateway_main
import target_agent.main as target_main
from aravex_loop.benign import BENIGN_ACTIONS
from gateway.policy import opa_client, rego_export
from gateway.policy.engine import PolicyEngine, Rule, load_rules
from gateway.security.anomaly import AnomalyTracker
from redteam_engine.attacks import FAMILY_BY_CATEGORY
from redteam_engine.attacks.base import AttackContext
from redteam_engine.target_client import TargetClient
from target_agent import gateway_guard

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"
AGENT = "nova-assistant-broad"
BASELINE = json.loads((POLICIES / "gate_baseline.json").read_text(encoding="utf-8"))["must_stay_blocked"]
APPROVED = (yaml.safe_load((POLICIES / "approved_rules.yaml").read_text(encoding="utf-8")) or {}).get("rules", [])
APPROVALS = json.loads((POLICIES / "approvals.json").read_text(encoding="utf-8"))
BACKENDS = ["yaml", "opa"]
TEST_KEY = "gate-test-key"  # credential_store.verify is patched to accept it


def _need_opa() -> None:
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


@pytest.fixture
def stack(monkeypatch):
    """Returns build(backend, with_approved) -> (target TargetClient, gateway TestClient)."""
    saved_opa_url = os.environ.get("OPA_URL")
    installed = []

    def build(backend: str, with_approved: bool):
        if backend == "opa":
            _need_opa()
            opa_client.put_policy(rego_export.POLICY_ID, rego_export.rules_to_rego(APPROVED if with_approved else []))
            installed.append(True)
        else:
            monkeypatch.delenv("OPA_URL", raising=False)

        rules = load_rules() + [Rule(**r) for r in (APPROVED if with_approved else [])]
        monkeypatch.setattr(gateway_main, "engine", PolicyEngine(rules=rules, anomaly_tracker=AnomalyTracker()))
        monkeypatch.setattr(gateway_main.credential_store, "verify", lambda *_: True)
        gateway = TestClient(gateway_main.app)

        monkeypatch.setattr(gateway_guard, "GATEWAY_MODE", "enforce")
        monkeypatch.setattr(gateway_guard, "GATEWAY_AGENT_ID", AGENT)
        # Without a bearer token the gateway answers 401 and every call is blocked,
        # which would make the gate pass for the wrong reason.
        monkeypatch.setattr(gateway_guard, "GATEWAY_API_KEY", TEST_KEY)
        monkeypatch.setattr(gateway_guard, "_http", lambda: gateway)
        gateway_guard.reset()

        target_main.startup()
        target = TargetClient(base_url="http://testserver", client=TestClient(target_main.app))
        target.reset()
        return target, gateway

    yield build

    if installed:
        opa_client.put_policy(rego_export.POLICY_ID, rego_export.rules_to_rego([]))
    if saved_opa_url:
        os.environ["OPA_URL"] = saved_opa_url


def _replay(target: TargetClient, entry: dict):
    family = FAMILY_BY_CATEGORY[entry["category"]]
    ctx = AttackContext(client=target, canaries=target.get_canaries(), campaign_session_prefix="verify-gate")
    seed = next((a for a in family.seeds(ctx) if a.technique == entry["technique"]), None)
    assert seed is not None, f"no seed attack for {entry['category']}/{entry['technique']}"
    session = f"verify-gate-{entry['category']}-{entry['technique']}"
    response = family.execute(seed, session, ctx)
    return family.judge(seed, session, response, target.get_state(session), ctx)


def test_gate_is_not_vacuous():
    assert BASELINE, "policies/gate_baseline.json is empty: the gate would pass without checking anything"


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("entry", BASELINE, ids=lambda e: f"{e['category']}:{e['technique']}")
def test_approved_rules_keep_finding_blocked(stack, backend, entry):
    target, _ = stack(backend, with_approved=True)
    result = _replay(target, entry)
    assert not result.success, (
        f"REGRESSION: {entry['category']}/{entry['technique']} (finding #{entry['finding_id']}, "
        f"rule {entry['rule_id']}) succeeds again under the {backend} backend. Evidence: {result.evidence}")


@pytest.mark.parametrize("entry", BASELINE, ids=lambda e: f"{e['category']}:{e['technique']}")
def test_control_attack_succeeds_without_the_approved_rules(stack, entry):
    target, _ = stack("yaml", with_approved=False)
    assert _replay(target, entry).success, (
        f"{entry['category']}/{entry['technique']} does not succeed even without the approved rules, "
        "so the gate cannot tell a working rule from none. Fix or remove this baseline entry.")


@pytest.mark.parametrize("backend", BACKENDS)
def test_benign_actions_still_allowed(stack, backend):
    _, gateway = stack(backend, with_approved=True)
    for action in BENIGN_ACTIONS:
        r = gateway.post("/v1/agent-action", json={"human_id": "h-jane-owner", "agent_id": AGENT, **action},
                         headers={"Authorization": f"Bearer {TEST_KEY}"})
        assert r.status_code == 200
        assert r.json()["decision"] == "ALLOW", f"approved rules now block benign {action['action']} on {action['resource']}"


def test_every_approved_rule_has_a_named_reviewer_and_a_baseline_entry():
    reviewed = {a["rule_id"]: a["reviewed_by"] for a in APPROVALS}
    covered = {b["rule_id"] for b in BASELINE}
    for rule in APPROVED:
        assert reviewed.get(rule["name"]), f"{rule['name']} has no reviewer on record in policies/approvals.json"
        assert not any(d in reviewed[rule["name"]] for d in ("unspecified", "demo auto-approve")), \
            f"{rule['name']} was only auto-approved"
        assert rule["name"] in covered, f"{rule['name']} has no gate_baseline.json entry, so nothing verifies it"


def test_approved_rules_can_be_expressed_in_rego():
    rego_export.rules_to_rego(APPROVED)  # raises UnsupportedRule if OPA could not enforce them
