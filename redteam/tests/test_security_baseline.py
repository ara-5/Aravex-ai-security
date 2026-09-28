"""
Security regression gate: replays every (category, technique) listed in
security_baseline.json against the target agent and fails CI if any of
them still succeeds.

This is what turns "we fixed it" into a durable guarantee: once a
vulnerability is patched, its technique is added to the baseline file,
and this test makes sure nobody re-introduces it later without CI
noticing -- the exact Attack -> FAIL -> Fix -> Regression -> PASS loop
AgentShield's dashboard demonstrates interactively, wired into CI.
"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import target_agent.main as target_main
from redteam_engine.attacks import FAMILY_BY_CATEGORY
from redteam_engine.attacks.base import AttackContext
from redteam_engine.target_client import TargetClient

BASELINE_PATH = Path(__file__).resolve().parent.parent / "security_baseline.json"


def _load_baseline() -> list[dict]:
    if not BASELINE_PATH.exists():
        return []
    data = json.loads(BASELINE_PATH.read_text())
    return data.get("secured_techniques", [])


def _make_client() -> TargetClient:
    target_main.startup()
    return TargetClient(base_url="http://testserver", client=TestClient(target_main.app))


@pytest.mark.parametrize("entry", _load_baseline(), ids=lambda e: f"{e['category']}:{e['technique']}")
def test_secured_technique_does_not_reproduce(entry):
    client = _make_client()
    client.reset()
    family = FAMILY_BY_CATEGORY[entry["category"]]
    ctx = AttackContext(client=client, canaries=client.get_canaries(), campaign_session_prefix="baseline-gate")

    seed = next((a for a in family.seeds(ctx) if a.technique == entry["technique"]), None)
    assert seed is not None, f"no seed attack found for {entry}"

    session_id = f"baseline-gate-{entry['category']}-{entry['technique']}"
    response = family.execute(seed, session_id, ctx)
    target_state = client.get_state(session_id)
    result = family.judge(seed, session_id, response, target_state, ctx)

    assert not result.success, (
        f"REGRESSION: {entry['category']}/{entry['technique']} was marked fixed in "
        f"security_baseline.json but reproduced again. Evidence: {result.evidence}"
    )


def test_baseline_file_is_well_formed():
    baseline = _load_baseline()
    for entry in baseline:
        assert entry["category"] in FAMILY_BY_CATEGORY, f"unknown category in baseline: {entry}"
