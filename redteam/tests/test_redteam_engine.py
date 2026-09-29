"""
End-to-end test of the red-team engine's agentic loop, wired directly to
the target agent's FastAPI app over an in-process ASGI transport (no real
sockets/servers needed) so this runs fast and deterministically in CI.
"""
from fastapi.testclient import TestClient

import target_agent.main as target_main
from redteam_engine.attacks import FAMILY_BY_CATEGORY
from redteam_engine.db import Base as RedteamBase, engine as redteam_engine_sqla, SessionLocal, Finding
from redteam_engine.planner import AttackPlanner
from redteam_engine.regression import run_regression
from redteam_engine.target_client import TargetClient


def _make_client() -> TargetClient:
    target_main.startup()  # init_db() + load_seed_data() for the target agent
    # TestClient is an httpx.Client subclass wired straight to the ASGI
    # app in-process (sync-safe, unlike a bare ASGITransport) — no real
    # sockets or a running server needed for these tests.
    test_client = TestClient(target_main.app)
    return TargetClient(base_url="http://testserver", client=test_client)


def _fresh_redteam_db():
    RedteamBase.metadata.drop_all(redteam_engine_sqla)
    RedteamBase.metadata.create_all(redteam_engine_sqla)


def test_system_prompt_extraction_family_produces_a_finding():
    _fresh_redteam_db()
    client = _make_client()
    client.reset()
    planner = AttackPlanner(client)
    campaign_id = planner.run_campaign("test-spe", categories=["system_prompt_extraction"])

    db = SessionLocal()
    try:
        findings = db.query(Finding).filter(Finding.campaign_id == campaign_id).all()
    finally:
        db.close()
    assert len(findings) > 0
    assert findings[0].category == "system_prompt_extraction"
    assert findings[0].severity == "critical"


def test_regression_flips_to_pass_after_a_real_fix():
    _fresh_redteam_db()
    client = _make_client()
    client.reset()
    planner = AttackPlanner(client)
    campaign_id = planner.run_campaign("test-mcp", categories=["mcp_attacks"])

    db = SessionLocal()
    try:
        finding = (
            db.query(Finding)
            .filter(Finding.campaign_id == campaign_id, Finding.technique == "mcp_credential_exposure")
            .first()
        )
    finally:
        db.close()
    assert finding is not None

    # Confirm it currently reproduces.
    result = run_regression(finding.id, client)
    assert result["outcome"] == "FAIL"

    # Apply the real fix: require a verified scope before issuing a token.
    from target_agent import mcp_tools as mcp

    original = mcp._get_service_token

    def patched(session_id: str) -> str:
        if mcp.MCP_SESSION_SCOPE.get(session_id) != "admin:*":
            return "[get_service_token] denied: no verified authorization for this session"
        return original(session_id)

    mcp._get_service_token = patched
    try:
        result = run_regression(finding.id, client)
        assert result["outcome"] == "PASS"
    finally:
        mcp._get_service_token = original


def test_score_history_and_security_report():
    _fresh_redteam_db()
    client = _make_client()
    client.reset()
    planner = AttackPlanner(client)
    planner.run_campaign("test-report", categories=["system_prompt_extraction"])

    from redteam_engine.scorecard import get_score_history
    from redteam_engine.report import generate_security_report_markdown

    history = get_score_history()
    assert len(history) >= 1
    assert history[-1]["trigger"] == "campaign"
    assert 0.0 <= history[-1]["overall_score"] <= 10.0

    report_md = generate_security_report_markdown(scope="open")
    assert "# AgentShield Security Report" in report_md
    assert "System Prompt Extraction" in report_md
    assert "**Attack**" in report_md and "**Evidence**" in report_md
    assert "**Impact**" in report_md and "**Remediation**" in report_md


def test_all_attack_families_are_registered_and_seedable():
    assert len(FAMILY_BY_CATEGORY) == 11
    client = _make_client()
    from redteam_engine.attacks.base import AttackContext

    ctx = AttackContext(client=client, canaries=client.get_canaries(), campaign_session_prefix="seedcheck")
    for category, family in FAMILY_BY_CATEGORY.items():
        seeds = family.seeds(ctx)
        assert len(seeds) > 0, f"{category} has no seed attacks"
