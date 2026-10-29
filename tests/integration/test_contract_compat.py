"""The shared contracts must accept what the two source projects already produce."""
import re
from pathlib import Path

from aravex_schemas import AgentAction, CATEGORY_LAYER, Finding, PolicyDecision

ROOT = Path(__file__).resolve().parents[2]


def test_gateway_action_request_validates_as_agent_action():
    from gateway.models import ActionRequest

    req = ActionRequest(human_id="h", agent_id="a", tool_id="email", action="send",
                        resource="mail", record_count=3)
    assert AgentAction.model_validate(req.model_dump()).record_count == 3


def test_gateway_decision_validates_as_policy_decision():
    from gateway.models import Decision, PolicyDecision as GwDecision, SecurityFinding

    d = GwDecision(request_id="1", agent_id="a", action="x", resource="r",
                   decision=Decision.HUMAN_APPROVAL, risk_score=0.7,
                   findings=[SecurityFinding(category="dlp", detail="ssn")])
    out = PolicyDecision.model_validate(d.model_dump())
    assert out.decision.value == "HUMAN_APPROVAL"
    assert out.findings[0].category == "dlp"


def test_redteam_finding_row_validates_as_finding():
    # Shape of redteam_engine.db.Finding columns (SQLAlchemy model, not imported here).
    row = dict(id="7", category="mcp_attacks", technique="credential_exposure",
               severity="critical", title="MCP leaks credentials",
               attack_payload="...", evidence="token seen", impact="takeover",
               remediation="redact", status="resolved", last_regression_result="PASS")
    assert Finding.model_validate(row).status.value == "resolved"


def test_category_map_matches_redteam_attack_families():
    found = set()
    for p in (ROOT / "redteam" / "redteam_engine" / "attacks").glob("*.py"):
        m = re.search(r'^\s+category = "(\w+)"', p.read_text(encoding="utf8"), re.M)
        if m:
            found.add(m.group(1))
    assert found == set(CATEGORY_LAYER), f"drift: {found ^ set(CATEGORY_LAYER)}"
