"""AgentShield — red-team engine FastAPI app + dashboard."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI, BackgroundTasks, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from redteam_engine.config import PORT, CATEGORY_LABELS, REDTEAM_API_KEY
from redteam_engine.db import init_db, SessionLocal, Campaign, AttackAttempt, Finding
from redteam_engine.planner import AttackPlanner
from redteam_engine.report import generate_security_report_markdown
from redteam_engine.scorecard import compute_scorecard, get_score_history
from redteam_engine.regression import run_regression, run_all_regressions
from redteam_engine.target_client import TargetClient

import observability

app = FastAPI(title="AgentShield — Autonomous AI Agent Red-Team Platform")
observability.setup_tracing("agentshield-redteam-engine", app)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
def startup():
    init_db()


def require_api_key(x_api_key: str | None = Header(default=None)):
    """Gates write endpoints only when REDTEAM_API_KEY is configured --
    empty (default) keeps local/CI/dashboard use frictionless."""
    if REDTEAM_API_KEY and x_api_key != REDTEAM_API_KEY:
        raise HTTPException(status_code=401, detail="missing/invalid X-API-Key")


@app.get("/health")
def health():
    return {"status": "ok", "target_reachable": TargetClient().health()}


@app.get("/")
def dashboard():
    return FileResponse(str(STATIC_DIR / "dashboard.html"))


class CampaignRequest(BaseModel):
    name: str = "AgentShield campaign"
    categories: list[str] | None = None
    reset_target: bool = True


def _run_campaign_bg(name: str, categories: list[str] | None, reset_target: bool):
    client = TargetClient()
    if reset_target:
        try:
            client.reset()
        except Exception:
            pass
    AttackPlanner(client).run_campaign(name, categories)


@app.post("/campaigns/run", dependencies=[Depends(require_api_key)])
def run_campaign(req: CampaignRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(_run_campaign_bg, req.name, req.categories, req.reset_target)
    return {"status": "started", "categories": req.categories or list(CATEGORY_LABELS.keys())}


@app.get("/campaigns")
def list_campaigns():
    db = SessionLocal()
    try:
        rows = db.query(Campaign).order_by(Campaign.id.desc()).limit(20).all()
        return [
            {
                "id": c.id, "name": c.name, "status": c.status,
                "started_at": str(c.started_at), "finished_at": str(c.finished_at) if c.finished_at else None,
                "categories": json.loads(c.categories or "[]"),
            }
            for c in rows
        ]
    finally:
        db.close()


@app.get("/campaigns/{campaign_id}")
def campaign_detail(campaign_id: int):
    db = SessionLocal()
    try:
        c = db.query(Campaign).filter(Campaign.id == campaign_id).first()
        if not c:
            return {"error": "not found"}
        attempts = db.query(AttackAttempt).filter(AttackAttempt.campaign_id == campaign_id).order_by(AttackAttempt.id).all()
        return {
            "id": c.id, "name": c.name, "status": c.status,
            "attempts": [
                {
                    "category": a.category, "technique": a.technique, "generation": a.generation,
                    "success": a.success, "severity": a.severity, "confidence": a.confidence,
                    "evidence": a.evidence, "payload": a.payload,
                    "llm_judge_verdict": a.llm_judge_verdict, "llm_judge_rationale": a.llm_judge_rationale,
                }
                for a in attempts
            ],
        }
    finally:
        db.close()


@app.get("/scorecard")
def scorecard():
    return compute_scorecard()


@app.get("/scorecard/history")
def scorecard_history(limit: int = 200):
    return get_score_history(limit=limit)


@app.get("/findings")
def list_findings(status: str | None = None):
    db = SessionLocal()
    try:
        q = db.query(Finding)
        if status:
            q = q.filter(Finding.status == status)
        rows = q.order_by(Finding.id.desc()).all()
        return [
            {
                "id": f.id, "category": f.category, "technique": f.technique, "severity": f.severity,
                "title": f.title, "status": f.status, "last_regression_result": f.last_regression_result,
                "created_at": str(f.created_at),
            }
            for f in rows
        ]
    finally:
        db.close()


@app.get("/findings/{finding_id}")
def finding_detail(finding_id: int):
    db = SessionLocal()
    try:
        f = db.query(Finding).filter(Finding.id == finding_id).first()
        if not f:
            return {"error": "not found"}
        return {
            "id": f.id, "category": f.category, "technique": f.technique, "severity": f.severity,
            "title": f.title, "status": f.status,
            "attack_payload": f.attack_payload,
            "evidence": f.evidence,
            "impact": f.impact,
            "remediation": f.remediation,
            "last_regression_result": f.last_regression_result,
            "last_regression_at": str(f.last_regression_at) if f.last_regression_at else None,
        }
    finally:
        db.close()


@app.post("/findings/{finding_id}/regression", dependencies=[Depends(require_api_key)])
def regress_finding(finding_id: int):
    return run_regression(finding_id)


@app.post("/regression/run-all", dependencies=[Depends(require_api_key)])
def regress_all():
    return {"results": run_all_regressions()}


@app.get("/reports/security")
def security_report(scope: str = "all"):
    md = generate_security_report_markdown(scope=scope)
    return PlainTextResponse(
        md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=agentshield-security-report.md"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("redteam_engine.main:app", host="0.0.0.0", port=PORT, reload=False)
