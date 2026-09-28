"""AegisAI Gateway -- the single choke point every agent action must pass
through before it touches a real tool, database, or external API.

    USER -> AI Gateway -> Security Policy Engine -> AI Agent -> RAG / Tools / MCP

Nothing downstream of this service should trust an agent's own claim that an
action is safe. This is where that claim gets checked.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from gateway.approvals.manager import ApprovalStatus, manager as approval_manager
from gateway.audit.logger import log_approval_resolution, log_decision
from gateway.identity.registry import registry
from gateway.models import ActionRequest, Decision, PolicyDecision
from gateway.policy.engine import engine
from gateway.telemetry import metrics
from gateway.telemetry.otel import get_tracer

app = FastAPI(
    title="AegisAI Gateway",
    description="Zero-trust runtime security gateway for autonomous AI agents.",
    version="0.1.0",
)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/metrics")
def metrics_endpoint() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/v1/agents")
def list_agents() -> list[dict]:
    return [a.model_dump() for a in registry.agents.values()]


@app.post("/v1/agent-action", response_model=PolicyDecision)
def agent_action(request: ActionRequest) -> PolicyDecision:
    """The zero-trust checkpoint. Every tool call an agent wants to make is
    submitted here first; only an ALLOW response authorizes execution."""
    tracer = get_tracer()
    with tracer.start_as_current_span("agent_action") as span:
        span.set_attribute("aegisai.agent_id", request.agent_id)
        span.set_attribute("aegisai.tool_id", request.tool_id)
        span.set_attribute("aegisai.action", request.action)
        span.set_attribute("aegisai.resource", request.resource)

        decision = engine.evaluate(request)

        span.set_attribute("aegisai.decision", decision.decision.value)
        span.set_attribute("aegisai.risk_score", decision.risk_score)

        if decision.decision == Decision.HUMAN_APPROVAL:
            record = approval_manager.create(request, decision)
            decision.approval_id = record.approval_id
            metrics.PENDING_APPROVALS.set(approval_manager.pending_count())

        log_decision(request, decision)
        metrics.record_decision(
            agent_id=request.agent_id,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            matched_rules=decision.matched_rules,
            findings=decision.findings,
        )

        return decision


class ApprovalResolutionRequest(BaseModel):
    approver: str
    approved: bool


@app.get("/v1/approvals")
def list_pending_approvals() -> list[dict]:
    return [r.model_dump() for r in approval_manager.list_pending()]


@app.get("/v1/approvals/{approval_id}")
def get_approval(approval_id: str) -> dict:
    record = approval_manager.get(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail="approval not found")
    return record.model_dump()


@app.post("/v1/approvals/{approval_id}/decision")
def resolve_approval(approval_id: str, body: ApprovalResolutionRequest) -> dict:
    record = approval_manager.get(approval_id)
    if record is None:
        raise HTTPException(status_code=404, detail="approval not found")
    if record.status != ApprovalStatus.PENDING:
        raise HTTPException(status_code=409, detail=f"approval already {record.status.value}")

    resolved = approval_manager.resolve(approval_id, body.approver, body.approved)
    metrics.PENDING_APPROVALS.set(approval_manager.pending_count())
    log_approval_resolution(approval_id, body.approver, body.approved, resolved.decision)
    return resolved.model_dump()
