"""Structured, append-only audit trail.

Every decision the policy engine makes is written as a single JSON line to
logs/audit.log (and echoed to stdout). That format is the integration point
for a SIEM: point Splunk/Elastic/whatever's log-shipping agent at the file
(or swap the stdlib handler below for a syslog/HTTP handler) and every
ALLOW/DENY/HUMAN_APPROVAL becomes a searchable, alertable event with no
extra glue code.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import structlog

from gateway.models import ActionRequest, PolicyDecision

LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
LOG_FILE = LOG_DIR / "audit.log"

_configured = False


def _configure() -> None:
    global _configured
    if _configured:
        return
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    stream_handler = logging.StreamHandler(sys.stdout)
    logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler], format="%(message)s")

    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger():
    _configure()
    return structlog.get_logger("aegisai.audit")


SEVERITY_BY_DECISION = {
    "ALLOW": "info",
    "HUMAN_APPROVAL": "warning",
    "DENY": "warning",
}


def log_decision(request: ActionRequest, decision: PolicyDecision) -> None:
    log = get_logger()
    severity = SEVERITY_BY_DECISION.get(decision.decision.value, "info")
    # Escalate: a DENY driven by a security rule (not just a routine
    # permission gap) or a high-risk score is worth flagging as a security
    # alert an analyst should actually look at.
    is_security_alert = decision.decision.value == "DENY" and (
        decision.matched_rules or decision.risk_score >= 0.75 or any(
            f.category in ("dlp", "prompt_injection", "anomaly") for f in decision.findings
        )
    )

    event = "security_alert" if is_security_alert else "policy_decision"
    log_fn = getattr(log, severity)
    log_fn(
        event,
        request_id=decision.request_id,
        human_id=request.human_id,
        agent_id=request.agent_id,
        tool_id=request.tool_id,
        action=request.action,
        resource=request.resource,
        data_classification=request.data_classification.value,
        record_count=request.record_count,
        destination=request.destination,
        decision=decision.decision.value,
        risk_score=round(decision.risk_score, 3),
        matched_rules=decision.matched_rules,
        findings=[f"{f.category}:{f.detail}" for f in decision.findings],
        reasons=decision.reasons,
    )


def log_approval_resolution(approval_id: str, approver: str, approved: bool, decision: PolicyDecision) -> None:
    log = get_logger()
    log.warning(
        "human_approval_resolved",
        approval_id=approval_id,
        approver=approver,
        approved=approved,
        request_id=decision.request_id,
        agent_id=decision.agent_id,
        action=decision.action,
        resource=decision.resource,
    )
