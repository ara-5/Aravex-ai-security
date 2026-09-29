"""Durable, queryable audit trail -- an additive dual-write alongside the
structured JSON log (gateway/audit/logger.py), never a replacement for it.

The JSON log is the SIEM integration point and stays the audit-of-record.
This table exists so a question like "how many DENYs did billing-agent get
this week" is a SQL query instead of a script that tails and parses a log
file. Deliberately best-effort: a Postgres outage logs a warning and the
request still completes -- the JSON log has already captured the decision
by the time this runs, so audit integrity never depends on this table being
up.

Only active when DATABASE_URL is set; a no-op otherwise, same pattern as
the OPA and Redis integrations.

Uses a pooled connection (psycopg_pool), not one TCP connection + full
Postgres auth handshake per request -- an earlier version of this module
did that, and a load test (scripts/loadtest.py) caught it immediately:
p50 latency went from single-digit milliseconds to over two seconds under
concurrency 20, because the FastAPI thread pool was mostly blocked on
connection setup instead of the actual insert. Real numbers found a real
bug; see README.md's Performance section for the before/after.
"""
from __future__ import annotations

import json
import logging
import os
import threading

from gateway.models import ActionRequest, PolicyDecision

_log = logging.getLogger("aegisai.audit.postgres")

_schema_ready = False
_schema_lock = threading.Lock()

_pool = None
_pool_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    human_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    data_classification TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    destination TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL,
    matched_rules JSONB NOT NULL,
    findings JSONB NOT NULL,
    reasons JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_agent_id_idx ON decisions (agent_id);
CREATE INDEX IF NOT EXISTS decisions_decision_idx ON decisions (decision);
CREATE INDEX IF NOT EXISTS decisions_occurred_at_idx ON decisions (occurred_at);
"""

INSERT = """
INSERT INTO decisions (
    request_id, human_id, agent_id, tool_id, action, resource,
    data_classification, record_count, destination, decision, risk_score,
    matched_rules, findings, reasons
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def is_configured() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                from psycopg_pool import ConnectionPool

                _pool = ConnectionPool(os.environ["DATABASE_URL"], min_size=1, max_size=10, open=True)
    return _pool


def _ensure_schema() -> None:
    global _schema_ready
    if _schema_ready:
        return
    with _schema_lock:
        if _schema_ready:
            return
        with _get_pool().connection() as conn:
            conn.execute(SCHEMA)
            conn.commit()
        _schema_ready = True


def reset_schema_cache() -> None:
    """Test hook: forces the next write_decision() to re-run _ensure_schema()."""
    global _schema_ready
    _schema_ready = False


def write_decision(request: ActionRequest, decision: PolicyDecision) -> None:
    if not is_configured():
        return
    try:
        _ensure_schema()
        with _get_pool().connection() as conn:
            conn.execute(
                INSERT,
                (
                    decision.request_id,
                    request.human_id,
                    request.agent_id,
                    request.tool_id,
                    request.action,
                    request.resource,
                    request.data_classification.value,
                    request.record_count,
                    request.destination,
                    decision.decision.value,
                    decision.risk_score,
                    json.dumps(decision.matched_rules),
                    json.dumps([f"{f.category}:{f.detail}" for f in decision.findings]),
                    json.dumps(decision.reasons),
                ),
            )
            conn.commit()
    except Exception as exc:  # noqa: BLE001 -- best-effort; the JSON log is already the audit-of-record
        _log.warning("Failed to write audit decision to Postgres: %s", exc)
