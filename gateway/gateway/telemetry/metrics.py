"""Prometheus metrics for the gateway.

Scraped by Prometheus (see prometheus/prometheus.yml) and visualized in
Grafana. This is the surface an on-call engineer or a SIEM correlation rule
would actually watch in production.
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

REQUESTS_TOTAL = Counter(
    "aegisai_requests_total",
    "Total agent action requests evaluated by the policy engine.",
    ["agent_id", "decision"],
)

RULE_MATCHES_TOTAL = Counter(
    "aegisai_rule_matches_total",
    "Number of times each declarative policy rule fired.",
    ["rule_name", "decision"],
)

SECURITY_FINDINGS_TOTAL = Counter(
    "aegisai_security_findings_total",
    "Security findings raised by detectors (DLP, prompt injection, anomaly).",
    ["category"],
)

RISK_SCORE = Histogram(
    "aegisai_risk_score",
    "Distribution of computed risk scores.",
    buckets=(0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.75, 0.85, 0.9, 1.0),
)

PENDING_APPROVALS = Gauge(
    "aegisai_pending_approvals",
    "Number of actions currently awaiting human approval.",
)


def record_decision(agent_id: str, decision: str, risk_score: float, matched_rules: list[str], findings: list) -> None:
    REQUESTS_TOTAL.labels(agent_id=agent_id, decision=decision).inc()
    RISK_SCORE.observe(risk_score)
    for rule_name in matched_rules:
        RULE_MATCHES_TOTAL.labels(rule_name=rule_name, decision=decision).inc()
    for finding in findings:
        SECURITY_FINDINGS_TOTAL.labels(category=finding.category).inc()
