"""Composable risk scoring.

Combines several independent signals -- action severity, data sensitivity,
record volume, destination, and live security findings (DLP, prompt
injection, behavioral anomaly) -- into a single [0, 1] score with a
human-readable breakdown. The score is what drives the ALLOW / HUMAN_APPROVAL
/ DENY fallback when no explicit rule already decided the outcome.
"""
from __future__ import annotations

import math

from gateway.models import ActionRequest, DataClassification

ACTION_BASE_RISK: dict[str, float] = {
    "read": 0.05,
    "list": 0.05,
    "send": 0.15,
    "update": 0.25,
    "write": 0.3,
    "export": 0.5,
    "delete": 0.7,
    "admin": 0.9,
}
DEFAULT_ACTION_RISK = 0.3

CLASSIFICATION_RISK: dict[DataClassification, float] = {
    DataClassification.PUBLIC: 0.0,
    DataClassification.INTERNAL: 0.05,
    DataClassification.SENSITIVE: 0.2,
    DataClassification.HIGHLY_SENSITIVE: 0.4,
}

DESTINATION_RISK: dict[str, float] = {
    "external_api": 0.25,
    "email": 0.1,
    "internal": 0.0,
}


def _volume_risk(record_count: int) -> float:
    if record_count <= 1:
        return 0.0
    return min(0.4, math.log10(record_count) * 0.15)


def compute_risk(
    request: ActionRequest,
    dlp_score: float,
    injection_score: float,
    anomaly_score: float,
) -> tuple[float, list[str]]:
    reasons: list[str] = []

    score = ACTION_BASE_RISK.get(request.action, DEFAULT_ACTION_RISK)
    reasons.append(f"base risk for action '{request.action}': +{score:.2f}")

    classification_risk = CLASSIFICATION_RISK.get(request.data_classification, 0.2)
    if classification_risk:
        reasons.append(
            f"data classification {request.data_classification.value}: +{classification_risk:.2f}"
        )
    score += classification_risk

    volume_risk = _volume_risk(request.record_count)
    if volume_risk:
        reasons.append(f"record volume {request.record_count}: +{volume_risk:.2f}")
    score += volume_risk

    destination_risk = DESTINATION_RISK.get(request.destination, 0.05)
    if destination_risk:
        reasons.append(f"destination '{request.destination}': +{destination_risk:.2f}")
    score += destination_risk

    if dlp_score:
        reasons.append(f"DLP findings in payload: +{dlp_score:.2f}")
    score += dlp_score

    if injection_score:
        reasons.append(f"prompt-injection indicators: +{injection_score:.2f}")
    score += injection_score

    if anomaly_score:
        reasons.append(f"behavioral anomaly: +{anomaly_score:.2f}")
    score += anomaly_score

    return max(0.0, min(1.0, score)), reasons
