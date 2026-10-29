from __future__ import annotations

from gateway.models import ActionRequest, DataClassification
from gateway.policy.risk import compute_risk


def _request(**overrides) -> ActionRequest:
    defaults = dict(
        human_id="h-jane-owner",
        agent_id="customer-support-agent",
        tool_id="customer_db_tool",
        action="read",
        resource="customer_db.profile",
    )
    defaults.update(overrides)
    return ActionRequest(**defaults)


def test_higher_severity_action_scores_higher():
    read_score, _ = compute_risk(_request(action="read"), 0, 0, 0)
    delete_score, _ = compute_risk(_request(action="delete"), 0, 0, 0)
    assert delete_score > read_score


def test_record_volume_increases_risk():
    low, _ = compute_risk(_request(record_count=1), 0, 0, 0)
    high, _ = compute_risk(_request(record_count=100000), 0, 0, 0)
    assert high > low


def test_highly_sensitive_classification_increases_risk():
    internal, _ = compute_risk(_request(data_classification=DataClassification.INTERNAL), 0, 0, 0)
    sensitive, _ = compute_risk(_request(data_classification=DataClassification.HIGHLY_SENSITIVE), 0, 0, 0)
    assert sensitive > internal


def test_score_is_clamped_to_unit_interval():
    score, _ = compute_risk(_request(action="delete", record_count=10_000_000), 0.6, 0.5, 0.5)
    assert 0.0 <= score <= 1.0
