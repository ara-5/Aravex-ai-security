"""The Security Policy Engine.

For every action an agent wants to perform, this answers: who is
requesting, which agent, what permissions, what resource, what action, what
data, what's the risk, and finally ALLOW / DENY / HUMAN_APPROVAL.

Evaluation order:
  1. Resolve identity chain (agent must exist, tool must be authorized for it).
  2. Evaluate explicit declarative rules (rules.yaml) -- first match wins and
     short-circuits everything below. These are hard guardrails.
  3. IAM permission check (does the agent's permission grant cover this
     resource + action).
  4. Run DLP / prompt-injection / anomaly detectors, fold their scores into
     the composite risk score.
  5. Threshold the risk score into ALLOW / HUMAN_APPROVAL / DENY.

Every path returns a PolicyDecision with a full reasoning trail so the
decision is always explainable, never a black box.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from gateway.identity.registry import IdentityRegistry, registry as default_registry
from gateway.models import ActionRequest, Decision, PolicyDecision, SecurityFinding
from gateway.policy import risk as risk_module
from gateway.security import anomaly as anomaly_module
from gateway.security import dlp as dlp_module
from gateway.security import prompt_injection as injection_module

DEFAULT_RULES_PATH = Path(__file__).parent / "rules.yaml"

RISK_HUMAN_APPROVAL_THRESHOLD = 0.4
RISK_DENY_THRESHOLD = 0.75


@dataclass
class Rule:
    name: str
    when: dict
    then: str
    reason: str

    def matches(self, request: ActionRequest) -> bool:
        w = self.when
        if "agent_id" in w and request.agent_id != w["agent_id"]:
            return False
        if "action" in w:
            actions = w["action"] if isinstance(w["action"], list) else [w["action"]]
            if request.action not in actions:
                return False
        if "resource_matches" in w and not re.search(w["resource_matches"], request.resource, re.IGNORECASE):
            return False
        if "record_count_gt" in w and not (request.record_count > w["record_count_gt"]):
            return False
        if "data_classification" in w and request.data_classification.value != w["data_classification"]:
            return False
        if "destination" in w and request.destination != w["destination"]:
            return False
        return True


def load_rules(path: Path | str = DEFAULT_RULES_PATH) -> list[Rule]:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    return [Rule(**r) for r in raw.get("rules", [])]


class PolicyEngine:
    def __init__(
        self,
        identity_registry: IdentityRegistry = default_registry,
        rules: list[Rule] | None = None,
        anomaly_tracker: anomaly_module.AnomalyTracker = anomaly_module.tracker,
    ):
        self.registry = identity_registry
        self.rules = rules if rules is not None else load_rules()
        self.anomaly_tracker = anomaly_tracker

    def _security_findings(self, request: ActionRequest) -> tuple[list[SecurityFinding], float, float, float]:
        dlp_hits, dlp_score = dlp_module.scan(request.payload_preview)
        injection_hits, injection_score = injection_module.scan(request.payload_preview)
        anomaly_hits, anomaly_score = self.anomaly_tracker.evaluate(request.agent_id)

        findings = (
            [SecurityFinding(category="dlp", detail=h) for h in dlp_hits]
            + [SecurityFinding(category="prompt_injection", detail=h) for h in injection_hits]
            + [SecurityFinding(category="anomaly", detail=h) for h in anomaly_hits]
        )
        return findings, dlp_score, injection_score, anomaly_score

    def _decision(
        self,
        request: ActionRequest,
        decision: Decision,
        reasons: list[str],
        matched_rules: list[str] | None = None,
        findings: list[SecurityFinding] | None = None,
        risk_score: float | None = None,
    ) -> PolicyDecision:
        if risk_score is None:
            sec_findings, dlp_score, injection_score, anomaly_score = self._security_findings(request)
            risk_score, risk_reasons = risk_module.compute_risk(request, dlp_score, injection_score, anomaly_score)
            reasons = reasons + risk_reasons
            findings = (findings or []) + sec_findings

        if decision == Decision.DENY:
            self.anomaly_tracker.record_denial(request.agent_id)

        return PolicyDecision(
            request_id=request.request_id,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            decision=decision,
            risk_score=risk_score,
            reasons=reasons,
            matched_rules=matched_rules or [],
            findings=findings or [],
        )

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        self.anomaly_tracker.record_call(request.agent_id)

        # 1. Identity resolution
        agent = self.registry.get_agent(request.agent_id)
        if agent is None:
            return self._decision(
                request, Decision.DENY, [f"unknown agent identity '{request.agent_id}'"], risk_score=1.0
            )

        tool = self.registry.get_tool(request.tool_id)
        if tool is None or not self.registry.tool_authorized_for_agent(agent, request.tool_id):
            return self._decision(
                request,
                Decision.DENY,
                [f"tool '{request.tool_id}' is not authorized for agent '{request.agent_id}'"],
                risk_score=0.9,
            )

        # 2. Explicit declarative rules (hard guardrails, first match wins)
        for rule in self.rules:
            if rule.matches(request):
                return self._decision(
                    request,
                    Decision(rule.then),
                    [f"rule '{rule.name}': {rule.reason}"],
                    matched_rules=[rule.name],
                )

        # 3. IAM permission check
        if not self.registry.has_permission(agent, request.resource, request.action):
            return self._decision(
                request,
                Decision.DENY,
                [
                    f"agent '{request.agent_id}' lacks permission for "
                    f"action '{request.action}' on resource '{request.resource}'"
                ],
                risk_score=0.85,
            )

        # 4 & 5. Security scans + risk-score threshold fallback
        findings, dlp_score, injection_score, anomaly_score = self._security_findings(request)
        risk_score, risk_reasons = risk_module.compute_risk(request, dlp_score, injection_score, anomaly_score)

        if risk_score >= RISK_DENY_THRESHOLD:
            decision = Decision.DENY
        elif risk_score >= RISK_HUMAN_APPROVAL_THRESHOLD:
            decision = Decision.HUMAN_APPROVAL
        else:
            decision = Decision.ALLOW

        return self._decision(request, decision, risk_reasons, findings=findings, risk_score=risk_score)


engine = PolicyEngine()
