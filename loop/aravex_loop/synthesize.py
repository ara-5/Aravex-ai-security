"""Turn the actions behind a successful attack into candidate gateway rules.

Principles:
  * Narrow: a rule keys on the agent, the action, the resource category and,
    where it matters, destination and data classification. Never a blanket
    block on a whole tool.
  * Safe to propose, not to apply: every rule is a draft for a human to approve.
  * Checked against benign work: a rule that would match a known-benign action
    is rejected, since blocking normal use is not a fix.
  * Conservative effect: the most dangerous classes (credentials, privilege
    changes, bulk export) are DENY; everything else asks a human
    (HUMAN_APPROVAL) rather than silently blocking.
"""
from __future__ import annotations

import re

import yaml

from aravex_schemas import Decision, DefenseLayer, PolicyProposal, layer_for

_DENY_CATEGORIES = {"secrets", "iam"}


from gateway.policy import rego_export  # noqa: E402  (gateway is on the path; see pytest.ini)


def _category(resource: str) -> str:
    return resource.split(".", 1)[0]


def effect_for(action: dict) -> Decision:
    if _category(action["resource"]) in _DENY_CATEGORIES or action["action"] == "export":
        return Decision.DENY
    return Decision.HUMAN_APPROVAL


def rule_from_action(action: dict, agent_id: str, name: str, reason: str) -> dict:
    when: dict = {
        "agent_id": agent_id,
        "action": action["action"],
        "resource_matches": f"^{re.escape(_category(action['resource']))}\\.",
    }
    destination = action.get("destination", "internal")
    if destination != "internal":
        when["destination"] = destination
        if action.get("data_classification") in ("SENSITIVE", "HIGHLY_SENSITIVE"):
            when["data_classification"] = action["data_classification"]
    return {"name": name, "when": when, "then": effect_for(action).value, "reason": reason}


def matches(rule: dict, action: dict, agent_id: str) -> bool:
    """Evaluate a rule with the gateway's own matcher, so there is one definition of 'match'."""
    from gateway.models import ActionRequest
    from gateway.policy.engine import Rule

    fields = {k: v for k, v in action.items()
              if k in ActionRequest.model_fields and k not in ('agent_id', 'human_id')}
    request = ActionRequest(human_id="h-jane-owner", agent_id=agent_id, **fields)
    return Rule(**rule).matches(request)


def signature(action: dict) -> tuple:
    return (action["action"], _category(action["resource"]),
            action.get("destination", "internal"), action.get("data_classification", "INTERNAL"))


def propose(finding_id: str, title: str, category: str, agent_id: str,
            allowed_actions: list[dict], benign: list[dict]) -> tuple[list[PolicyProposal], list[str]]:
    """Return (proposals, notes). ``allowed_actions`` are the actions the attack
    got executed, i.e. ones the current policy let through."""
    if layer_for(category) is DefenseLayer.MODEL:
        return [], [f"{category}: happens inside the model; a gateway rule cannot address it"]
    if not allowed_actions:
        return [], [f"{category}: attack succeeded without any gateway-visible action"]

    notes: list[str] = []
    proposals: list[PolicyProposal] = []
    seen: set[tuple] = set()
    for action in allowed_actions:
        sig = signature(action)
        if sig in seen:
            continue
        seen.add(sig)
        n = len(seen)
        rule_id = f"aravex_gen_{finding_id}_{n}"
        rule = rule_from_action(action, agent_id, rule_id, f"Generated from finding #{finding_id}: {title}")
        blocked = [b for b in benign if matches(rule, b, agent_id)]
        if blocked:
            notes.append(f"{rule_id} rejected: would also block benign {blocked[0]['action']} "
                         f"on {blocked[0]['resource']}")
            continue
        proposals.append(PolicyProposal(
            id=f"prop-{finding_id}-{n}", finding_id=str(finding_id), rule_id=rule_id,
            effect=Decision(rule["then"]),
            rationale=f"{action['action']} on {_category(action['resource'])} "
                      f"(destination {action.get('destination', 'internal')}) was executed during a "
                      f"successful '{category}' attack.",
            yaml_rule=yaml.safe_dump(rule, sort_keys=False),
            rego=rego_export.rule_to_rego(rule)))
    return proposals, notes
