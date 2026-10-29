"""Translate rules.yaml-style rules into Rego for a real OPA server.

The local YAML matcher (engine.Rule) and OPA must agree on every rule, so
this module covers exactly the conditions engine.Rule supports and refuses
anything else rather than guess. Parity is tested against both evaluators.

Generated rules extend the static guardrails.rego through three partial sets
it declares (generated_deny, generated_approval, generated_reasons).
"""
from __future__ import annotations

import re

PACKAGE_HEADER = "package aegisai.guardrails\n\nimport rego.v1\n"
POLICY_ID = "aravex_generated"

_SUPPORTED = {"agent_id", "action", "resource_matches", "record_count_gt", "data_classification", "destination"}
_EFFECT_SET = {"DENY": "generated_deny", "HUMAN_APPROVAL": "generated_approval"}
_NAME = re.compile(r"^[A-Za-z0-9_]+$")


class UnsupportedRule(ValueError):
    pass


def _s(value: str) -> str:
    """A Rego string literal. JSON string escaping is valid Rego."""
    import json

    return json.dumps(value)


def _conditions(when: dict) -> list[str]:
    unknown = set(when) - _SUPPORTED
    if unknown:
        raise UnsupportedRule(f"unsupported condition(s): {sorted(unknown)}")
    out: list[str] = []
    if "agent_id" in when:
        out.append(f"input.agent_id == {_s(when['agent_id'])}")
    if "action" in when:
        actions = when["action"] if isinstance(when["action"], list) else [when["action"]]
        out.append(f"input.action in {{{', '.join(_s(a) for a in actions)}}}")
    if "resource_matches" in when:
        # The YAML matcher is re.search with IGNORECASE; regex.match is a search too.
        out.append(f"regex.match({_s('(?i)' + when['resource_matches'])}, input.resource)")
    if "record_count_gt" in when:
        out.append(f"input.record_count > {int(when['record_count_gt'])}")
    if "data_classification" in when:
        out.append(f"input.data_classification == {_s(when['data_classification'])}")
    if "destination" in when:
        out.append(f"input.destination == {_s(when['destination'])}")
    if not out:
        raise UnsupportedRule("a rule with no conditions would match everything")
    return out


def rule_to_rego(rule: dict) -> str:
    """Rego for one rule dict ({name, when, then, reason}); no package header."""
    name, effect = rule["name"], rule["then"]
    if not _NAME.match(name):
        raise UnsupportedRule(f"rule name must be [A-Za-z0-9_]+: {name!r}")
    if effect not in _EFFECT_SET:
        raise UnsupportedRule(f"cannot export effect {effect!r}")
    body = "\n".join(f"\t{c}" for c in _conditions(rule["when"]))
    return (f"{_EFFECT_SET[effect]} contains {_s(name)} if {{\n{body}\n}}\n\n"
            f"generated_reasons[{_s(name)}] := {_s(rule.get('reason', ''))}\n")


def rules_to_rego(rules: list[dict]) -> str:
    """A complete Rego module for the given rules (empty list gives a valid no-op module)."""
    return PACKAGE_HEADER + "".join("\n" + rule_to_rego(r) for r in rules)
