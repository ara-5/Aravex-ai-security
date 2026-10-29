"""Proposals live in a JSON file. Approval is an explicit, recorded act."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from aravex_schemas import PolicyProposal, ProposalStatus


def save(path: Path, proposals: list[PolicyProposal]) -> None:
    path.write_text(json.dumps([p.model_dump(mode="json") for p in proposals], indent=2), encoding="utf-8")


def load(path: Path) -> list[PolicyProposal]:
    return [PolicyProposal.model_validate(p) for p in json.loads(path.read_text(encoding="utf-8"))]


def approve(proposals: list[PolicyProposal], ids: set[str] | None, reviewer: str) -> list[PolicyProposal]:
    """Approve the given ids (None = all drafts). Only drafts can be approved."""
    for p in proposals:
        if p.status is ProposalStatus.DRAFT and (ids is None or p.id in ids):
            p.status, p.reviewed_by = ProposalStatus.APPROVED, reviewer
    return proposals


def export_active_rules(proposals: list[PolicyProposal], path: Path) -> list[str]:
    """Write approved proposals as a gateway rules file; return the rule ids written.
    Drafts and rejected proposals are never exported."""
    rules = [yaml.safe_load(p.yaml_rule) for p in proposals
             if p.status in (ProposalStatus.APPROVED, ProposalStatus.ACTIVE) and p.yaml_rule]
    path.write_text(yaml.safe_dump({"rules": rules}, sort_keys=False), encoding="utf-8")
    return [r["name"] for r in rules]
