"""Shared contracts for the Aravex attack -> defend -> verify loop."""
from .action import AgentAction, PolicyDecision, RuntimeFinding
from .common import DataClassification, DefenseLayer, Decision, FindingStatus, Severity
from .coverage import CATEGORY_LAYER, layer_for
from .finding import Finding
from .policy import PolicyProposal, ProposalStatus
from .verification import VerificationOutcome, VerificationResult, classify

__all__ = [
    "AgentAction", "PolicyDecision", "RuntimeFinding",
    "DataClassification", "DefenseLayer", "Decision", "FindingStatus", "Severity",
    "CATEGORY_LAYER", "layer_for",
    "Finding", "PolicyProposal", "ProposalStatus",
    "VerificationOutcome", "VerificationResult", "classify",
]
