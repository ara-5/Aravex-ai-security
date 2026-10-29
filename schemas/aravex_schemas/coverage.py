"""Which attack categories a runtime gateway can address.

This is a design claim, not a measured result: it says where a defense can
live. Measured effectiveness comes from ``VerificationResult``. Keeping the
two separate stops the project from reporting "the gateway blocks everything".
"""
from __future__ import annotations

from .common import DefenseLayer

CATEGORY_LAYER: dict[str, DefenseLayer] = {
    # Unsafe step is an observable action.
    "tool_poisoning": DefenseLayer.GATEWAY,
    "mcp_attacks": DefenseLayer.GATEWAY,
    "privilege_escalation": DefenseLayer.GATEWAY,
    "excessive_agency": DefenseLayer.GATEWAY,
    "data_exfiltration": DefenseLayer.GATEWAY,
    "agent_to_agent": DefenseLayer.GATEWAY,
    # Gateway limits the damage but cannot stop the injection itself.
    "prompt_injection": DefenseLayer.PARTIAL,
    "rag_poisoning": DefenseLayer.PARTIAL,
    "memory_poisoning": DefenseLayer.PARTIAL,
    # Happens inside the model's output.
    "jailbreak": DefenseLayer.MODEL,
    "system_prompt_extraction": DefenseLayer.MODEL,
}


def layer_for(category: str) -> DefenseLayer:
    """Unknown categories default to MODEL: never claim gateway coverage unasserted."""
    return CATEGORY_LAYER.get(category, DefenseLayer.MODEL)
