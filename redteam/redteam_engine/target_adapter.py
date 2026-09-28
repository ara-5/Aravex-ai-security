"""
The Target Adapter contract — what AgentShield actually needs from a
"thing to attack".

`TargetClient` (target_client.py) is the reference implementation, wired
to this repo's own target_agent. It happens to be the richest possible
adapter: it can ingest documents, dump memory, and introspect full tool/
MCP state, because we own the target and built those hooks in on purpose.

A real third-party agent won't expose any of that. `GenericChatAdapter`
below is the other extreme: it implements this exact same Protocol against
nothing but a bare chat endpoint, with every introspection method
returning empty/no-op — and it needs ZERO changes to any AttackFamily to
work, because every judge already treats target_state/tool_calls/memory as
"whatever's there, possibly nothing" rather than assuming a specific
shape. That's what "pluggable" means in practice here: swap the adapter,
keep every attack family, lose only the ground-truth judging that needs
introspection the target can't offer (those techniques still run, they
just can't be proven to succeed from outside).
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class TargetAdapter(Protocol):
    """Every AttackFamily talks to the target ONLY through this surface
    (via AttackContext.client). Anything implementing these seven methods
    can be red-teamed by every attack family in attacks/, unmodified."""

    def chat(self, session_id: str, message: str) -> dict:
        """Send a message, get back at least {"response": str}. Adapters
        that can observe tool calls should also include
        {"tool_calls": [{"name": ..., "arguments": ..., "result": ...}]}."""
        ...

    def ingest_document(self, doc_id: str, title: str, content: str, trust: str = "external") -> dict:
        """Plant a document for RAG/agent-to-agent poisoning techniques.
        Adapters with no document ingestion surface may no-op; those
        specific techniques just won't have anything to poison."""
        ...

    def get_canaries(self) -> dict:
        """Known secret values to watch for in responses. For a target
        you don't control, supply your own via the adapter's constructor
        instead of asking the target for them."""
        ...

    def get_memory(self, session_id: str) -> list[dict]:
        """Long-term memory entries, if the target exposes any. Return
        [] if not observable."""
        ...

    def get_state(self, session_id: str | None = None) -> dict:
        """Ground-truth introspection: outbox, MCP logs, granted scopes,
        tool call logs. Return {} if not observable — judges are written
        to treat every key as optional."""
        ...

    def reset(self) -> dict:
        """Best-effort: clear state between campaigns/regression runs."""
        ...

    def health(self) -> bool: ...
