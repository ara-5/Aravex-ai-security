"""
GenericChatAdapter — proves the TargetAdapter contract is real, not just
an interface with one implementation.

Point this at ANY black-box agent that exposes nothing but a chat
endpoint (no document ingestion, no memory/tool/MCP introspection, no
admin reset) and every attack family in attacks/ still runs against it
unmodified: prompt injection, jailbreak, and system-prompt-extraction
work exactly as well as against the reference target, because they only
need response text. RAG-poisoning/tool-poisoning/MCP/agent-to-agent
techniques still execute — they just can't be proven to succeed, since
there's nothing to introspect, so their judges correctly report
`success=False` (not observable) instead of crashing.

That's the honest scope: no code changes anywhere else in the repo, at
the cost of losing ground-truth judging for techniques that need it.
"""
from __future__ import annotations

from typing import Callable

import httpx


def _default_response_extractor(data: dict) -> str:
    for key in ("response", "reply", "answer", "text", "message"):
        if isinstance(data.get(key), str):
            return data[key]
    # OpenAI-chat-completions shape, in case the black-box endpoint speaks that.
    try:
        return data["choices"][0]["message"]["content"]
    except Exception:
        return str(data)


class GenericChatAdapter:
    """Minimal contract expected of the target: POST `chat_url` with
    {"message": str, "session_id": str} (override via `request_builder`
    for a different request shape), get back JSON containing the reply
    text somewhere `response_extractor` can find it."""

    def __init__(
        self,
        chat_url: str,
        known_secrets: dict | None = None,
        health_url: str | None = None,
        headers: dict | None = None,
        request_builder: Callable[[str, str], dict] | None = None,
        response_extractor: Callable[[dict], str] = _default_response_extractor,
        timeout: float = 30.0,
    ):
        self.chat_url = chat_url
        self.health_url = health_url
        self._canaries = known_secrets or {}
        self._request_builder = request_builder or (lambda sid, msg: {"message": msg, "session_id": sid})
        self._response_extractor = response_extractor
        self._client = httpx.Client(headers=headers or {}, timeout=timeout)

    def chat(self, session_id: str, message: str) -> dict:
        payload = self._request_builder(session_id, message)
        resp = self._client.post(self.chat_url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return {"response": self._response_extractor(data), "tool_calls": []}

    def ingest_document(self, doc_id: str, title: str, content: str, trust: str = "external") -> dict:
        return {"status": "unsupported: this adapter has no document-ingestion surface"}

    def get_canaries(self) -> dict:
        return self._canaries

    def get_memory(self, session_id: str) -> list[dict]:
        return []

    def get_state(self, session_id: str | None = None) -> dict:
        return {}

    def reset(self) -> dict:
        return {"status": "unsupported: this adapter has no admin reset surface"}

    def health(self) -> bool:
        try:
            if self.health_url:
                r = self._client.get(self.health_url, timeout=3.0)
                return r.status_code == 200
            self.chat("healthcheck", "ping")
            return True
        except Exception:
            return False
