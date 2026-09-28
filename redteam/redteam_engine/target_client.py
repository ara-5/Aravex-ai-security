"""
HTTP client the red-team engine uses to drive this repo's reference
target agent. This is one implementation of the TargetAdapter protocol
(target_adapter.py) — the richest possible one, since we own the target
and built in full introspection on purpose. See
redteam_engine/adapters/generic_chat_adapter.py for the other extreme:
an adapter for a black-box agent with nothing but a chat endpoint.
"""
from __future__ import annotations

import httpx

from redteam_engine.config import TARGET_ADMIN_API_KEY, TARGET_AGENT_URL


class TargetClient:
    def __init__(self, base_url: str = TARGET_AGENT_URL, client: httpx.Client | None = None):
        """`client` lets callers (tests, or an in-process deployment) hand
        in a preconfigured httpx.Client — e.g. one built on an ASGI
        transport wrapping the target agent's FastAPI app directly, with
        no real network/socket involved."""
        self.base_url = base_url
        headers = {"X-API-Key": TARGET_ADMIN_API_KEY} if TARGET_ADMIN_API_KEY else {}
        self._client = client or httpx.Client(base_url=base_url, headers=headers, timeout=30.0)

    def chat(self, session_id: str, message: str) -> dict:
        r = self._client.post("/chat", json={"session_id": session_id, "message": message})
        r.raise_for_status()
        return r.json()

    def ingest_document(self, doc_id: str, title: str, content: str, trust: str = "external") -> dict:
        r = self._client.post("/admin/documents", json={"doc_id": doc_id, "title": title, "content": content, "trust": trust})
        r.raise_for_status()
        return r.json()

    def get_canaries(self) -> dict:
        r = self._client.get("/admin/canaries")
        r.raise_for_status()
        return r.json()

    def get_memory(self, session_id: str) -> list[dict]:
        r = self._client.get("/admin/memory", params={"session_id": session_id})
        r.raise_for_status()
        return r.json()

    def get_state(self, session_id: str | None = None) -> dict:
        params = {"session_id": session_id} if session_id else {}
        r = self._client.get("/admin/state", params=params)
        r.raise_for_status()
        return r.json()

    def reset(self) -> dict:
        r = self._client.post("/admin/reset")
        r.raise_for_status()
        return r.json()

    def health(self) -> bool:
        try:
            r = self._client.get("/health", timeout=3.0)
            return r.status_code == 200
        except Exception:
            return False
