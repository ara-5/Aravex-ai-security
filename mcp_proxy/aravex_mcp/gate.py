"""Client for the Aravex gateway. Fails closed.

check() never raises. Only an HTTP 200 whose body says decision == "ALLOW" for the
request we sent lets a call through. Everything else is a refusal: gateway down,
timeout, 401/403/5xx, malformed JSON, a decision for a different request, or a
decision that is DENY, HUMAN_APPROVAL or anything unrecognised.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from uuid import uuid4

import httpx

log = logging.getLogger("aravex_mcp")

ALLOW = "ALLOW"
DENY = "DENY"
HUMAN_APPROVAL = "HUMAN_APPROVAL"
ERROR = "ERROR"  # the gateway could not give a usable answer

APPROVED = "APPROVED"
DENIED = "DENIED"
TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class Verdict:
    decision: str
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    approval_id: str | None = None
    request_id: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW


class Gate:
    def __init__(self, client: httpx.Client, api_key: str, *, approval_wait: float = 0.0,
                 poll_interval: float = 1.0):
        self._client = client
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.approval_wait = approval_wait
        self.poll_interval = poll_interval

    @classmethod
    def for_url(cls, url: str, api_key: str, *, timeout: float = 10.0, **kw) -> "Gate":
        return cls(httpx.Client(base_url=url.rstrip("/"), timeout=timeout), api_key, **kw)

    def healthy(self) -> bool:
        try:
            return self._client.get("/healthz").status_code == 200
        except Exception:
            return False

    def check(self, action: dict) -> Verdict:
        """Ask the gateway about one action. The request id is set here so the
        reply can be matched to the question."""
        request_id = action.get("request_id") or str(uuid4())
        action = {**action, "request_id": request_id}
        try:
            resp = self._client.post("/v1/agent-action", json=action, headers=self._headers)
        except Exception as exc:
            return Verdict(ERROR, [f"gateway unavailable ({type(exc).__name__})"], request_id=request_id)
        if resp.status_code != 200:
            return Verdict(ERROR, [f"gateway returned HTTP {resp.status_code}"], request_id=request_id)
        try:
            body = resp.json()
            decision = body["decision"]
            if not isinstance(decision, str):
                raise TypeError("decision is not a string")
            echoed = body.get("request_id")
            reasons = [str(r) for r in body.get("reasons") or []]
            rules = [str(r) for r in body.get("matched_rules") or []]
            approval_id = body.get("approval_id")
        except Exception:
            return Verdict(ERROR, ["gateway returned an unreadable decision"], request_id=request_id)
        if echoed != request_id:
            return Verdict(ERROR, ["gateway decision does not match the request"], request_id=request_id)
        if decision not in (ALLOW, DENY, HUMAN_APPROVAL):
            return Verdict(ERROR, [f"gateway returned unknown decision {decision!r}"], request_id=request_id)
        return Verdict(decision, reasons, rules, approval_id if isinstance(approval_id, str) else None, request_id)

    def await_approval(self, approval_id: str) -> str:
        """Block until a person resolves the approval or approval_wait runs out.
        Returns APPROVED, DENIED, TIMEOUT or ERROR. Only APPROVED lets the call run."""
        deadline = time.monotonic() + self.approval_wait
        while True:
            try:
                resp = self._client.get(f"/v1/approvals/{approval_id}", headers=self._headers)
                if resp.status_code != 200:
                    return ERROR
                status = resp.json().get("status")
            except Exception:
                return ERROR
            if status == APPROVED:
                return APPROVED
            if status == DENIED:
                return DENIED
            if status != "PENDING":
                return ERROR
            if time.monotonic() >= deadline:
                return TIMEOUT
            time.sleep(min(self.poll_interval, max(deadline - time.monotonic(), 0.0)))
