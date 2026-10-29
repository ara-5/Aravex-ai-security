"""Toy email tool. Only ever called after the gateway has returned ALLOW."""
from __future__ import annotations


def send(to: str, subject: str, body: str) -> dict:
    return {"status": "sent", "to": to, "subject": subject}
