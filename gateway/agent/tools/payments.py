"""Toy payments tool. Only ever called after the gateway has returned ALLOW."""
from __future__ import annotations


def read_account(account_id: str) -> dict:
    return {"account_id": account_id, "balance_cents": 4599, "status": "current"}
