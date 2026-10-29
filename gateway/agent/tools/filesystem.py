"""Toy filesystem/database-admin tool. Only ever called after the gateway
has returned ALLOW."""
from __future__ import annotations


def delete_database(name: str) -> dict:
    return {"status": "deleted", "database": name}
