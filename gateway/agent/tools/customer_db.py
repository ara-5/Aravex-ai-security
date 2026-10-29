"""Toy customer-database tool. Only ever called after the gateway has
already returned ALLOW -- these functions do no security checking of their
own, by design: enforcement lives entirely in the gateway."""
from __future__ import annotations

_FAKE_CUSTOMERS = {
    "cust_1001": {"id": "cust_1001", "name": "Alicia Kim", "email": "alicia@example.com", "plan": "pro"},
}


def read_profile(customer_id: str) -> dict:
    return _FAKE_CUSTOMERS.get(customer_id, {"id": customer_id, "name": "Unknown", "email": "", "plan": "unknown"})


def export_records(record_count: int) -> dict:
    return {"exported": record_count, "format": "csv"}


def write_profile(customer_id: str, fields: dict) -> dict:
    return {"id": customer_id, "updated_fields": list(fields.keys())}
