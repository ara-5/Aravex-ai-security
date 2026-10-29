"""Actions a legitimate assistant performs. A generated rule must not block these.

This is the guard against over-fitting: a rule that stops the attack by also
stopping normal work is not a fix. Extend this set as real usage is learned.
"""
from __future__ import annotations

BENIGN_ACTIONS: list[dict] = [
    {"tool_id": "customer_db_tool", "action": "read", "resource": "customer_db.records",
     "data_classification": "SENSITIVE", "record_count": 1, "destination": "internal"},
    {"tool_id": "filesystem_tool", "action": "read", "resource": "filesystem.notes.txt",
     "data_classification": "INTERNAL", "record_count": 1, "destination": "internal"},
    {"tool_id": "filesystem_tool", "action": "write", "resource": "filesystem.notes.txt",
     "data_classification": "INTERNAL", "record_count": 1, "destination": "internal"},
    {"tool_id": "email_tool", "action": "send", "resource": "email.alice@example.com",
     "data_classification": "INTERNAL", "record_count": 1, "destination": "internal"},
    {"tool_id": "calendar_mcp_tool", "action": "send", "resource": "calendar.team_shared",
     "data_classification": "INTERNAL", "record_count": 1, "destination": "internal"},
]
