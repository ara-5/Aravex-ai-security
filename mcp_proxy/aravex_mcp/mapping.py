"""Translate an MCP tool call into a gateway ActionRequest.

An MCP server only says "tool X was called with these arguments". The gateway
reasons about identity, action, resource and data class, so something has to say
what each tool *does*. That is this mapping, written by the operator.

Rules of the mapping:
  * It is literal. It describes the call; the gateway's policy judges it.
  * A tool with no entry is still sent to the gateway, under a tool id nobody is
    authorized for, so it is refused and the refusal is audited. Forgetting to map
    a tool therefore fails closed instead of open.
  * An unknown key or a bad value is an error at load time. A typo in a security
    config must not be silently ignored.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ACTIONS = {"read", "write", "send", "delete", "access", "export"}
CLASSIFICATIONS = {"PUBLIC", "INTERNAL", "SENSITIVE", "HIGHLY_SENSITIVE"}
EXTERNAL = "external_api"
INTERNAL = "internal"
MAX_PREVIEW = 2000
MAX_VALUE = 500

_PLACEHOLDER = re.compile(r"\{(\w+)\}")
_ALLOWED_KEYS = {
    "tool_id", "action", "resource", "data_classification", "destination",
    "destination_from", "payload_from", "record_count", "record_count_from",
}


class MappingError(ValueError):
    """The mapping file is invalid."""


@dataclass(frozen=True)
class ToolMapping:
    tool_id: str
    action: str
    resource: str                       # template; {arg} is replaced by that argument
    data_classification: str = "INTERNAL"
    destination: str = INTERNAL
    destination_from: str | None = None  # argument holding an address or URL
    payload_from: tuple[str, ...] = ()   # arguments copied into payload_preview
    record_count: int = 1
    record_count_from: str | None = None  # argument that is a list (its length) or an int


@dataclass(frozen=True)
class Mapping:
    server: str
    tools: dict[str, ToolMapping] = field(default_factory=dict)
    internal_domains: frozenset[str] = frozenset()

    # -- loading ---------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Mapping":
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise MappingError(f"cannot read mapping {path}: {exc}") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: Any) -> "Mapping":
        if not isinstance(raw, dict):
            raise MappingError("mapping must be a YAML mapping")
        unknown = set(raw) - {"server", "internal_domains", "tools"}
        if unknown:
            raise MappingError(f"unknown top-level keys: {sorted(unknown)}")
        server = raw.get("server")
        if not isinstance(server, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", server):
            raise MappingError("'server' is required and may only contain letters, digits, '_' and '-'")
        domains = raw.get("internal_domains") or []
        if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
            raise MappingError("'internal_domains' must be a list of strings")
        tools_raw = raw.get("tools") or {}
        if not isinstance(tools_raw, dict):
            raise MappingError("'tools' must be a mapping of tool name to entry")
        tools = {str(name): _parse_tool(str(name), entry) for name, entry in tools_raw.items()}
        return cls(server=server, tools=tools, internal_domains=frozenset(d.lower() for d in domains))

    # -- translation -----------------------------------------------------------
    def build_action(self, tool_name: str, arguments: dict[str, Any] | None, *,
                     agent_id: str, human_id: str, request_id: str | None = None) -> dict:
        args = arguments or {}
        base: dict[str, Any] = {"human_id": human_id, "agent_id": agent_id}
        if request_id:
            base["request_id"] = request_id

        entry = self.tools.get(tool_name)
        if entry is None:
            # Nobody is authorized for this id, so the gateway refuses and audits it.
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", tool_name)[:100]
            return {**base, "tool_id": f"mcp_unmapped.{self.server}.{safe}", "action": "access",
                    "resource": f"mcp.{self.server}.{safe}",
                    "payload_preview": _text(args)[:MAX_PREVIEW]}

        action: dict[str, Any] = {
            **base,
            "tool_id": entry.tool_id,
            "action": entry.action,
            "resource": _render(entry.resource, args)[:MAX_PREVIEW],
            "data_classification": entry.data_classification,
            "destination": entry.destination,
            "record_count": entry.record_count,
        }
        if entry.destination_from:
            action["destination"] = self._destination(args.get(entry.destination_from))
        if entry.record_count_from:
            action["record_count"] = _count(args.get(entry.record_count_from), entry.record_count)
        if entry.payload_from:
            parts = [_text(args[k]) for k in entry.payload_from if k in args]
            action["payload_preview"] = "\n".join(parts)[:MAX_PREVIEW]
        return action

    def _destination(self, value: Any) -> str:
        """external_api unless EVERY address or URL host is exactly an internal domain.
        One external recipient among several makes the whole call external, and a
        missing or unparseable value counts as external."""
        hosts = _hosts(value)
        return INTERNAL if hosts and all(h in self.internal_domains for h in hosts) else EXTERNAL


# -- helpers ------------------------------------------------------------------
def _parse_tool(name: str, entry: Any) -> ToolMapping:
    where = f"tools.{name}"
    if not isinstance(entry, dict):
        raise MappingError(f"{where} must be a mapping")
    unknown = set(entry) - _ALLOWED_KEYS
    if unknown:
        raise MappingError(f"{where}: unknown keys {sorted(unknown)}")
    for key in ("tool_id", "action", "resource"):
        if not isinstance(entry.get(key), str) or not entry[key]:
            raise MappingError(f"{where}: '{key}' is required")
    if entry["action"] not in ACTIONS:
        raise MappingError(f"{where}: action must be one of {sorted(ACTIONS)}, got {entry['action']!r}")
    if not re.match(r"^[A-Za-z0-9_-]+\.", entry["resource"]):
        raise MappingError(f"{where}: resource must start with a category prefix such as 'filesystem.'")
    cls_ = entry.get("data_classification", "INTERNAL")
    if cls_ not in CLASSIFICATIONS:
        raise MappingError(f"{where}: data_classification must be one of {sorted(CLASSIFICATIONS)}")
    if "destination" in entry and "destination_from" in entry:
        raise MappingError(f"{where}: give 'destination' or 'destination_from', not both")
    destination = entry.get("destination", INTERNAL)
    if not isinstance(destination, str) or not destination:
        raise MappingError(f"{where}: destination must be a string")
    if "record_count" in entry and "record_count_from" in entry:
        raise MappingError(f"{where}: give 'record_count' or 'record_count_from', not both")
    count = entry.get("record_count", 1)
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise MappingError(f"{where}: record_count must be a non-negative integer")
    payload = entry.get("payload_from", [])
    if not isinstance(payload, list) or not all(isinstance(p, str) for p in payload):
        raise MappingError(f"{where}: payload_from must be a list of argument names")
    for key in ("destination_from", "record_count_from"):
        if key in entry and not isinstance(entry[key], str):
            raise MappingError(f"{where}: {key} must be an argument name")
    return ToolMapping(
        tool_id=entry["tool_id"], action=entry["action"], resource=entry["resource"],
        data_classification=cls_, destination=destination,
        destination_from=entry.get("destination_from"), payload_from=tuple(payload),
        record_count=count, record_count_from=entry.get("record_count_from"),
    )


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _render(template: str, args: dict[str, Any]) -> str:
    """Replace {name} with that argument's text. Only plain names are substituted
    (no attribute or index access), and a missing argument becomes an empty string."""
    return _PLACEHOLDER.sub(lambda m: _text(args.get(m.group(1), ""))[:MAX_VALUE], template)


def _count(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, (list, tuple, dict)):
        return len(value)
    return default


def _hosts(value: Any) -> list[str]:
    """Host of each address or URL in value (a string, comma/semicolon/space
    separated, or a list of them). A token with no recognizable host yields ''."""
    if isinstance(value, (list, tuple)):
        tokens = [t for item in value for t in _tokens(item)]
    else:
        tokens = _tokens(value)
    return [_host(t) for t in tokens]


def _tokens(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    return [t for t in re.split(r"[,;\s]+", value.strip()) if t]


def _host(token: str) -> str:
    token = token.strip("<>\"'")
    if "://" in token:
        return (urlparse(token).hostname or "").lower()
    if "@" in token:
        return token.rsplit("@", 1)[-1].lower()
    return token.lower()
