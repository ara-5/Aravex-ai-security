"""Scan an MCP server's tool definitions before an agent trusts them.

`aravex-mcp scan -- <server command>` connects to a stdio MCP server, reads its tool
list and produces, with no model and no network:

  * a tool inventory with the capability each tool appears to have;
  * findings for tool descriptions that look poisoned (hidden instructions, invisible
    characters, concealment, steering toward other tools, side-channel parameters);
  * mapping.suggested.yaml, a starting point for the proxy's mapping file;
  * pins.json, a fingerprint of every tool definition, so the proxy can refuse a tool
    whose description changes after it was reviewed (a "rug pull").

It is a static, heuristic check. A clean scan does not mean a server is safe, and a
finding is a reason to read the description, not proof of an attack.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Issue:
    code: str
    severity: str
    detail: str


@dataclass
class ToolReport:
    name: str
    description: str
    action: str | None
    category: str | None
    capability_risk: str
    issues: list[Issue] = field(default_factory=list)
    fingerprint: str = ""

    @property
    def risk(self) -> str:
        worst = max([RANK[self.capability_risk]] + [RANK[i.severity] for i in self.issues])
        return next(k for k, v in RANK.items() if v == worst)

    @property
    def poisoned(self) -> bool:
        return any(i.severity == "high" for i in self.issues)


# -- fingerprints ---------------------------------------------------------------------------------
def fingerprint(tool: types.Tool) -> str:
    """Stable hash of what the model sees of a tool: name, description, input schema.
    ASCII-escaped before hashing so an invisible character changes the hash."""
    blob = json.dumps({"name": tool.name, "description": tool.description or "",
                       "inputSchema": tool.inputSchema or {}},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# -- poisoning checks -----------------------------------------------------------------------------
_OVERRIDE = [
    (r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules|prompts?|messages)",
     "tells the model to ignore its earlier instructions"),
    (r"disregard (all |any )?(the )?(previous|prior|above|earlier)", "tells the model to disregard earlier context"),
    (r"<\s*(important|system|instructions?|secret|admin)\s*>", "contains an <IMPORTANT>/<SYSTEM>-style instruction block"),
    (r"(do not|don'?t|never) (tell|mention|reveal|show|inform|let|notify|disclose to) (the )?(user|human|anyone)",
     "tells the model to hide something from the user"),
    (r"without (telling|informing|notifying|alerting) (the )?(user|human)", "asks for actions without telling the user"),
]
_STEERING = [
    (r"(before|prior to) (using|calling|running|invoking) this tool,? (you )?(must|should|need to|have to)",
     "gives conditions the model must satisfy before using the tool"),
    (r"you (must|should|have to|need to) (first|always)", "gives the model standing orders"),
]
_SENSITIVE = (r"(~|/home/\w+|/root)?/\.ssh\b|\bid_rsa\b|\.aws/credentials|/etc/passwd|/etc/shadow|\.env\b|\.npmrc\b|"
              r"\.netrc\b|credentials\.json|\bprivate key\b|\bapi[_ -]?keys?\b|\baccess[_ -]?tokens?\b")
_EXFIL_WORDS = r"\b(send|upload|post|forward|transmit|attach|include in|pass (it|them|the)|exfiltrate)\b"
_SIDE_CHANNEL = {"notes", "note", "context", "conversation", "conversation_history", "history", "system_prompt",
                 "reasoning", "thoughts", "sidenote", "metadata", "extra", "additional_info"}
_SIDE_CHANNEL_DESC = r"(contents? of|conversation|chat history|system prompt|previous messages|\bfiles?\b)"
_MAX_LEN = 1500


def _texts(tool: types.Tool) -> list[tuple[str, str]]:
    """Every piece of text the model reads for this tool, with where it came from."""
    out: list[tuple[str, str]] = []
    if tool.description:
        out.append(("description", tool.description))

    def walk(node, path):
        if isinstance(node, dict):
            if isinstance(node.get("description"), str):
                out.append((f"parameter {path}", node["description"]))
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    for pname, pval in value.items():
                        walk(pval, pname)
                elif key in ("items", "anyOf", "oneOf", "allOf"):
                    walk(value, path)
        elif isinstance(node, list):
            for item in node:
                walk(item, path)

    walk(tool.inputSchema or {}, "")
    return out


def _invisible(text: str) -> list[str]:
    return sorted({f"U+{ord(c):04X}" for c in text if unicodedata.category(c) == "Cf"})


def check_tool(tool: types.Tool, other_tools: list[str]) -> list[Issue]:
    issues: list[Issue] = []
    texts = _texts(tool)
    for where, text in texts:
        low = text.lower()
        hidden = _invisible(text)
        if hidden:
            issues.append(Issue("invisible-characters", "high",
                                f"{where} contains invisible characters ({', '.join(hidden[:4])}) that a reader cannot see"))
        override = [why for pat, why in _OVERRIDE if re.search(pat, low)]
        for why in override:
            issues.append(Issue("hidden-instruction", "high", f"{where} {why}"))
        for pat, why in _STEERING:
            if re.search(pat, low):
                issues.append(Issue("steering-instruction", "medium", f"{where} {why}"))
        if re.search(_SENSITIVE, low):
            exfil = bool(re.search(_EXFIL_WORDS, low))
            if override or exfil:
                issues.append(Issue("sensitive-data-instruction", "high",
                                    f"{where} refers to credentials or key files and also instructs the model to move or conceal data"))
            else:
                issues.append(Issue("sensitive-reference", "medium",
                                    f"{where} mentions credentials or key files; confirm the tool really needs them"))
        if re.search(r"https?://", low) and re.search(_EXFIL_WORDS, low):
            issues.append(Issue("outbound-url", "medium", f"{where} tells the model to send something to a URL"))
        if len(text) > _MAX_LEN:
            issues.append(Issue("long-description", "low",
                                f"{where} is {len(text)} characters; long text can hide instructions"))
        if where == "description":
            for other in other_tools:
                if len(other) >= 4 and other != tool.name and re.search(rf"\b{re.escape(other)}\b", low) \
                        and re.search(r"\b(instead of|before|after|always|must|first|then)\b", low):
                    issues.append(Issue("tool-steering", "medium",
                                        f"description steers the model toward another tool ('{other}')"))
    props = (tool.inputSchema or {}).get("properties") or {}
    for pname, pval in props.items():
        if str(pname).lower() in _SIDE_CHANNEL and isinstance(pval, dict) and pval.get("type", "string") == "string":
            desc = str(pval.get("description", "")).lower()
            if re.search(_SIDE_CHANNEL_DESC, desc):
                issues.append(Issue("side-channel-parameter", "medium",
                                    f"parameter '{pname}' asks for conversation or file contents the tool should not need"))
            else:
                issues.append(Issue("free-text-parameter", "low",
                                    f"parameter '{pname}' is free text that could carry extra data; confirm it is needed"))
    seen, unique = set(), []
    for i in issues:
        if (i.code, i.detail) not in seen:
            seen.add((i.code, i.detail))
            unique.append(i)
    return unique


# -- capability inference --------------------------------------------------------------------------
_ACTIONS = [
    ("delete", r"\b(delete|remove|drop|destroy|wipe|purge|truncate)\b"),
    ("export", r"\b(export|dump|bulk)\b"),
    ("send", r"\b(send|email|mail|post|publish|notify|message|upload|share|forward|webhook)\b"),
    ("write", r"\b(write|create|update|edit|save|append|put|set|insert|modify|rename|move|add)\b"),
    ("read", r"\b(read|get|list|search|fetch|query|view|show|find|open|cat|lookup|load)\b"),
]
_CATEGORIES = [
    ("secrets", r"secret|credential|password|passwd|token|api.?key|private.?key|\bssh\b"),
    ("iam", r"\b(role|permission|scope|grant|revoke|admin|privilege|iam|acl)\b"),
    ("payments", r"payment|invoice|charge|refund|billing|\bcard\b"),
    ("email", r"\b(email|mail|smtp|inbox)\b"),
    ("calendar", r"calendar|\bevent|meeting|schedule"),
    ("customer_db", r"customer|\bcrm\b|contact"),
    ("database", r"\b(sql|database|table|schema|db)\b"),
    ("filesystem", r"\b(file|path|directory|folder|dir|fs|filename)\b"),
]
TOOL_FOR_CATEGORY = {"secrets": "secrets_tool", "iam": "iam_tool", "payments": "payments_tool", "email": "email_tool",
                     "calendar": "calendar_mcp_tool", "customer_db": "customer_db_tool",
                     "database": "database_admin_tool", "filesystem": "filesystem_tool"}
_RESOURCE_ARGS = ["path", "file", "filename", "uri", "url", "to", "recipient", "table", "name", "id", "query", "key"]
_DEST_ARGS = ["to", "recipient", "recipients", "email", "url", "uri", "webhook", "address"]
_PAYLOAD_ARGS = ["body", "content", "text", "message", "subject", "data", "query"]


def _words(name: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return re.sub(r"[_\-./]+", " ", spaced).lower()


def _first(table, text: str) -> str | None:
    return next((label for label, pat in table if re.search(pat, text)), None)


def infer(tool: types.Tool, trust_description: bool = True) -> tuple[str | None, str | None]:
    """(action, category) from the tool's name and argument names, falling back to its
    description. A description that was flagged as hostile is not allowed to define what
    the tool is, so callers pass trust_description=False for those."""
    props = list(((tool.inputSchema or {}).get("properties") or {}).keys())
    primary = _words(tool.name) + " " + " ".join(_words(p) for p in props)
    secondary = (tool.description or "").lower() if trust_description else ""
    action = _first(_ACTIONS, _words(tool.name)) or _first(_ACTIONS, secondary)
    category = _first(_CATEGORIES, primary) or _first(_CATEGORIES, secondary)
    return action, category


def capability_risk(action: str | None, category: str | None) -> str:
    if category in ("secrets", "iam") or action in ("delete", "export", "send"):
        return "high"
    if action == "write" or category is None or action is None:
        return "medium"
    return "low"


# -- scanning --------------------------------------------------------------------------------------
def scan_tools(tools: list[types.Tool]) -> list[ToolReport]:
    names = [t.name for t in tools]
    reports = []
    for tool in tools:
        issues = check_tool(tool, names)
        action, category = infer(tool, trust_description=not any(i.severity == "high" for i in issues))
        reports.append(ToolReport(
            name=tool.name, description=tool.description or "", action=action, category=category,
            capability_risk=capability_risk(action, category), issues=issues,
            fingerprint=fingerprint(tool)))
    return reports


def suggest_mapping(server: str, tools: list[types.Tool], reports: list[ToolReport]) -> tuple[dict, list[str]]:
    """A starting mapping for the proxy. Tools it cannot classify, and tools with a
    high-severity finding, are left out, so the proxy refuses them until a person decides."""
    by_name = {r.name: r for r in reports}
    mapping: dict = {"server": server, "internal_domains": [], "tools": {}}
    left_out: list[str] = []
    for tool in tools:
        rep = by_name[tool.name]
        if rep.poisoned or rep.category is None:
            left_out.append(tool.name)
            continue
        props = (tool.inputSchema or {}).get("properties") or {}
        entry: dict = {"tool_id": TOOL_FOR_CATEGORY[rep.category],
                       "action": rep.action or ("access" if rep.category == "iam" else "read")}
        arg = next((a for a in _RESOURCE_ARGS if a in props), None)
        entry["resource"] = f"{rep.category}.{{{arg}}}" if arg else f"{rep.category}.{_words(tool.name).replace(' ', '_')}"
        if rep.category in ("customer_db", "payments", "secrets"):
            entry["data_classification"] = "SENSITIVE"
        if entry["action"] == "send":
            dest = next((a for a in _DEST_ARGS if a in props), None)
            if dest:
                entry["destination_from"] = dest
        payload = [a for a in _PAYLOAD_ARGS if a in props and props[a].get("type") == "string"][:3]
        if payload:
            entry["payload_from"] = payload
        mapping["tools"][tool.name] = entry
    return mapping, left_out


def render_report(server: str, reports: list[ToolReport], left_out: list[str]) -> str:
    high = sum(1 for r in reports if r.risk == "high")
    flagged = [r for r in reports if r.issues]
    lines = [f"# Aravex MCP scan: {server}", "",
             f"{len(reports)} tools. {high} high risk. {len(flagged)} with findings. "
             "This is a static check of tool definitions; a clean result does not make a server safe.", "",
             "| Tool | Looks like | Risk | Findings |", "|---|---|---|---:|"]
    for r in sorted(reports, key=lambda r: -RANK[r.risk]):
        looks = f"{r.action or '?'} on {r.category or 'unknown'}"
        lines.append(f"| `{r.name}` | {looks} | {r.risk} | {len(r.issues)} |")
    if flagged:
        lines += ["", "## Findings", ""]
        for r in sorted(flagged, key=lambda r: -RANK[r.risk]):
            lines.append(f"### `{r.name}`")
            lines += [f"- **{i.severity}** `{i.code}`: {i.detail}" for i in r.issues]
            lines.append("")
    if left_out:
        lines += ["## Left out of the suggested mapping", "",
                  "The proxy will refuse these until a person maps them: "
                  + ", ".join(f"`{n}`" for n in left_out) + ".", ""]
    lines += ["## Next", "",
              "1. Read the findings and the descriptions behind them. Fix `mapping.suggested.yaml` "
              "(it is a guess from tool names) and set `internal_domains`.",
              "2. Run the server behind the gateway with the definitions pinned:",
              "   `aravex-mcp --agent-id <id> --mapping mapping.suggested.yaml --pins pins.json -- <server command>`",
              "3. Re-scan whenever the server updates. With `--pins`, a tool whose definition changed is hidden and refused."]
    return "\n".join(lines) + "\n"


# -- command line ----------------------------------------------------------------------------------
async def _list_tools(command: list[str], env: dict[str, str]) -> list[types.Tool]:
    params = StdioServerParameters(command=command[0], args=command[1:], env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools: list[types.Tool] = []
            cursor = None
            while True:
                page = await session.list_tools(cursor)
                tools.extend(page.tools)
                cursor = page.nextCursor
                if not cursor:
                    return tools


def scan_main(argv: list[str]) -> int:
    split = argv.index("--") if "--" in argv else len(argv)
    p = argparse.ArgumentParser(prog="aravex-mcp scan", description="Scan an MCP server's tool definitions.")
    p.add_argument("--name", help="server name for the mapping (default: from the command)")
    p.add_argument("--out-dir", default="aravex-scan", help="where to write report.md, mapping.suggested.yaml, pins.json")
    p.add_argument("--fail-on", choices=list(RANK), help="exit 1 if any finding is at least this severe (for CI)")
    p.add_argument("--upstream-env", action="append", default=[], metavar="NAME",
                   help="forward this environment variable to the server (repeatable)")
    args = p.parse_args(argv[:split])
    command = argv[split + 1:]
    if split == len(argv) or not command:
        print("aravex-mcp scan: give the server command after '--'", file=sys.stderr)
        return 2

    server = args.name or re.sub(r"[^A-Za-z0-9_-]+", "-", Path(command[-1]).stem or "upstream").strip("-") or "upstream"
    env = {n: os.environ[n] for n in args.upstream_env if n in os.environ}
    try:
        tools = asyncio.run(_list_tools(command, env))
    except Exception as exc:  # the server failed to start or speak MCP
        print(f"aravex-mcp scan: could not read tools from the server: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    reports = scan_tools(tools)
    mapping, left_out = suggest_mapping(server, tools, reports)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = render_report(server, reports, left_out)
    (out / "report.md").write_text(report, encoding="utf-8")
    (out / "mapping.suggested.yaml").write_text(
        "# SUGGESTED by `aravex-mcp scan` from tool names and descriptions. A guess: review every entry,\n"
        "# and set internal_domains. Tools not listed here are refused by the proxy.\n"
        + yaml.safe_dump(mapping, sort_keys=False), encoding="utf-8")
    (out / "pins.json").write_text(
        json.dumps({"server": server, "tools": {r.name: r.fingerprint for r in reports}}, indent=2) + "\n",
        encoding="utf-8")

    print(report)
    print(f"Wrote {out / 'report.md'}, {out / 'mapping.suggested.yaml'}, {out / 'pins.json'}")
    if args.fail_on:
        worst = [(r.name, i) for r in reports for i in r.issues if RANK[i.severity] >= RANK[args.fail_on]]
        if worst:
            print(f"aravex-mcp scan: {len(worst)} finding(s) at or above '{args.fail_on}'", file=sys.stderr)
            return 1
    return 0
