"""Look at what a tool sends BACK to the agent.

Indirect prompt injection arrives in tool results: a web page, a file, an email or a
ticket that contains instructions meant for the model. Secrets can arrive the same way
when a tool reads something it should not have. This is a heuristic check on result
text; it catches the common crude cases, not a determined attacker.

Modes (`--inspect-results`): off (default), warn (log and pass through), block (withhold
a result that has a high-severity finding). Blocking has a cost: a security article
that quotes "ignore previous instructions" will be withheld too.
"""
from __future__ import annotations

import json
import re

from mcp import types

from aravex_mcp.scan import _OVERRIDE, Issue

_SECRETS = [
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "a private key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "an AWS access key id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "a GitHub token"),
    (r"\bsk-[A-Za-z0-9_-]{20,}\b", "an API secret key (sk-...)"),
    (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "a Slack token"),
]
_ROLE_MARKER = re.compile(r"(^|\n)\s*(system|assistant)\s*:", re.I)
_BIDI = re.compile("[‪-‮⁦-⁩]")
_TAGS = re.compile("[\U000e0000-\U000e007f]")  # "ASCII smuggling": invisible text a model can still read
_ZERO_WIDTH = re.compile("[​⁠﻿]")  # not ZWJ/ZWNJ: those appear in ordinary emoji and scripts


def result_text(result: types.CallToolResult) -> str:
    parts: list[str] = []
    for block in result.content or []:
        if isinstance(block, types.TextContent):
            parts.append(block.text)
        elif isinstance(block, types.EmbeddedResource) and hasattr(block.resource, "text"):
            parts.append(block.resource.text)
    if result.structuredContent:
        parts.append(json.dumps(result.structuredContent, default=str))
    return "\n".join(parts)


def inspect_result(result: types.CallToolResult) -> list[Issue]:
    text = result_text(result)
    low = text.lower()
    issues: list[Issue] = []
    for pat, why in _OVERRIDE:
        if re.search(pat, low):
            issues.append(Issue("injection-in-result", "high", f"result {why}"))
    for pat, what in _SECRETS:
        if re.search(pat, text):
            issues.append(Issue("secret-in-result", "high", f"result contains {what}"))
    if _TAGS.search(text):
        issues.append(Issue("hidden-text", "high", "result contains invisible tag characters that can carry hidden instructions"))
    if _BIDI.search(text):
        issues.append(Issue("hidden-text", "medium", "result contains bidirectional text controls"))
    if len(_ZERO_WIDTH.findall(text)) >= 3:
        issues.append(Issue("hidden-text", "medium", "result contains runs of zero-width characters"))
    if _ROLE_MARKER.search(text):
        issues.append(Issue("role-marker", "medium", "result contains text formatted as a system or assistant message"))
    return issues
