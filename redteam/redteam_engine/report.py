"""
Turns a successful AttackResult into the
Attack -> Evidence -> Impact -> Remediation -> Regression-Test report shape.
"""
from __future__ import annotations

from redteam_engine.attacks.base import AttackResult

IMPACT_LIBRARY = {
    "prompt_injection": (
        "An attacker who can reach the chat interface can override the agent's intended "
        "task with arbitrary instructions, defeating any behavioral controls layered on top "
        "of the base prompt."
    ),
    "jailbreak": (
        "Behavioral guardrails can be bypassed via role-play/persona framing, exposing the "
        "agent's full unrestricted capability surface to any user."
    ),
    "system_prompt_extraction": (
        "Hidden instructions and any secrets embedded in the system prompt are recoverable by "
        "any user, enabling further targeted attacks and direct credential theft."
    ),
    "rag_poisoning": (
        "Anyone able to influence the document corpus (shared drive, ticketing system, wiki) "
        "can achieve remote instruction injection against every user who triggers retrieval of "
        "that document, at scale and without touching the agent directly."
    ),
    "memory_poisoning": (
        "A single injected instruction can become a persistent backdoor that silently "
        "re-executes on unrelated future turns, long after the original attacker interaction."
    ),
    "tool_poisoning": (
        "Data returned by a tool is treated as trustworthy as a direct user instruction, so "
        "any attacker-influenced tool output (a file, a scraped page, a DB row) becomes a "
        "second injection vector even if the chat interface itself is hardened."
    ),
    "mcp_attacks": (
        "MCP tools are trusted based on their advertised description alone. A malicious or "
        "compromised MCP server can behave completely differently from what it claims, grant "
        "itself broad permissions, or hand out live credentials with no authentication."
    ),
    "data_exfiltration": (
        "Sensitive credentials or bulk customer data can leave the organization via a single "
        "conversational turn, with no DLP, approval, or anomaly detection in the path."
    ),
    "privilege_escalation": (
        "Authorization is decided by trusting free-text claims inside the conversation instead "
        "of a real identity/authorization system, so any user can grant themselves elevated "
        "access on demand."
    ),
    "excessive_agency": (
        "The agent independently chains multiple consequential, hard-to-reverse actions from a "
        "single ambiguous request, without any human-in-the-loop confirmation step."
    ),
    "agent_to_agent": (
        "Inter-agent messages are trusted without verification, so a single compromised or "
        "poisoned agent early in the pipeline can manipulate every downstream agent into taking "
        "unauthorized action — the multi-agent architecture multiplies a single-point failure."
    ),
}

REMEDIATION_LIBRARY = {
    "prompt_injection": (
        "Separate trusted developer instructions from untrusted content at the framework level "
        "(e.g. structured tool/function-calling instead of string concatenation); add an "
        "instruction-hierarchy/guard model pass that flags override attempts before they reach "
        "the primary model."
    ),
    "jailbreak": (
        "Add a dedicated safety/policy classifier in front of and behind the main model; do not "
        "rely on the base model's own instruction-following to enforce policy under adversarial "
        "framing."
    ),
    "system_prompt_extraction": (
        "Never place secrets in the system prompt — inject them at tool-execution time from a "
        "secrets manager, scoped to the tool call, and never into model-visible context. Add "
        "output filtering for known-secret patterns as defense in depth."
    ),
    "rag_poisoning": (
        "Enforce a hard trust boundary between retrieved content and instructions: retrieved "
        "text must never be interpreted as directives. Sanitize/strip imperative-looking text "
        "from ingested documents, and require provenance + review for any document that can "
        "influence tool-triggering behavior."
    ),
    "memory_poisoning": (
        "Treat memory writes as untrusted user data, not instructions, when re-injected into "
        "future context. Validate/sanitize memory content at write time, and require explicit "
        "re-confirmation before memory-derived content can trigger a privileged tool call."
    ),
    "tool_poisoning": (
        "Apply the same trust boundary to tool OUTPUT as to any other untrusted input — never "
        "let tool results be parsed as instructions. Sandbox and validate tool arguments "
        "server-side regardless of what the model requests."
    ),
    "mcp_attacks": (
        "Pin and review MCP server code/permissions like any other third-party dependency; run "
        "MCP tools with least-privilege credentials; require explicit user/admin approval for "
        "scope grants; never return long-lived credentials through a tool call without a real "
        "auth check on the caller."
    ),
    "data_exfiltration": (
        "Add DLP/egress controls on tools capable of sending data externally (allow-listed "
        "recipients, content scanning for secret patterns, human approval for bulk exports)."
    ),
    "privilege_escalation": (
        "Authorization must come from a real identity/session system, never from parsing the "
        "conversation. Privileged tools should check a verified auth token, not a role the "
        "model believes was set."
    ),
    "excessive_agency": (
        "Require explicit confirmation before any tool call classified as high-impact "
        "(financial, bulk-data, external-communication), and cap the number of chained "
        "consequential actions per turn without a checkpoint."
    ),
    "agent_to_agent": (
        "Treat inter-agent messages as untrusted input at every hop; require downstream agents "
        "to independently verify authorization claims (e.g. against the real session/auth "
        "state) rather than trusting an upstream agent's assertion."
    ),
}


def build_finding_fields(result: AttackResult) -> dict:
    category = result.attack.category
    title = f"{category.replace('_', ' ').title()} - {result.attack.technique.replace('_', ' ')}"
    return {
        "title": title,
        "impact": IMPACT_LIBRARY.get(category, "Undermines the agent's intended access boundaries."),
        "remediation": REMEDIATION_LIBRARY.get(category, "Add explicit validation at the relevant trust boundary."),
    }


def regression_test_spec(finding_row) -> dict:
    """The exact, replayable attack a regression run re-executes."""
    return {
        "category": finding_row.category,
        "technique": finding_row.technique,
        "payload": finding_row.attack_payload,
    }
