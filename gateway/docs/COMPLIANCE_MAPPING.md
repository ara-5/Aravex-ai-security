# Compliance Mapping: OWASP LLM Top 10 & NIST AI RMF

What AegisAI actually covers against two widely-referenced frameworks, and
-- just as importantly -- what it deliberately doesn't. A mapping that only
lists strengths isn't credible; the gaps here are real and are the honest
answer to "what would you build next."

OWASP's LLM Top 10 gets revised periodically and item numbering shifts
between editions -- treat the IDs below as pointers to check against the
current published list, not a frozen citation.

## OWASP Top 10 for LLM Applications

| # | Risk | AegisAI coverage |
|---|------|-------------------|
| LLM01 | Prompt Injection | **Partial, by design.** `gateway/security/prompt_injection.py` is a heuristic detector that feeds the risk score -- it will miss a novel injection. The actual mitigation is architectural, not detection-based: even a *fully successful* injection still can't do anything the compromised agent's IAM grant doesn't allow. See [ARCHITECTURE.md](ARCHITECTURE.md#why-this-is-a-deeper-problem-than-prompt-filtering). |
| LLM02 | Sensitive Information Disclosure | **Covered.** `gateway/security/dlp.py` scans payloads for secrets/PII patterns; `data_classification` + the `block_highly_sensitive_to_external` Rego rule hard-block HIGHLY_SENSITIVE data from leaving via an external API destination. |
| LLM03 | Supply Chain | **Not covered.** No SBOM generation, dependency vulnerability scanning, or image signing in this project. A real deployment needs `pip-audit`/`trivy` in CI and signed container images. |
| LLM04 | Data and Model Poisoning | **Out of scope.** AegisAI doesn't train or fine-tune models. If wired to a real RAG pipeline, retrieved content passed through `payload_preview` gets the same DLP/injection scan as any other input, but that's incidental coverage, not a poisoning-specific control. |
| LLM05 | Improper Output Handling | **Not covered.** AegisAI governs tool *calls*, not how an LLM's raw text output gets rendered downstream (e.g. XSS from unsanitized output in a UI). Out of this project's boundary. |
| LLM06 | Excessive Agency | **This is the core of the project.** Agent IAM (`gateway/identity/`) enforces least-privilege, per-resource permission grants; Tool Identity binding means an agent can't even reach a tool that isn't in its `allowed_tools`; the policy engine and human-approval workflow are the second and third layers behind that. If you map only one row, map this one. |
| LLM07 | System Prompt Leakage | **Partial.** `prompt_injection.py` includes patterns for "reveal your system prompt" as a risk signal (raises the score, can trigger HUMAN_APPROVAL) -- it's a detector, not a hard block, and it only sees text that's routed through `payload_preview`. |
| LLM08 | Vector and Embedding Weaknesses | **Out of scope.** AegisAI doesn't implement retrieval or embeddings itself; the architecture diagram shows RAG as an example downstream resource an agent might reach, not a component this project secures internally. |
| LLM09 | Misinformation | **Out of scope.** Not an access-control concern; nothing here evaluates output truthfulness. |
| LLM10 | Unbounded Consumption | **Partial.** `gateway/security/anomaly.py`'s sliding-window call-rate detector and the `deny_bulk_export` rule catch specific abuse patterns (call bursts, oversized exports). There's no general per-agent cost/token/resource quota system. |

## Agentic-specific threats (no single canonical numbering yet)

| Threat | AegisAI coverage |
|--------|-------------------|
| Excessive agency / no least privilege | **Primary control** -- see LLM06 above. |
| Unauthorized tool invocation | **Covered** -- Tool Identity check runs before any policy logic; an agent can't use a tool that isn't explicitly listed for it. |
| Agent identity spoofing | **Covered** -- `gateway/identity/credentials.py` requires a bearer credential proving the caller actually is the `agent_id` it claims, checked before authorization. See [ARCHITECTURE.md](ARCHITECTURE.md#authentication-vs-authorization). |
| Privilege escalation via chained actions | **Partial.** Specific known escalation patterns are hard-coded rules (e.g. `deny_customer_support_db_write`). There's no general state machine reasoning about multi-step escalation across a sequence of otherwise-individually-allowed actions -- a real gap. |
| Human oversight bypass | **Covered by construction** -- `gateway/approvals/manager.py` means a `HUMAN_APPROVAL` decision is never auto-executed; the demo agent only calls a tool on `ALLOW`. |
| Credential stuffing / spraying against a known agent identity | **Covered** -- authentication failures are logged as `security_alert` and feed the same anomaly tracker as policy denials, surfacing as `repeated_failed_authorization`. |
| Non-repudiation / audit integrity | **Covered** -- structured JSON audit log (SIEM-ready) plus a dual-written durable Postgres table (`gateway/audit/postgres_store.py`) when `DATABASE_URL` is configured. |

## NIST AI Risk Management Framework

| Function | AegisAI's contribution |
|----------|-------------------------|
| **Govern** | `gateway/identity/agents.yaml` is a versioned, explicit statement of which agent exists, who owns it, and exactly what it may touch -- the kind of documented governance artifact NIST AI RMF asks an organization to maintain, expressed as config instead of a wiki page. |
| **Map** | The identity chain (Human -> Agent -> Tool -> Resource) makes the context of every action explicit and traceable rather than implicit in application code. |
| **Measure** | The risk-scoring engine (`gateway/policy/risk.py`), Prometheus metrics, and the Grafana dashboard give continuous, quantified visibility into agent behavior and decision outcomes -- not a point-in-time assessment. |
| **Manage** | The ALLOW / DENY / HUMAN_APPROVAL enforcement itself, plus the human-approval workflow, is the actual risk-response mechanism -- Measure without Manage is just a dashboard nobody acts on. |

## What this mapping is for

Not a compliance certification -- a working demonstration that the project
was built against a named threat model rather than intuition, and an honest
list of what "harden this for production" would need to close next
(supply-chain scanning, output-handling controls, multi-step escalation
reasoning, and resource-quota enforcement, specifically).
