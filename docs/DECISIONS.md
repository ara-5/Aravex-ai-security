# Decisions

The choices that are not obvious from the code: what was chosen, why, and what it costs.

**Separate packages, history preserved.** `redteam/` and `gateway/` were imported with
their git history and kept as separate packages joined by shared contracts
(`schemas/`). *Why:* each can be tested and released on its own, and nothing was lost.
*Cost:* two codebases, no unified dashboard or onboarding yet.

**Everything refuses when unsure.** The gateway guard, the MCP proxy and the approval
endpoints deny on errors, timeouts, bad responses and missing configuration. *Why:* a
security control that opens on failure is worse than none. *Cost:* a down gateway stops
the agent.

**An unmapped MCP tool is sent to the gateway, not skipped.** It goes under an id nobody
holds, so it is refused and audited. *Why:* forgetting to map a tool must fail closed and
leave a record. *Cost:* every new tool needs a mapping before it works.

**The agent sees the reason and rule name, not the risk arithmetic.** *Why:* the score
breakdown would let a probing agent tune attempts against the thresholds. *Cost:*
agents (and their developers) get less detail; the operator log has all of it.

**Rules need a person.** Generated rules are drafts; only approved ones apply, and
promotion into `policies/` requires a named reviewer and a verified replay. *Why:* an
unreviewed rule can block real work. *Cost:* slower, and it needs a reviewer.

**The CI gate uses fixed rephrasings, not model-written mutations.** *Why:* the gate must
give the same answer every run. *Cost:* a rule can pass the gate and still miss a phrasing
those templates do not cover.

**A gate that cannot fail proves nothing.** Every gate and proxy test has a control (the
attack succeeds without the rules; the tool runs without the proxy), and the checks were
validated by breaking the code on purpose. *Why:* an early version passed because every
call was rejected for a missing credential.

**Approvals need their own key, one per person.** *Why:* an agent must never approve its
own request, and the audit trail should name a real person. *Cost:* keys live in
environment variables; no rotation, expiry or sign-on yet.

**Waiting for approval in the proxy is off by default.** *Why:* it is only as strong as
the approver keys staying with people.

**Real-model results are rejected if any attempt timed out or fell back.** *Why:* a
timeout is recorded as "no success" and a fallback silently swaps in the stand-in, so
either one makes the table meaningless. See [EVIDENCE.md](EVIDENCE.md).

**Proprietary license, all rights reserved,** with an MIT carve-out for versions
previously published under MIT. *Why:* the owner wants sole rights. *Cost:* adoption is
harder than with an open license. The repo is public, so the code is readable but not
licensed for use. Whether to open-source the scanner is an open question
([ROADMAP.md](ROADMAP.md)). The license text has not been reviewed by a lawyer.

**The proxy package is marked "Private :: Do Not Upload".** *Why:* it is proprietary and
should not reach PyPI by accident.
