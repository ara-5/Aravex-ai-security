# The feedback loop: finding -> rule -> approval -> verification

```
attack campaign ──▶ findings ──▶ draft rules ──▶ human approval ──▶ active rules
       ▲                                                                  │
       └──────────── replay every finding's attack ◀──────────────────────┘
                        result recorded as a VerificationResult
```

Run it: `python scripts/run_loop.py propose --work DIR`, review `DIR/proposals.json`,
then `python scripts/run_loop.py verify --work DIR --approve prop-9-1 --reviewer NAME`.
`demo` does both and approves every draft; use it only for demos.

## Design rules

- **Nothing applies without a person.** Rules are generated as drafts. Only
  approved ones reach the gateway, and the reviewer is recorded.
- **Narrow rules.** Keyed on agent, action, resource category and, where it
  matters, destination and data classification. Never a blanket block on a tool.
- **A rule that blocks normal work is rejected.** Each candidate is checked,
  with the gateway's own matcher, against `loop/aravex_loop/benign.py`. After
  activation the same actions are sent to the live gateway and must still be
  allowed.
- **Conservative effect.** Credentials, privilege changes and bulk export are
  `DENY`. Anything ambiguous is `HUMAN_APPROVAL`.
- **Only what a gateway can see.** Model-level categories (jailbreak,
  system-prompt extraction) get no rule, and neither does an attack that
  succeeded without any tool call.
- **Verification is a replay,** reusing the red-team engine's regression runner.
  A finding counts as blocked only if its exact attack no longer succeeds.

## Result (one run, over-permissioned identity `nova-assistant-broad`)

| | |
|---|---|
| Open findings behind the gateway | 10 |
| Draft rules proposed | 1 |
| Rejected (would block benign work) | 1 |
| No rule possible (model-level, or no gateway-visible action) | 8 |
| Approved and activated | 1 (`aravex_gen_9_1`, DENY `iam` access) |
| Findings blocked after activation | **1 of 10** (the one with a rule) |
| Benign actions still allowed | 5 of 5 |

That is a small number, and it is the honest one. Most of what still succeeds
is not something a gateway rule can stop. Finding #10 (a plain customer-DB read)
is indistinguishable from legitimate use by rule, so the loop correctly refused
to propose one.

## From approval to CI

`python scripts/run_loop.py promote --work DIR` moves rules that are approved by a
named reviewer **and** verified blocked into `policies/`:

| File | Purpose |
|---|---|
| `policies/approved_rules.yaml` | The rules the gateway loads via `ARAVEX_EXTRA_RULES` |
| `policies/approvals.json` | Who approved each rule, and why it was proposed |
| `policies/gate_baseline.json` | Findings that must stay blocked |

`promote` refuses a rule with no reviewer, one that was only auto-approved by
`demo`, or one that was not verified blocked.

## Works under OPA as well as the YAML matcher

The gateway translates the extra rules to Rego (`gateway/policy/rego_export.py`) and
installs them on the OPA server at startup through OPA's REST API. Only the
conditions the YAML matcher supports are translated; anything else is refused
rather than guessed. If OPA is unreachable the gateway falls back to the YAML
matcher, which already has the rules. If OPA is reachable but rejects the module,
startup fails, because carrying on would run OPA without rules the operator
believes are active. Each proposal carries its Rego so a reviewer sees both forms.

Parity is tested, not assumed: for each rule shape the YAML matcher and a live OPA
are compared over 960 generated inputs (3,840 comparisons) and must agree on every one.

## The CI gate

`.github/workflows/verification-gate.yml` runs `tests/gate` against a real OPA and
fails the build when:

- an approved rule stops keeping its finding blocked, under **either** backend;
- a **control run without the rules** no longer shows the attack succeeding. A gate
  that cannot fail proves nothing. While building it, this check caught a harness
  bug where every call was rejected with a 401, which had made the first version
  pass for the wrong reason;
- the rules start blocking benign actions;
- a rule has no named reviewer, or no baseline entry to verify it.

CI sets `REQUIRE_OPA=1`, so a missing OPA fails the build instead of skipping.

## Limits

- **Rules are generalized from one example** (category + action + destination),
  so they can be too broad or too narrow for other cases. The benign set is a
  small hand-written list, and a rule is only as safe as that list is complete.
- **The gate replays seed attacks** from the red-team engine, not every mutated
  variant that found the original issue. A rule could stop the seed and miss a
  rephrased attack.
- **Target is the deterministic offline stand-in**, not a real model. One run.
- **The gate covers rules in `policies/`.** The base policy and the least-privilege
  identity are covered by their own tests, not by this gate.
