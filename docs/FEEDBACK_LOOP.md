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

## Limits

- **Local YAML matcher only.** Approved rules are loaded through
  `ARAVEX_EXTRA_RULES`. A gateway running against OPA evaluates its own Rego
  and does not see them. Emitting Rego (`PolicyProposal.rego`) is not done.
- **Rules are generalized from one example** (category + action + destination),
  so they can be too broad or too narrow for other cases. The benign set is a
  small hand-written list, and a rule is only as safe as that list is complete.
- **Target is the deterministic offline stand-in**, not a real model. One run.
- **Not a CI gate yet.** The verification runs by script, not on pull requests.
