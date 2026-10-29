# Aravex AI Security

**Attack. Defend. Verify.**

Aravex is one platform for securing AI agents end to end: an autonomous
red-team engine that attacks an agent system, a zero-trust runtime gateway
that bounds what a compromised agent can do, and a regression gate that proves
the defense holds.

```
 redteam/  ──attacks──▶  target agent  ──tool calls──▶  gateway/  ──▶ tools, data, MCP
    │                                                       │
    └──────── findings ──▶ policies ──▶ regression gate ◀───┘
```

## Layout

| Path | Origin | Role |
|---|---|---|
| [`redteam/`](redteam/) | AgentShield | Agentic red-team engine, 11 attack families, scorecard, dashboard, CI regression gate, plus the deliberately vulnerable `target_agent` |
| [`gateway/`](gateway/) | AegisAI | Zero-trust gateway: agent IAM, OPA/Rego policy engine, risk scoring, human approval, audit, observability |
| [`schemas/`](schemas/) | new | Shared contracts (`AgentAction`, `PolicyDecision`, `Finding`, `PolicyProposal`, `VerificationResult`) that let the two halves exchange data |
| [`tests/`](tests/) | new | Contract tests proving the shared schemas accept what both projects already produce |

Both projects were imported with full git history and still run as before;
see the README in each directory for setup.

## Status

Early integration. The two halves share a tested set of contracts
(`schemas/`), and the target agent can run behind the gateway
(`GATEWAY_MODE=enforce`). A first comparison on the 11-category campaign:
**19 successful attacks bare, 6 behind the gateway**, with every
gateway-addressable category at zero. See
[docs/DEFENSE_COMPARISON.md](docs/DEFENSE_COMPARISON.md) for method and caveats;
reproduce with `python scripts/compare_defense.py`.

Next:

1. Generate candidate Rego rules from confirmed findings (human-approved).
2. Re-run the campaign to verify each rule, and record the result as a `VerificationResult`.
3. Run that verification as a CI gate against gateway policies.
4. Expose the gateway as an MCP proxy.

Not every attack family is addressable at the gateway: jailbreaks and
system-prompt extraction happen inside the model and need model-level
defenses. The comparison report will say which categories the gateway
mitigates and which it does not.

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE).
