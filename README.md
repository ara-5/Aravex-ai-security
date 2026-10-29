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

Both projects were imported with full git history and still run as before;
see the README in each directory for setup.

## Status

Early integration. Today the two halves run side by side. Planned:

1. Route `target_agent` tool calls through the gateway (protected / unprotected toggle).
2. Report attack success with and without the gateway, per attack category.
3. Generate candidate Rego rules from confirmed findings.
4. Run the regression gate against gateway policies in CI.

Not every attack family is addressable at the gateway: jailbreaks and
system-prompt extraction happen inside the model and need model-level
defenses. The comparison report will say which categories the gateway
mitigates and which it does not.

## License

MIT. See [LICENSE](LICENSE).
