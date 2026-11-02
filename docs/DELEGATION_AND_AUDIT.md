# Delegation and evidence: capabilities and a tamper-evident audit trail

Two pieces for systems where agents hand work to other agents.

## 1. Capabilities: authority that can be handed down but only ever shrinks

An orchestrator agent usually should not give a sub-agent everything it holds. A capability is
a token that says what its holder may do. The holder can pass a **narrower** copy to the next
agent, and that agent to another, without asking the gateway and without any key. Nobody in the
chain can widen what they got, remove a restriction, or forge a token.

```bash
export GATEWAY_CAPABILITY_ROOT_KEY=<at least 16 random bytes; set on the gateway and the minting tool>

# the platform mints a token for the orchestrator (needs the root key)
python -m gateway.capabilities mint --id orchestrator-1 --agent nova-assistant \
    --tools filesystem_tool,email_tool --ttl 3600

# the orchestrator narrows it for a sub-agent (needs no key)
python -m gateway.capabilities attenuate <token> --tools filesystem_tool \
    --prefix filesystem.reports/ --actions read

python -m gateway.capabilities inspect <token>      # shows restrictions; does not check the signature
```

The sub-agent presents it with each call, as the `X-Aravex-Capability` header. The MCP proxy does
this when `ARAVEX_CAPABILITY` is set in its environment.

**Restrictions:** `agent_id`, `tools`, `actions`, `resource_prefixes`, `destinations`,
`max_record_count`, `expires`. All of them must hold at once, so adding one can only narrow.

**How it works.** The token carries its restrictions and a signature. The signature starts as
`HMAC(root_key, id)` and each restriction re-signs it: `sig = HMAC(previous_sig, restriction)`.
Anyone holding a token can append a restriction because they hold the signature so far. Removing
or changing one needs the signature from before it, which they do not have. Only the gateway, with
the root key, recomputes the chain and checks it. This is the macaroon construction.

**A capability only restricts.** It is checked in addition to the normal policy, never instead of
it. The most permissive token possible still cannot read secrets, because the base rules decide.
A refused capability returns `DENY` with the matched rule `capability`, is written to the audit
trail, and counts toward the anomaly tracker.

Gateway settings: `GATEWAY_CAPABILITY_ROOT_KEY` (verify tokens) and `GATEWAY_REQUIRE_CAPABILITY=1`
(refuse any call that carries none). With neither, existing callers behave exactly as before.
A token presented to a gateway with no root key configured is refused, not ignored.

Safety choices: every token must expire; an unknown restriction kind is a failure; resource
restrictions are plain prefixes (a regex added by an untrusted sub-agent could stall the gateway);
a resource containing `..` never satisfies a prefix; tokens and restriction lists are size-limited.

**Limits**
- **No revocation.** A token is valid until it expires, so keep lifetimes short. Rotating the root
  key invalidates every token at once.
- **Bearer tokens.** Whoever holds the token can use it. It is not bound to a machine or key.
- **Stateless:** no "at most 3 calls" restriction, because that needs shared counters.
- The root key is a single shared secret held by the gateway and the minting tool.

## 2. A tamper-evident audit trail

Set `AUDIT_CHAIN_PATH` and the gateway also writes every decision and approval resolution to a
hash chain: each entry commits to the one before it. Edit a record, or delete, insert or reorder
entries, and verification fails and says where.

```bash
export AUDIT_CHAIN_PATH=/var/aravex/audit.chain
export AUDIT_CHAIN_KEY=<secret held by the gateway>      # optional but recommended

python -m gateway.audit.chain verify /var/aravex/audit.chain \
    --expect-head <hash you recorded elsewhere>
```

What each setting buys you, and what it does not:

| | Detects edits, deletions, inserts, reordering | Stops a full rewrite by someone who can edit the file | Detects entries cut off the end |
|---|---|---|---|
| Plain chain | yes | **no** | no |
| With `AUDIT_CHAIN_KEY` | yes | yes (they lack the key) | no |
| With `--expect-head` / `--expect-entries` recorded somewhere the log's writer cannot reach | yes | yes | yes |

The tests include the two failures on purpose: a plain chain can be rewritten from scratch and
still verify, and a truncated chain is a valid chain. Treat the chain as evidence only if the key
stays out of reach of whoever stores the log and the head is anchored elsewhere.

**Other limits**
- One process writes the chain; two gateways appending to one file would fork it.
- Once `AUDIT_CHAIN_PATH` is set, a failed write fails the request. Evidence-grade audit that
  silently drops entries is worse than an outage. Plan for the disk filling up.
- The chain records what the gateway decided. It does not prove what the agent then did.
