# Evidence log

What has been measured, how, and what it does and does not show. Entries are kept
even when they went wrong, because the failures explain why later numbers can be
trusted.

## 1. Stand-in model, seed attacks only (2026-10-30)

`MAX_MUTATIONS_PER_TECHNIQUE=0 python scripts/compare_defense.py`

| | Successful attacks |
|---|---:|
| Target without the gateway | 19 |
| Target behind the gateway (least-privilege identity) | 6 |

Same result as the earlier full campaign with mutations, so seed-only runs are a fair
quick baseline. The target is the deterministic offline stand-in, not a language
model, and it takes the bait on almost every seed. **This shows the mechanism works.
It does not show how a real model behaves.**

## 2. Real model, first attempt: invalid (2026-10-30)

Same command with `LLM_PROVIDER=ollama OLLAMA_MODEL=llama3.2:3b`. Result: 0 successes
bare and 0 behind the gateway. **Discarded.**

Cause: on this machine (laptop CPU, 16 GB) one chat takes about 40 seconds. The
red-team client waited 30 seconds and the model call 20, so attacks timed out and were
recorded as "no success". On a model timeout the target also falls back to the stand-in
model without saying so, so a "real model" run could be partly the stand-in. A direct
probe showed the model calling the file-read tool when asked, so zero was not safety.

Fixes: `TARGET_TIMEOUT` and `OLLAMA_TIMEOUT` are now settings; the target counts model
calls and fallbacks (`/admin/state`, `llm`); and `compare_defense.py` refuses to print a
table when any attempt timed out or any real-model call fell back.

## 3. Real model, valid run (2026-10-30)

`MAX_MUTATIONS_PER_TECHNIQUE=0 LLM_PROVIDER=ollama OLLAMA_MODEL=llama3.2:3b OLLAMA_TIMEOUT=300 TARGET_TIMEOUT=400 python scripts/compare_defense.py`

50 model calls in the gateway run, none fell back, no attempt timed out. One run.

| Category | Gateway can address | Techniques | Bare | Behind gateway |
|---|---|---:|---:|---:|
| agent_to_agent | gateway | 1 | 0 | 0 |
| data_exfiltration | gateway | 2 | 0 | 0 |
| excessive_agency | gateway | 1 | 0 | 0 |
| jailbreak | model | 3 | 3 | 1 |
| mcp_attacks | gateway | 3 | 0 | 0 |
| memory_poisoning | partial | 2 | 0 | 0 |
| privilege_escalation | gateway | 2 | 0 | 0 |
| prompt_injection | partial | 1 | 1 | 1 |
| rag_poisoning | partial | 1 | 0 | 0 |
| system_prompt_extraction | model | 3 | 1 | 1 |
| tool_poisoning | gateway | 2 | 0 | 0 |
| **Total** | | 23 | **5** | **3** |

What this shows and does not show:

- **It does not demonstrate the gateway's value.** Every category the gateway can
  address had 0 successes even without it. This small model rarely did anything
  harmful with tools on seed attacks, so there was nothing for the gateway to block.
- **The 5 → 3 difference is not a gateway effect.** The drop is in `jailbreak`, a
  model-level category the gateway does not address, from a model that answers
  differently each time. Treat it as run-to-run variance.
- **The stand-in is far more exploitable than this model** (19 vs 5 successes bare),
  so the stand-in numbers overstate how vulnerable a real agent is.
- Not tested: larger models, models that follow the tool-call format reliably,
  mutated attacks, repeated runs. Only a model that actually takes harmful tool
  actions can show whether the gateway helps.
