"""
LLM entry point for the target agent — a thin dispatcher over the
pluggable providers in llm_providers.py.

Kept as its own module (re-exporting ContextBlock/LLMResponse) so
agents.py's imports don't need to change as providers evolve. The
configured provider (LLM_PROVIDER: naive | ollama | openai_compatible)
is tried first; on any failure/unavailability it falls back to the
deterministic NaiveLLMProvider, so the agent never hard-fails on a
misconfigured or unreachable model backend.
"""
from __future__ import annotations

from target_agent.config import SYSTEM_PROMPT
from target_agent.llm_providers import (
    ContextBlock,
    LLMResponse,
    NaiveLLMProvider,
    get_provider,
)

_fallback = NaiveLLMProvider()


def call_llm(
    context_blocks: list[ContextBlock],
    history: list[dict],
    user_message: str,
    tool_specs: list[dict],
    system_prompt: str = SYSTEM_PROMPT,
) -> LLMResponse:
    provider = get_provider()
    result = provider.generate(system_prompt, context_blocks, history, user_message, tool_specs)
    if result is not None:
        return result
    if provider.name == _fallback.name:
        # Shouldn't happen (naive never returns None) but keep it safe.
        return _fallback.generate(system_prompt, context_blocks, history, user_message, tool_specs)
    return _fallback.generate(system_prompt, context_blocks, history, user_message, tool_specs)


__all__ = ["ContextBlock", "LLMResponse", "call_llm"]
