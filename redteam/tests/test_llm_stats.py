"""The target counts how often the configured model really answered, so a run that
silently fell back to the stand-in cannot pass for a real-model result."""
from __future__ import annotations

from target_agent import llm


class _Provider:
    def __init__(self, name, answer):
        self.name, self._answer = name, answer

    def generate(self, *args):
        return self._answer


def _call():
    return llm.call_llm([], [], "hello", [])


def _delta(monkeypatch, provider):
    monkeypatch.setattr(llm, "get_provider", lambda name=None: provider)
    before = dict(llm._stats)
    _call()
    return {k: llm._stats[k] - before[k] for k in ("calls", "fallbacks")}


def test_a_failed_real_model_call_counts_as_a_fallback(monkeypatch):
    assert _delta(monkeypatch, _Provider("ollama", None)) == {"calls": 1, "fallbacks": 1}


def test_a_successful_real_model_call_is_not_a_fallback(monkeypatch):
    answer = llm.LLMResponse(content="hi", tool_calls=[], raw="hi")
    assert _delta(monkeypatch, _Provider("ollama", answer)) == {"calls": 1, "fallbacks": 0}


def test_the_stand_in_is_never_counted_as_a_fallback(monkeypatch):
    assert _delta(monkeypatch, llm._fallback) == {"calls": 1, "fallbacks": 0}


def test_stats_report_the_active_provider(monkeypatch):
    monkeypatch.setattr(llm, "get_provider", lambda name=None: _Provider("ollama", None))
    assert llm.stats()["provider"] == "ollama"
