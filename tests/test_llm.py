import sys
import types

import pytest

from txwarden.llm import AnthropicLLM, Reply, ScriptedLLM


def test_scripted_llm_replays_in_order_records_calls_and_runs_out():
    llm = ScriptedLLM([Reply([{"type": "text", "text": "a"}], "end_turn"),
                       Reply([{"type": "text", "text": "b"}], "end_turn")])
    assert llm.create("sys", [{"role": "user", "content": "hi"}], []).content[0]["text"] == "a"
    assert llm.create("sys", [], []).content[0]["text"] == "b"
    assert len(llm.calls) == 2 and llm.calls[0][0]["content"] == "hi"
    with pytest.raises(AssertionError, match="exhausted"):
        llm.create("sys", [], [])


def test_anthropic_wrapper_uses_env_model_and_converts_blocks(monkeypatch):
    seen = {}

    class Block:
        def __init__(self, d):
            self.d = d

        def model_dump(self, exclude_none=False):
            return self.d

    class Messages:
        def create(self, **kw):
            seen.update(kw)
            return types.SimpleNamespace(content=[Block({"type": "text", "text": "ok"})],
                                         stop_reason="end_turn")

    fake = types.ModuleType("anthropic")
    fake.Anthropic = lambda: types.SimpleNamespace(messages=Messages())
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    monkeypatch.setenv("TXWARDEN_MODEL", "my-test-model")
    llm = AnthropicLLM()
    reply = llm.create("system text", [{"role": "user", "content": "x"}], [{"name": "t"}])
    assert reply.stop_reason == "end_turn" and reply.content == [{"type": "text", "text": "ok"}]
    assert seen["model"] == "my-test-model" and seen["system"] == "system text"
    assert AnthropicLLM(model="explicit").model == "explicit"
    monkeypatch.delenv("TXWARDEN_MODEL")
    assert AnthropicLLM().model  # falls back to the configurable default


def test_anthropic_wrapper_without_sdk_raises_import_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", None)  # makes `import anthropic` fail
    with pytest.raises(ImportError):
        AnthropicLLM()
