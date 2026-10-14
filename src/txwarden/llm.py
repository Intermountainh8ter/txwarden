"""LLM abstraction. Messages use the Anthropic content-block format."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class Reply:
    content: list[dict[str, Any]]
    stop_reason: str  # "tool_use" | "end_turn"


class LLM(Protocol):
    def create(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Reply: ...


class LLMError(RuntimeError):
    """The language model could not be used (SDK missing, no API key, request failed).

    Never affects a verdict: the deterministic engine does not need the model."""


class AnthropicLLM:
    def __init__(self, model: str | None = None, max_tokens: int = 1024):
        try:
            import anthropic  # optional dependency: pip install txwarden[llm]
        except ImportError as e:
            raise LLMError("the `anthropic` package is not installed "
                           "(pip install 'txwarden[llm]')") from e
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise LLMError("ANTHROPIC_API_KEY is not set")
        self.client = anthropic.Anthropic()
        self.model = model or os.environ.get("TXWARDEN_MODEL", "claude-sonnet-5-5")
        self.max_tokens = max_tokens

    def create(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Reply:
        try:
            r = self.client.messages.create(
                model=self.model, max_tokens=self.max_tokens, system=system,
                messages=messages, tools=tools,
            )
        except Exception as e:  # SDK errors are many and version-specific; all mean "no model"
            raise LLMError(f"{type(e).__name__}: {e}") from e
        blocks = [b.model_dump(exclude_none=True) for b in r.content]
        return Reply(blocks, r.stop_reason)


class ScriptedLLM:
    """Deterministic stand-in for tests: replays a fixed list of replies."""

    def __init__(self, replies: list[Reply]):
        self.replies = list(replies)
        self.calls: list[list[dict[str, Any]]] = []

    def create(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Reply:
        self.calls.append(list(messages))
        if not self.replies:
            raise AssertionError("ScriptedLLM exhausted")
        return self.replies.pop(0)
