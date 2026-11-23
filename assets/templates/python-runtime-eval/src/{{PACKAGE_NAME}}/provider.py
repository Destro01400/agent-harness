"""Thin LLM provider seam, immutable message types, and declarative HarnessProfile."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, Sequence


def canonical_json(data: Any) -> str:
    """Serialize data deterministically with sorted keys to preserve KV-cache prefixes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class ToolCall:
    """Structured tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "arguments": copy.deepcopy(self.arguments),
            "id": self.id,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ToolCall:
        return cls(
            id=str(raw["id"]),
            name=str(raw["name"]),
            arguments=dict(raw.get("arguments", {})),
        )


@dataclass(frozen=True)
class Message:
    """Single conversation turn preserving reasoning/thinking blocks verbatim."""

    role: str
    content: str
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str | None = None
    name: str | None = None
    reasoning_content: str | None = None
    thinking_blocks: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "content": self.content,
            "role": self.role,
        }
        if self.tool_calls:
            payload["tool_calls"] = [tc.to_dict() for tc in self.tool_calls]
        if self.tool_call_id is not None:
            payload["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            payload["name"] = self.name
        if self.reasoning_content is not None:
            payload["reasoning_content"] = self.reasoning_content
        if self.thinking_blocks:
            payload["thinking_blocks"] = copy.deepcopy(list(self.thinking_blocks))
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Message:
        tool_calls = tuple(ToolCall.from_dict(tc) for tc in raw.get("tool_calls", ()))
        thinking_blocks = tuple(copy.deepcopy(b) for b in raw.get("thinking_blocks", ()))
        return cls(
            role=str(raw["role"]),
            content=str(raw.get("content", "")),
            tool_calls=tool_calls,
            tool_call_id=raw.get("tool_call_id"),
            name=raw.get("name"),
            reasoning_content=raw.get("reasoning_content"),
            thinking_blocks=thinking_blocks,
        )


@dataclass(frozen=True)
class Usage:
    """Token and cost accounting enforcing inclusive OTel GenAI invariants."""

    tokens_in: int = 0
    tokens_cached: int = 0
    tokens_out: int = 0
    thinking_tokens: int = 0
    cost_usd: float = 0.0

    def __post_init__(self) -> None:
        if self.tokens_in < 0 or self.tokens_cached < 0:
            raise ValueError("Input token counts must be non-negative")
        if self.tokens_cached > self.tokens_in:
            raise ValueError("tokens_cached cannot exceed tokens_in")
        if self.tokens_out < 0 or self.thinking_tokens < 0:
            raise ValueError("Output token counts must be non-negative")
        if self.thinking_tokens > self.tokens_out:
            raise ValueError("thinking_tokens cannot exceed tokens_out")
        if self.cost_usd < 0:
            raise ValueError("cost_usd must be non-negative")


@dataclass(frozen=True)
class ModelResponse:
    """Normalized provider response."""

    content: str
    tool_calls: tuple[ToolCall, ...] = ()
    usage: Usage = field(default_factory=Usage)
    reasoning_content: str | None = None
    thinking_blocks: tuple[dict[str, Any], ...] = ()
    stop_reason: str = "end_turn"


@dataclass(frozen=True)
class HarnessProfile:
    """Declarative per-model harness configuration (zero hardcoded model branches in loop)."""

    name: str = "default-profile"
    system_prompt: str = (
        "You are a focused, deterministic assistant. Use the registered tools to inspect "
        "and verify ground truth before answering concisely."
    )
    preserve_reasoning_content: bool = True
    preserve_thinking_blocks: bool = True
    tool_aliases: dict[str, str] = field(default_factory=dict)
    max_output_chars: int = 8_000
    default_tool_timeout_s: float = 15.0
    enable_loop_detection: bool = True
    enable_pre_completion_verify: bool = True
    temperature: float = 0.0


class LLMProvider(Protocol):
    """Minimal provider boundary; swap real SDKs without changing the loop."""

    async def complete(
        self,
        messages: Sequence[Message],
        tools: Sequence[dict[str, Any]],
        profile: HarnessProfile,
    ) -> ModelResponse:
        ...


ResponseGenerator = Callable[
    [Sequence[Message], Sequence[dict[str, Any]], HarnessProfile, int],
    ModelResponse,
]


class MockProvider:
    """Deterministic offline provider for tests, replay, and local eval runs."""

    def __init__(
        self,
        responses: Sequence[ModelResponse] | None = None,
        handler: ResponseGenerator | None = None,
    ) -> None:
        if responses is None and handler is None:
            raise ValueError("Provide either scripted responses or a handler callable")
        self._responses = list(responses or ())
        self._handler = handler
        self.recorded_calls: list[dict[str, Any]] = []
        self._call_index = 0

    async def complete(
        self,
        messages: Sequence[Message],
        tools: Sequence[dict[str, Any]],
        profile: HarnessProfile,
    ) -> ModelResponse:
        idx = self._call_index
        self._call_index += 1
        snapshot = {
            "call_index": idx,
            "messages": [m.to_dict() for m in messages],
            "profile": profile.name,
            "tools": copy.deepcopy(list(tools)),
        }
        self.recorded_calls.append(snapshot)

        if self._handler is not None:
            return self._handler(messages, tools, profile, idx)

        if idx >= len(self._responses):
            return ModelResponse(
                content="MockProvider exhausted scripted responses.",
                usage=Usage(tokens_in=64, tokens_cached=32, tokens_out=12, cost_usd=0.0001),
                stop_reason="end_turn",
            )
        return self._responses[idx]
