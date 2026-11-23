"""Bounded agent harness loop, durable traces with secret redaction, checkpoints, and hooks."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from {{PACKAGE_NAME}}.provider import (
    HarnessProfile,
    LLMProvider,
    Message,
    ToolCall,
    canonical_json,
)
from {{PACKAGE_NAME}}.tools import ApprovalPolicy, ToolRegistry, ToolResult

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b"), "[REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b"), "[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{16,}"), "Bearer [REDACTED]"),
    (
        re.compile(r"(?i)([?&](?:X-Amz-Signature|access_token|token|sig|api_key)=)[^&\s\"']+"),
        r"\1[REDACTED]",
    ),
)


def redact_secrets(value: Any) -> Any:
    """Recursively redact credentials and signed tokens before writing traces."""
    if isinstance(value, str):
        redacted = value
        for pattern, replacement in SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    if isinstance(value, dict):
        return {str(k): redact_secrets(v) for k, v in value.items()}
    return value


@dataclass(frozen=True)
class BudgetConfig:
    """Orthogonal runtime limits enforced in code, never by prompt wishes."""

    max_steps: int = 12
    max_tokens_in: int = 200_000
    max_tokens_out: int = 50_000
    max_cost_usd: float = 2.0
    max_wall_time_s: float = 120.0
    max_messages: int = 64
    max_working_seconds: float = 120.0
    soft_warning_fraction: float = 0.75

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if self.max_tokens_in < 1 or self.max_tokens_out < 1:
            raise ValueError("Token budgets must be >= 1")
        if self.max_cost_usd < 0 or self.max_wall_time_s <= 0 or self.max_working_seconds <= 0:
            raise ValueError("Cost must be >= 0 and time limits > 0")
        if self.max_messages < 2:
            raise ValueError("max_messages must be >= 2")
        if not (0.0 < self.soft_warning_fraction <= 1.0):
            raise ValueError("soft_warning_fraction must be in (0, 1]")


class TraceWriter:
    """Append-only JSONL event log emitting OTel GenAI compatible records with secret redaction."""

    def __init__(self, path: Path, trace_id: str | None = None, session_id: str | None = None) -> None:
        self.path = path
        self.trace_id = trace_id or uuid.uuid4().hex
        self.session_id = session_id or uuid.uuid4().hex
        self._last_ts_ns = 0
        self._dir_ensured = False

    def _next_timestamp(self) -> str:
        now_ns = time.time_ns()
        if now_ns <= self._last_ts_ns:
            now_ns = self._last_ts_ns + 1_000
        self._last_ts_ns = now_ns
        dt = datetime.fromtimestamp(now_ns / 1_000_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _build_record(
        self,
        *,
        event_type: str,
        operation_name: str,
        step: int,
        status: str = "ok",
        tokens_in: int = 0,
        tokens_cached: int = 0,
        tokens_out: int = 0,
        thinking_tokens: int = 0,
        payload: dict[str, Any] | None = None,
        top_level: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {}
        if top_level:
            record.update(redact_secrets(top_level))
        record.update(
            {
                "event_type": event_type,
                "gen_ai.operation.name": operation_name,
                "payload": redact_secrets(payload or {}),
                "session_id": self.session_id,
                "status": status,
                "step": step,
                "thinking_tokens": thinking_tokens,
                "timestamp": self._next_timestamp(),
                "tokens_cached": tokens_cached,
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "trace_id": self.trace_id,
            }
        )
        return record

    def _append_line(self, line: str) -> None:
        if not self._dir_ensured:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._dir_ensured = True
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()

    def write_event(
        self,
        *,
        event_type: str,
        operation_name: str,
        step: int,
        status: str = "ok",
        tokens_in: int = 0,
        tokens_cached: int = 0,
        tokens_out: int = 0,
        thinking_tokens: int = 0,
        payload: dict[str, Any] | None = None,
        top_level: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = self._build_record(
            event_type=event_type,
            operation_name=operation_name,
            step=step,
            status=status,
            tokens_in=tokens_in,
            tokens_cached=tokens_cached,
            tokens_out=tokens_out,
            thinking_tokens=thinking_tokens,
            payload=payload,
            top_level=top_level,
        )
        self._append_line(canonical_json(record))
        return record

    async def write_event_async(
        self,
        *,
        event_type: str,
        operation_name: str,
        step: int,
        status: str = "ok",
        tokens_in: int = 0,
        tokens_cached: int = 0,
        tokens_out: int = 0,
        thinking_tokens: int = 0,
        payload: dict[str, Any] | None = None,
        top_level: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = self._build_record(
            event_type=event_type,
            operation_name=operation_name,
            step=step,
            status=status,
            tokens_in=tokens_in,
            tokens_cached=tokens_cached,
            tokens_out=tokens_out,
            thinking_tokens=thinking_tokens,
            payload=payload,
            top_level=top_level,
        )
        line = canonical_json(record)
        await asyncio.to_thread(self._append_line, line)
        return record


def derive_messages_from_events(events: Sequence[dict[str, Any]]) -> list[Message]:
    """Pure projection: derive model-visible Message history from canonical JSONL trace events."""
    drafts: list[dict[str, Any]] = []
    assistant_by_step: dict[int, int] = {}
    last_assistant_idx: int | None = None

    for event in events:
        ev_type = str(event.get("event_type", "")).lower()
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        step = event.get("step") if isinstance(event.get("step"), int) else 0

        if ev_type == "agent_start":
            if isinstance(payload.get("system_prompt"), str):
                drafts.append({"role": "system", "content": payload["system_prompt"]})
            if isinstance(payload.get("user_input"), str):
                drafts.append({"role": "user", "content": payload["user_input"]})
        elif ev_type == "user/message":
            content = event.get("content")
            if content is None:
                content = payload.get("content", "")
            drafts.append({"role": "user", "content": str(content)})
        elif ev_type == "assistant/message":
            content = event.get("content")
            if content is None:
                content = payload.get("content", "")
            draft: dict[str, Any] = {
                "role": "assistant",
                "content": str(content),
                "tool_calls": [],
                "reasoning_content": (
                    payload["reasoning_content"]
                    if isinstance(payload.get("reasoning_content"), str)
                    else None
                ),
                "thinking_blocks": (
                    copy.deepcopy(payload["thinking_blocks"])
                    if isinstance(payload.get("thinking_blocks"), list)
                    else []
                ),
            }
            idx = len(drafts)
            drafts.append(draft)
            assistant_by_step[step] = idx
            last_assistant_idx = idx
        elif ev_type == "tool/call":
            call_id = str(event.get("tool_call_id") or payload.get("tool_call_id") or "")
            tool_name = str(event.get("tool_name") or payload.get("tool_name") or "")
            raw_args = event.get("arguments") if "arguments" in event else payload.get("arguments", {})
            args_dict = copy.deepcopy(raw_args) if isinstance(raw_args, dict) else {}
            target_idx = assistant_by_step.get(step, last_assistant_idx)
            if target_idx is not None and drafts[target_idx]["role"] == "assistant":
                drafts[target_idx]["tool_calls"].append(
                    ToolCall(id=call_id, name=tool_name, arguments=args_dict)
                )
        elif ev_type == "tool/result":
            call_id = str(event.get("tool_call_id") or payload.get("tool_call_id") or "")
            tool_name = str(event.get("tool_name") or payload.get("tool_name") or "")
            output = event.get("output")
            if output is None:
                output = payload.get("output", "")
            drafts.append(
                {
                    "role": "tool",
                    "content": str(output),
                    "tool_call_id": call_id,
                    "name": tool_name,
                }
            )

    messages: list[Message] = []
    for item in drafts:
        role = item["role"]
        if role == "assistant":
            messages.append(
                Message(
                    role="assistant",
                    content=item["content"],
                    tool_calls=tuple(item["tool_calls"]),
                    reasoning_content=item["reasoning_content"],
                    thinking_blocks=tuple(item["thinking_blocks"]),
                )
            )
        elif role == "tool":
            messages.append(
                Message(
                    role="tool",
                    content=item["content"],
                    tool_call_id=item["tool_call_id"],
                    name=item["name"],
                )
            )
        else:
            messages.append(Message(role=role, content=item["content"]))
    return messages


def derive_messages_from_trace(trace_path: Path) -> list[Message]:
    """Reconstruct model-visible messages directly from an append-only JSONL session trace file."""
    events: list[dict[str, Any]] = []
    for raw_line in trace_path.read_text(encoding="utf-8-sig").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        events.append(json.loads(stripped))
    return derive_messages_from_events(events)


class CheckpointStore:
    """Atomic temp-file + fsync + os.replace JSON checkpoint store for crash-safe pause/resume."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def _path_for(self, session_id: str) -> Path:
        safe_id = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in session_id)
        return self.directory / f"{safe_id}.checkpoint.json"

    def save(self, session_id: str, state: dict[str, Any]) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self._path_for(session_id)
        serialized = json.dumps(redact_secrets(state), sort_keys=True, indent=2, ensure_ascii=False)
        fd, tmp_name = tempfile.mkstemp(dir=str(self.directory), prefix=".ckpt_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(serialized + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, target)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
        return target

    async def save_async(self, session_id: str, state: dict[str, Any]) -> Path:
        return await asyncio.to_thread(self.save, session_id, state)

    def load(self, session_id: str) -> dict[str, Any] | None:
        target = self._path_for(session_id)
        if not target.exists():
            return None
        return json.loads(target.read_text(encoding="utf-8-sig"))

    async def load_async(self, session_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.load, session_id)


@dataclass
class HookContext:
    """Mutable per-run state passed to deletable middleware hooks."""

    step: int
    messages: list[Message]
    mutated: bool = False
    verified_after_mutation: bool = False
    verification_nudges: int = 0
    tool_history: list[str] = field(default_factory=list)


class MiddlewareHook:
    """Deletable middleware interface; remove any hook cleanly as models improve."""

    def pre_step(self, ctx: HookContext) -> None:
        return None

    def pre_tool(self, ctx: HookContext, tool_call: ToolCall) -> str | None:
        return None

    def post_tool(
        self,
        ctx: HookContext,
        tool_call: ToolCall,
        result: ToolResult,
        *,
        mutating: bool,
        verification: bool,
    ) -> None:
        return None

    def pre_exit(self, ctx: HookContext, final_content: str) -> str | None:
        return None


class LoopDetectionHook(MiddlewareHook):
    """Detects identical consecutive tool calls and breaks doom loops deterministically."""

    def __init__(self, max_identical_repeats: int = 2) -> None:
        if max_identical_repeats < 1:
            raise ValueError("max_identical_repeats must be >= 1")
        self.max_identical_repeats = max_identical_repeats
        self._last_signature: str | None = None
        self._repeat_count = 0

    def pre_tool(self, ctx: HookContext, tool_call: ToolCall) -> str | None:
        signature = f"{tool_call.name}:{canonical_json(tool_call.arguments)}"
        if signature == self._last_signature:
            self._repeat_count += 1
        else:
            self._last_signature = signature
            self._repeat_count = 1

        if self._repeat_count > self.max_identical_repeats:
            return (
                f"ERROR [doom_loop_detected]: Identical call to '{tool_call.name}' repeated "
                f"{self._repeat_count} times with unchanged arguments. Change approach or stop."
            )
        return None


class PreCompletionVerifyHook(MiddlewareHook):
    """Deterministic exit gate nudging verification when mutations occurred without passing checks."""

    def __init__(self, max_nudges: int = 1) -> None:
        self.max_nudges = max_nudges

    def post_tool(
        self,
        ctx: HookContext,
        tool_call: ToolCall,
        result: ToolResult,
        *,
        mutating: bool,
        verification: bool,
    ) -> None:
        if result.ok and mutating:
            ctx.mutated = True
            ctx.verified_after_mutation = False
        elif verification:
            ctx.verified_after_mutation = result.ok

    def pre_exit(self, ctx: HookContext, final_content: str) -> str | None:
        if ctx.mutated and not ctx.verified_after_mutation and ctx.verification_nudges < self.max_nudges:
            ctx.verification_nudges += 1
            return (
                "Before finishing, run a verification tool (such as verify_file) to confirm "
                "your workspace changes against the expected outcome."
            )
        return None


@dataclass(frozen=True)
class RunResult:
    """Structured final result of an AgentHarness run."""

    session_id: str
    trace_id: str
    final_output: str
    stop_reason: str
    steps: int
    tokens_in: int
    tokens_cached: int
    tokens_out: int
    thinking_tokens: int
    cost_usd: float
    tool_calls_made: tuple[str, ...]
    messages: tuple[Message, ...]


class AgentHarness:
    """Bounded, inspectable agent runtime enforcing production invariants in code."""

    def __init__(
        self,
        *,
        provider: LLMProvider,
        tools: ToolRegistry,
        profile: HarnessProfile | None = None,
        budget: BudgetConfig | None = None,
        trace_writer: TraceWriter,
        checkpoint_store: CheckpointStore,
        approval_policy: ApprovalPolicy | None = None,
        spill_dir: Path,
        hooks: Sequence[MiddlewareHook] | None = None,
    ) -> None:
        self.provider = provider
        self.tools = tools
        self.profile = profile or HarnessProfile()
        self.budget = budget or BudgetConfig()
        self.trace = trace_writer
        self.checkpoints = checkpoint_store
        self.approval_policy = approval_policy or ApprovalPolicy()
        self.spill_dir = spill_dir
        if hooks is not None:
            self.hooks = list(hooks)
        else:
            default_hooks: list[MiddlewareHook] = []
            if self.profile.enable_loop_detection:
                default_hooks.append(LoopDetectionHook())
            if self.profile.enable_pre_completion_verify:
                default_hooks.append(PreCompletionVerifyHook())
            self.hooks = default_hooks

    async def run(self, user_input: str, *, resume: bool = False) -> RunResult:
        started = time.monotonic()
        tool_schemas = self.tools.schemas()

        messages: list[Message] = []
        start_step = 1
        totals: dict[str, Any] = {
            "cost_usd": 0.0,
            "thinking_tokens": 0,
            "tokens_cached": 0,
            "tokens_in": 0,
            "tokens_out": 0,
        }
        tool_calls_made: list[str] = []
        mutated = False
        verified_after_mutation = False
        verification_nudges = 0
        working_seconds = 0.0
        soft_warning_sent = False

        if resume:
            saved = await self.checkpoints.load_async(self.trace.session_id)
            if saved is not None:
                saved_messages = [Message.from_dict(m) for m in saved.get("messages", ())]
                if bool(saved.get("completed", False)):
                    last_assistant = next(
                        (m.content for m in reversed(saved_messages) if m.role == "assistant"),
                        "",
                    )
                    saved_totals = saved.get("totals", {})
                    return RunResult(
                        session_id=str(saved.get("session_id", self.trace.session_id)),
                        trace_id=str(saved.get("trace_id", self.trace.trace_id)),
                        final_output=last_assistant,
                        stop_reason=str(saved.get("stop_reason", "completed")),
                        steps=int(saved.get("step", 0)),
                        tokens_in=int(saved_totals.get("tokens_in", 0)),
                        tokens_cached=int(saved_totals.get("tokens_cached", 0)),
                        tokens_out=int(saved_totals.get("tokens_out", 0)),
                        thinking_tokens=int(saved_totals.get("thinking_tokens", 0)),
                        cost_usd=float(saved_totals.get("cost_usd", 0.0)),
                        tool_calls_made=tuple(saved.get("tool_calls_made", ())),
                        messages=tuple(saved_messages),
                    )
                messages = saved_messages
                start_step = int(saved.get("step", 0)) + 1
                totals.update(saved.get("totals", {}))
                tool_calls_made = list(saved.get("tool_calls_made", ()))
                mutated = bool(saved.get("mutated", False))
                verified_after_mutation = bool(saved.get("verified_after_mutation", False))
                verification_nudges = int(saved.get("verification_nudges", 0))
                working_seconds = float(saved.get("working_seconds", 0.0))
                soft_warning_sent = bool(saved.get("soft_warning_sent", False))

        if not messages:
            messages = [
                Message(role="system", content=self.profile.system_prompt),
                Message(role="user", content=user_input),
            ]
            await self.trace.write_event_async(
                event_type="agent_start",
                operation_name="invoke_agent",
                step=0,
                payload={
                    "profile": self.profile.name,
                    "system_prompt": self.profile.system_prompt,
                    "user_input": user_input,
                },
            )

        ctx = HookContext(
            step=start_step,
            messages=messages,
            mutated=mutated,
            verified_after_mutation=verified_after_mutation,
            verification_nudges=verification_nudges,
            tool_history=tool_calls_made,
        )

        last_output = ""
        stop_reason = "max_steps"
        executed_steps = start_step - 1

        for step in range(start_step, self.budget.max_steps + 1):
            ctx.step = step
            wall_elapsed_s = time.monotonic() - started
            if wall_elapsed_s > self.budget.max_wall_time_s:
                stop_reason = "wall_time_exceeded"
                break
            if working_seconds > self.budget.max_working_seconds:
                stop_reason = "working_time_exceeded"
                break
            if len(messages) >= self.budget.max_messages:
                stop_reason = "message_budget_exceeded"
                break
            if totals["tokens_in"] >= self.budget.max_tokens_in:
                stop_reason = "token_in_budget_exceeded"
                break
            if totals["tokens_out"] >= self.budget.max_tokens_out:
                stop_reason = "token_out_budget_exceeded"
                break
            if totals["cost_usd"] > self.budget.max_cost_usd:
                stop_reason = "cost_budget_exceeded"
                break

            if not soft_warning_sent:
                utilizations = (
                    ("steps", (step - 1) / self.budget.max_steps),
                    ("tokens_in", totals["tokens_in"] / self.budget.max_tokens_in),
                    ("tokens_out", totals["tokens_out"] / self.budget.max_tokens_out),
                    (
                        "cost_usd",
                        totals["cost_usd"] / self.budget.max_cost_usd if self.budget.max_cost_usd > 0 else 0.0,
                    ),
                    ("messages", len(messages) / self.budget.max_messages),
                    ("wall_time", wall_elapsed_s / self.budget.max_wall_time_s),
                    ("working_time", working_seconds / self.budget.max_working_seconds),
                )
                metric_name, highest_util = max(utilizations, key=lambda pair: pair[1])
                if highest_util >= self.budget.soft_warning_fraction:
                    soft_warning_sent = True
                    pct = min(100, round(highest_util * 100))
                    warning_text = (
                        f"[BUDGET WARNING]: Approaching {metric_name} budget limit ({pct}% used). "
                        "Wrap up verification and deliver your concise final answer."
                    )
                    messages.append(Message(role="user", content=warning_text))
                    await self.trace.write_event_async(
                        event_type="user/message",
                        operation_name="plan",
                        step=step,
                        top_level={"content": warning_text},
                        payload={
                            "content": warning_text,
                            "kind": "budget_warning",
                            "metric": metric_name,
                            "utilization": round(highest_util, 4),
                        },
                    )

            executed_steps = step
            for hook in self.hooks:
                hook.pre_step(ctx)

            remaining_wall_s = self.budget.max_wall_time_s - (time.monotonic() - started)
            remaining_working_s = self.budget.max_working_seconds - working_seconds
            call_timeout_s = min(remaining_wall_s, remaining_working_s)
            if call_timeout_s <= 0:
                stop_reason = (
                    "wall_time_exceeded"
                    if remaining_wall_s <= remaining_working_s
                    else "working_time_exceeded"
                )
                break

            llm_started = time.monotonic()
            try:
                response = await asyncio.wait_for(
                    self.provider.complete(messages, tool_schemas, self.profile),
                    timeout=call_timeout_s,
                )
            except asyncio.TimeoutError:
                working_seconds += time.monotonic() - llm_started
                stop_reason = (
                    "wall_time_exceeded"
                    if (time.monotonic() - started) >= self.budget.max_wall_time_s
                    else "working_time_exceeded"
                )
                break
            working_seconds += time.monotonic() - llm_started

            totals["tokens_in"] += response.usage.tokens_in
            totals["tokens_cached"] += response.usage.tokens_cached
            totals["tokens_out"] += response.usage.tokens_out
            totals["thinking_tokens"] += response.usage.thinking_tokens
            totals["cost_usd"] += response.usage.cost_usd

            assistant_msg = Message(
                role="assistant",
                content=response.content,
                tool_calls=response.tool_calls,
                reasoning_content=(
                    response.reasoning_content if self.profile.preserve_reasoning_content else None
                ),
                thinking_blocks=(
                    response.thinking_blocks if self.profile.preserve_thinking_blocks else ()
                ),
            )
            messages.append(assistant_msg)
            last_output = response.content

            turn_stop_reason = "tool_use" if response.tool_calls else response.stop_reason
            assistant_payload: dict[str, Any] = {
                "content": response.content,
                "has_reasoning": assistant_msg.reasoning_content is not None,
                "stop_reason": turn_stop_reason,
                "tool_call_count": len(response.tool_calls),
            }
            if assistant_msg.reasoning_content is not None:
                assistant_payload["reasoning_content"] = assistant_msg.reasoning_content
            if assistant_msg.thinking_blocks:
                assistant_payload["thinking_blocks"] = copy.deepcopy(list(assistant_msg.thinking_blocks))

            await self.trace.write_event_async(
                event_type="assistant/message",
                operation_name="chat",
                step=step,
                tokens_in=response.usage.tokens_in,
                tokens_cached=response.usage.tokens_cached,
                tokens_out=response.usage.tokens_out,
                thinking_tokens=response.usage.thinking_tokens,
                top_level={
                    "content": response.content,
                    "stop_reason": turn_stop_reason,
                },
                payload=assistant_payload,
            )

            if response.tool_calls:
                circuit_tripped = False
                for tc in response.tool_calls:
                    tool_calls_made.append(tc.name)
                    await self.trace.write_event_async(
                        event_type="tool/call",
                        operation_name="execute_tool",
                        step=step,
                        top_level={
                            "arguments": tc.arguments,
                            "tool_call_id": tc.id,
                            "tool_name": tc.name,
                        },
                        payload={
                            "arguments": tc.arguments,
                            "tool_call_id": tc.id,
                            "tool_name": tc.name,
                        },
                    )

                    blocked_reason: str | None = None
                    for hook in self.hooks:
                        blocked_reason = hook.pre_tool(ctx, tc)
                        if blocked_reason is not None:
                            break

                    tool_started = time.monotonic()
                    if blocked_reason is not None:
                        result = ToolResult(
                            tool_call_id=tc.id,
                            name=tc.name,
                            output=blocked_reason,
                            ok=False,
                            duration_ms=0.0,
                            error_code="hook_blocked",
                        )
                    else:
                        result = await self.tools.execute(
                            tc,
                            approval_policy=self.approval_policy,
                            spill_dir=self.spill_dir,
                            max_output_chars=self.profile.max_output_chars,
                            default_timeout_s=self.profile.default_tool_timeout_s,
                            aliases=self.profile.tool_aliases,
                        )
                    working_seconds += time.monotonic() - tool_started

                    if result.approval_decision == "modify":
                        await self.trace.write_event_async(
                            event_type="approval/decision",
                            operation_name="execute_tool",
                            step=step,
                            top_level={
                                "tool_call_id": tc.id,
                                "tool_name": result.name,
                            },
                            payload={
                                "decision": "modify",
                                "modified_arguments": result.executed_arguments or {},
                                "tool_call_id": tc.id,
                                "tool_name": result.name,
                            },
                        )

                    spec = self.tools.get(tc.name, aliases=self.profile.tool_aliases)
                    for hook in self.hooks:
                        hook.post_tool(
                            ctx,
                            tc,
                            result,
                            mutating=bool(spec and spec.mutating),
                            verification=bool(spec and spec.verification),
                        )

                    # Emit tool outputs strictly with role="tool" and preserve failed turns in context.
                    messages.append(
                        Message(
                            role="tool",
                            content=result.output,
                            tool_call_id=tc.id,
                            name=result.name,
                        )
                    )
                    await self.trace.write_event_async(
                        event_type="tool/result",
                        operation_name="execute_tool",
                        step=step,
                        status="ok" if result.ok else "error",
                        top_level={
                            "is_error": not result.ok,
                            "output": result.output,
                            "tool_call_id": tc.id,
                            "tool_name": result.name,
                        },
                        payload={
                            "duration_ms": round(result.duration_ms, 2),
                            "error_code": result.error_code,
                            "is_error": not result.ok,
                            "output": result.output,
                            "spill_path": result.spill_path,
                            "tool_call_id": tc.id,
                            "tool_name": result.name,
                            "truncated": result.truncated,
                        },
                    )

                    if self.approval_policy.circuit_open:
                        circuit_tripped = True

                await self._save_checkpoint_async(
                    step=step,
                    messages=messages,
                    totals=totals,
                    tool_calls_made=tool_calls_made,
                    mutated=ctx.mutated,
                    verified_after_mutation=ctx.verified_after_mutation,
                    verification_nudges=ctx.verification_nudges,
                    working_seconds=working_seconds,
                    soft_warning_sent=soft_warning_sent,
                    completed=False,
                    stop_reason="in_progress",
                )

                if circuit_tripped:
                    stop_reason = (
                        "approval_circuit_breaker"
                        if self.approval_policy.consecutive_rejections
                        >= self.approval_policy.max_consecutive_rejections
                        else "approval_terminated"
                    )
                    break
                continue

            exit_nudge: str | None = None
            for hook in self.hooks:
                exit_nudge = hook.pre_exit(ctx, response.content)
                if exit_nudge is not None:
                    break

            if exit_nudge is not None:
                messages.append(Message(role="user", content=exit_nudge))
                await self.trace.write_event_async(
                    event_type="user/message",
                    operation_name="plan",
                    step=step,
                    top_level={"content": exit_nudge},
                    payload={"content": exit_nudge, "kind": "pre_exit_nudge"},
                )
                continue

            stop_reason = "completed"
            await self._save_checkpoint_async(
                step=step,
                messages=messages,
                totals=totals,
                tool_calls_made=tool_calls_made,
                mutated=ctx.mutated,
                verified_after_mutation=ctx.verified_after_mutation,
                verification_nudges=ctx.verification_nudges,
                working_seconds=working_seconds,
                soft_warning_sent=soft_warning_sent,
                completed=True,
                stop_reason=stop_reason,
            )
            break

        await self.trace.write_event_async(
            event_type="agent_end",
            operation_name="invoke_agent",
            step=executed_steps,
            status="ok" if stop_reason == "completed" else "stopped",
            top_level={"stop_reason": stop_reason},
            payload={
                "cost_usd": round(totals["cost_usd"], 6),
                "stop_reason": stop_reason,
                "steps": executed_steps,
                "working_seconds": round(working_seconds, 4),
            },
        )
        return RunResult(
            session_id=self.trace.session_id,
            trace_id=self.trace.trace_id,
            final_output=last_output,
            stop_reason=stop_reason,
            steps=executed_steps,
            tokens_in=int(totals["tokens_in"]),
            tokens_cached=int(totals["tokens_cached"]),
            tokens_out=int(totals["tokens_out"]),
            thinking_tokens=int(totals["thinking_tokens"]),
            cost_usd=float(totals["cost_usd"]),
            tool_calls_made=tuple(tool_calls_made),
            messages=tuple(messages),
        )

    async def _save_checkpoint_async(
        self,
        *,
        step: int,
        messages: Sequence[Message],
        totals: dict[str, Any],
        tool_calls_made: Sequence[str],
        mutated: bool,
        verified_after_mutation: bool,
        verification_nudges: int,
        working_seconds: float,
        soft_warning_sent: bool,
        completed: bool,
        stop_reason: str,
    ) -> None:
        await self.checkpoints.save_async(
            self.trace.session_id,
            {
                "completed": completed,
                "messages": [m.to_dict() for m in messages],
                "mutated": mutated,
                "session_id": self.trace.session_id,
                "soft_warning_sent": soft_warning_sent,
                "step": step,
                "stop_reason": stop_reason,
                "tool_calls_made": list(tool_calls_made),
                "totals": dict(totals),
                "trace_id": self.trace.trace_id,
                "verification_nudges": verification_nudges,
                "verified_after_mutation": verified_after_mutation,
                "working_seconds": round(working_seconds, 4),
            },
        )
