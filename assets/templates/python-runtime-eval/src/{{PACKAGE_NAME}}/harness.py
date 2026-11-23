"""Bounded agent harness loop, durable traces with secret redaction, checkpoints, and hooks."""

from __future__ import annotations

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
        re.compile(r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "[REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b"), "[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._-]{16,}"), "Bearer [REDACTED]"),
    (re.compile(r"([?&](?:X-Amz-Signature|token|sig|api_key)=)[^&\s\"']+"), r"\1[REDACTED]"),
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

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if self.max_tokens_in < 1 or self.max_tokens_out < 1:
            raise ValueError("Token budgets must be >= 1")
        if self.max_cost_usd < 0 or self.max_wall_time_s <= 0:
            raise ValueError("Cost must be >= 0 and max_wall_time_s > 0")


class TraceWriter:
    """Append-only JSONL event log emitting OTel GenAI compatible records with secret redaction."""

    def __init__(self, path: Path, trace_id: str | None = None, session_id: str | None = None) -> None:
        self.path = path
        self.trace_id = trace_id or uuid.uuid4().hex
        self.session_id = session_id or uuid.uuid4().hex
        self._last_ts_ns = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _next_timestamp(self) -> str:
        now_ns = time.time_ns()
        if now_ns <= self._last_ts_ns:
            now_ns = self._last_ts_ns + 1_000
        self._last_ts_ns = now_ns
        dt = datetime.fromtimestamp(now_ns / 1_000_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

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
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
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
        line = canonical_json(record)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()
        return record


class CheckpointStore:
    """Atomic temp-file + os.replace JSON checkpoint store for crash-safe pause/resume."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path_for(self, session_id: str) -> Path:
        safe_id = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in session_id)
        return self.directory / f"{safe_id}.checkpoint.json"

    def save(self, session_id: str, state: dict[str, Any]) -> Path:
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

    def load(self, session_id: str) -> dict[str, Any] | None:
        target = self._path_for(session_id)
        if not target.exists():
            return None
        return json.loads(target.read_text(encoding="utf-8"))


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

    def post_tool(self, ctx: HookContext, tool_call: ToolCall, result: ToolResult, *, mutating: bool, verification: bool) -> None:
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
    """Deterministic exit gate nudging verification when mutations occurred without checks."""

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
        elif result.ok and verification:
            ctx.verified_after_mutation = True

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
        totals = {
            "cost_usd": 0.0,
            "thinking_tokens": 0,
            "tokens_cached": 0,
            "tokens_in": 0,
            "tokens_out": 0,
        }
        tool_calls_made: list[str] = []
        mutated = False
        verified_after_mutation = False

        if resume:
            saved = self.checkpoints.load(self.trace.session_id)
            if saved is not None:
                messages = [Message.from_dict(m) for m in saved.get("messages", ())]
                start_step = int(saved.get("step", 0)) + 1
                totals.update(saved.get("totals", {}))
                tool_calls_made = list(saved.get("tool_calls_made", ()))
                mutated = bool(saved.get("mutated", False))
                verified_after_mutation = bool(saved.get("verified_after_mutation", False))

        if not messages:
            messages = [
                Message(role="system", content=self.profile.system_prompt),
                Message(role="user", content=user_input),
            ]
            self.trace.write_event(
                event_type="agent_start",
                operation_name="invoke_agent",
                step=0,
                payload={"profile": self.profile.name, "user_input": user_input},
            )

        ctx = HookContext(
            step=start_step,
            messages=messages,
            mutated=mutated,
            verified_after_mutation=verified_after_mutation,
            tool_history=tool_calls_made,
        )

        last_output = ""
        stop_reason = "max_steps"
        executed_steps = start_step - 1

        for step in range(start_step, self.budget.max_steps + 1):
            ctx.step = step
            if (time.monotonic() - started) > self.budget.max_wall_time_s:
                stop_reason = "wall_time_exceeded"
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

            executed_steps = step
            for hook in self.hooks:
                hook.pre_step(ctx)

            response = await self.provider.complete(messages, tool_schemas, self.profile)
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

            self.trace.write_event(
                event_type="model_response",
                operation_name="chat",
                step=step,
                tokens_in=response.usage.tokens_in,
                tokens_cached=response.usage.tokens_cached,
                tokens_out=response.usage.tokens_out,
                thinking_tokens=response.usage.thinking_tokens,
                payload={
                    "content": response.content,
                    "has_reasoning": assistant_msg.reasoning_content is not None,
                    "stop_reason": response.stop_reason,
                    "tool_call_count": len(response.tool_calls),
                },
            )

            if response.tool_calls:
                circuit_tripped = False
                for tc in response.tool_calls:
                    tool_calls_made.append(tc.name)
                    self.trace.write_event(
                        event_type="tool_call",
                        operation_name="execute_tool",
                        step=step,
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
                    self.trace.write_event(
                        event_type="tool_result",
                        operation_name="execute_tool",
                        step=step,
                        status="ok" if result.ok else "error",
                        payload={
                            "duration_ms": round(result.duration_ms, 2),
                            "error_code": result.error_code,
                            "output": result.output,
                            "spill_path": result.spill_path,
                            "tool_call_id": tc.id,
                            "tool_name": result.name,
                            "truncated": result.truncated,
                        },
                    )

                    if self.approval_policy.circuit_open:
                        circuit_tripped = True

                self._save_checkpoint(
                    step=step,
                    messages=messages,
                    totals=totals,
                    tool_calls_made=tool_calls_made,
                    mutated=ctx.mutated,
                    verified_after_mutation=ctx.verified_after_mutation,
                    completed=False,
                    stop_reason="in_progress",
                )

                if circuit_tripped:
                    stop_reason = "approval_circuit_breaker"
                    break
                continue

            exit_nudge: str | None = None
            for hook in self.hooks:
                exit_nudge = hook.pre_exit(ctx, response.content)
                if exit_nudge is not None:
                    break

            if exit_nudge is not None:
                messages.append(Message(role="user", content=exit_nudge))
                self.trace.write_event(
                    event_type="pre_exit_nudge",
                    operation_name="plan",
                    step=step,
                    payload={"nudge": exit_nudge},
                )
                continue

            stop_reason = "completed"
            self._save_checkpoint(
                step=step,
                messages=messages,
                totals=totals,
                tool_calls_made=tool_calls_made,
                mutated=ctx.mutated,
                verified_after_mutation=ctx.verified_after_mutation,
                completed=True,
                stop_reason=stop_reason,
            )
            break

        self.trace.write_event(
            event_type="agent_end",
            operation_name="invoke_agent",
            step=executed_steps,
            status="ok" if stop_reason == "completed" else "stopped",
            payload={
                "cost_usd": round(totals["cost_usd"], 6),
                "stop_reason": stop_reason,
                "steps": executed_steps,
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

    def _save_checkpoint(
        self,
        *,
        step: int,
        messages: Sequence[Message],
        totals: dict[str, Any],
        tool_calls_made: Sequence[str],
        mutated: bool,
        verified_after_mutation: bool,
        completed: bool,
        stop_reason: str,
    ) -> None:
        self.checkpoints.save(
            self.trace.session_id,
            {
                "completed": completed,
                "messages": [m.to_dict() for m in messages],
                "mutated": mutated,
                "session_id": self.trace.session_id,
                "step": step,
                "stop_reason": stop_reason,
                "tool_calls_made": list(tool_calls_made),
                "totals": dict(totals),
                "trace_id": self.trace.trace_id,
                "verified_after_mutation": verified_after_mutation,
            },
        )
