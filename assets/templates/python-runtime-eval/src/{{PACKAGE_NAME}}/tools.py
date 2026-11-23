"""Tool contracts, strict validation, timeouts, output spilling, containment, and approvals."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import math
import os
import tempfile
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal, Mapping, Sequence

from {{PACKAGE_NAME}}.provider import ToolCall

ApprovalDecision = Literal[
    "approve",
    "modify",
    "reject",
    "escalate",
    "terminate",
]

VALID_APPROVAL_DECISIONS: frozenset[str] = frozenset(
    {"approve", "modify", "reject", "escalate", "terminate"}
)

DEFAULT_ENV_ALLOWLIST: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TMP", "TEMP")

PROTECTED_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        ".git",
        ".vscode",
        ".cursor",
        ".agents",
        "mcp.json",
        ".npmrc",
        ".pypirc",
    }
)

ALLOWED_ENV_TEMPLATES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
    }
)


class ToolExecutionError(RuntimeError):
    """Recoverable tool failure carrying a structured machine-readable error code."""

    def __init__(self, message: str, *, code: str = "execution_error") -> None:
        super().__init__(message)
        self.code = code


def build_safe_env(
    source_env: Mapping[str, str] | None = None,
    allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
) -> dict[str, str]:
    """Construct an explicit zero-credential subprocess environment from an allowlist."""
    env_source = source_env if source_env is not None else os.environ
    return {key: env_source[key] for key in allowlist if key in env_source}


def _is_protected_segment(segment: str) -> bool:
    norm = unicodedata.normalize("NFC", segment).casefold()
    if norm in PROTECTED_PATH_SEGMENTS:
        return True
    if norm in ALLOWED_ENV_TEMPLATES:
        return False
    return norm == ".env" or norm.startswith(".env.")


def resolve_in_workspace(workspace: Path, relative_path: str) -> Path:
    """Canonicalize a path with realpath, reject escapes, and block NFC protected paths."""
    if not relative_path or not isinstance(relative_path, str) or "\x00" in relative_path:
        raise ValueError("Path must be a non-empty string without NUL bytes")
    root = Path(os.path.realpath(workspace))
    candidate = Path(os.path.realpath(root / relative_path))
    try:
        common = os.path.commonpath([str(root), str(candidate)])
    except ValueError as exc:
        raise ValueError(
            f"Path '{relative_path}' resolves outside workspace root. "
            "Use a relative path inside the workspace."
        ) from exc
    if common != str(root):
        raise ValueError(
            f"Path '{relative_path}' resolves outside workspace root. "
            "Use a relative path inside the workspace."
        )

    rel_parts = candidate.relative_to(root).parts
    for seg in rel_parts:
        if _is_protected_segment(seg):
            raise ValueError(
                f"Access to protected path '{relative_path}' ('{seg}') is denied by workspace policy."
            )
    return candidate


def _build_bounded_spill_output(text: str, max_chars: int, spill_path: Path) -> str:
    file_name = spill_path.name

    def _notice(omitted: int) -> str:
        return f"\n...[truncated {omitted} chars; full: {file_name}]...\n"

    kept = max(0, max_chars - len(_notice(len(text))))
    for _ in range(4):
        omitted = len(text) - kept
        notice = _notice(omitted)
        next_kept = max(0, max_chars - len(notice))
        if next_kept == kept:
            break
        kept = next_kept

    omitted = len(text) - kept
    notice = _notice(omitted)
    if len(notice) > max_chars:
        return f"\n...[truncated {len(text)} chars]...\n"[:max_chars]

    if kept + len(notice) > max_chars:
        kept = max(0, max_chars - len(notice))
        omitted = len(text) - kept
        notice = _notice(omitted)
        if kept + len(notice) > max_chars:
            kept = max(0, kept - (kept + len(notice) - max_chars))
            omitted = len(text) - kept
            notice = _notice(omitted)

    if kept == 0:
        return notice[:max_chars]
    head_len = kept // 2
    tail_len = kept - head_len
    tail = text[-tail_len:] if tail_len > 0 else ""
    return f"{text[:head_len]}{notice}{tail}"


def truncate_and_spill(
    text: str,
    max_chars: int,
    spill_dir: Path,
    label: str,
) -> tuple[str, bool, str | None]:
    """Bound tool output strictly <= max_chars while spilling full content atomically to disk."""
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 120:
        raise ValueError("max_chars must be an integer >= 120")
    if len(text) <= max_chars:
        return text, False, None

    spill_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in label)[:32] or "tool"
    spill_path = spill_dir / f"{safe_label}_{digest}.txt"

    fd, tmp_name = tempfile.mkstemp(dir=str(spill_dir), prefix=".spill_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, spill_path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise

    bounded = _build_bounded_spill_output(text, max_chars, spill_path)
    return bounded, True, str(spill_path)


@dataclass(frozen=True)
class ApprovalDirective:
    """Rich approval response returned by custom deciders (supports modify without in-place mutation)."""

    decision: ApprovalDecision
    reason: str = ""
    modified_arguments: dict[str, Any] | None = None
    tool_name: str | None = None


@dataclass(frozen=True)
class ApprovalEvaluation:
    """Normalized outcome of ApprovalPolicy.evaluate()."""

    approved: bool
    decision: ApprovalDecision
    reason: str
    modified_arguments: dict[str, Any] | None = None
    terminate_run: bool = False


ApprovalDecider = Callable[[str, Mapping[str, Any]], ApprovalDecision | ApprovalDirective]


def _normalize_directive(raw: ApprovalDecision | ApprovalDirective) -> ApprovalDirective:
    if isinstance(raw, str):
        return ApprovalDirective(decision=raw)
    return raw


class ApprovalPolicy:
    """Inspect AI aligned 5-decision HITL policy (`approve`/`modify`/`reject`/`escalate`/`terminate`)."""

    def __init__(
        self,
        default_decision: ApprovalDecision | None = None,
        per_tool: Mapping[str, ApprovalDecision] | None = None,
        decider: ApprovalDecider | None = None,
        escalators: Sequence[ApprovalDecider] = (),
        max_consecutive_rejections: int = 3,
    ) -> None:
        resolved_default: ApprovalDecision = (
            default_decision
            if default_decision is not None
            else ("escalate" if decider is not None else "approve")
        )
        if resolved_default not in VALID_APPROVAL_DECISIONS:
            raise ValueError(f"Unsupported approval decision: {resolved_default}")
        if isinstance(max_consecutive_rejections, bool) or max_consecutive_rejections < 1:
            raise ValueError("max_consecutive_rejections must be >= 1")
        for tool, rule in (per_tool or {}).items():
            if rule not in VALID_APPROVAL_DECISIONS:
                raise ValueError(f"Unsupported approval decision '{rule}' for tool '{tool}'")

        self.default_decision: ApprovalDecision = resolved_default
        self._per_tool: dict[str, ApprovalDecision] = dict(per_tool or {})
        self._decider = decider
        self._escalators: tuple[ApprovalDecider, ...] = tuple(escalators)
        self.max_consecutive_rejections = max_consecutive_rejections
        self.consecutive_rejections = 0
        self.circuit_open = False

    def evaluate(self, tool_name: str, arguments: Mapping[str, Any]) -> ApprovalEvaluation:
        """Evaluate whether a tool call is approved without mutating proposed arguments in place."""
        if self.circuit_open:
            return ApprovalEvaluation(
                approved=False,
                decision="terminate",
                reason="Approval circuit breaker is open after repeated rejections. Run terminated.",
                terminate_run=True,
            )

        base_decision: ApprovalDecision = self._per_tool.get(tool_name, self.default_decision)
        directive = ApprovalDirective(decision=base_decision)

        layers: list[ApprovalDecider] = []
        if self._decider is not None:
            layers.append(self._decider)
        layers.extend(self._escalators)

        if directive.decision == "escalate":
            for layer in layers:
                snapshot = copy.deepcopy(dict(arguments))
                directive = _normalize_directive(layer(tool_name, snapshot))
                if directive.decision != "escalate":
                    break

        decision: ApprovalDecision = (
            directive.decision if directive.decision in VALID_APPROVAL_DECISIONS else "reject"
        )

        if directive.tool_name is not None and directive.tool_name != tool_name:
            return self._record_rejection(
                tool_name,
                "reject",
                f"Approval policy cannot rename tool '{tool_name}' to '{directive.tool_name}'.",
            )

        if decision == "approve":
            self.consecutive_rejections = 0
            return ApprovalEvaluation(
                approved=True,
                decision="approve",
                reason=directive.reason or "Approved by policy",
                terminate_run=False,
            )

        if decision == "modify":
            if not isinstance(directive.modified_arguments, dict):
                return self._record_rejection(
                    tool_name,
                    "reject",
                    "Approval decision 'modify' requires a dict in modified_arguments.",
                )
            self.consecutive_rejections = 0
            return ApprovalEvaluation(
                approved=True,
                decision="modify",
                reason=directive.reason or "Approved with modified arguments",
                modified_arguments=copy.deepcopy(directive.modified_arguments),
                terminate_run=False,
            )

        if decision == "terminate":
            self.circuit_open = True
            return ApprovalEvaluation(
                approved=False,
                decision="terminate",
                reason=directive.reason or f"Tool '{tool_name}' triggered immediate termination.",
                terminate_run=True,
            )

        default_reason = (
            f"Tool '{tool_name}' was escalated with no approver accepting the call."
            if decision == "escalate"
            else f"Tool '{tool_name}' was rejected by approval policy."
        )
        return self._record_rejection(tool_name, decision, directive.reason or default_reason)

    def _record_rejection(
        self,
        tool_name: str,
        decision: ApprovalDecision,
        reason: str,
    ) -> ApprovalEvaluation:
        self.consecutive_rejections += 1
        if self.consecutive_rejections >= self.max_consecutive_rejections:
            self.circuit_open = True
            return ApprovalEvaluation(
                approved=False,
                decision="terminate",
                reason=(
                    f"Tool '{tool_name}' rejected ({decision}); circuit breaker upgraded to "
                    f"terminate after {self.consecutive_rejections} consecutive rejections. {reason}"
                ),
                terminate_run=True,
            )
        return ApprovalEvaluation(
            approved=False,
            decision=decision,
            reason=f"{reason} Choose a safer read-only alternative or ask the user.",
            terminate_run=False,
        )


ToolHandler = Callable[[dict[str, Any]], Awaitable[str]]


@dataclass(frozen=True)
class ToolSpec:
    """Declarative tool contract with JSON Schema parameters and examples."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: ToolHandler
    timeout_s: float = 15.0
    mutating: bool = False
    verification: bool = False
    input_examples: tuple[dict[str, Any], ...] = ()

    def to_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "description": self.description,
            "name": self.name,
            "parameters": self.parameters,
        }
        if self.input_examples:
            schema["input_examples"] = list(self.input_examples)
        return schema


@dataclass(frozen=True)
class ToolResult:
    """Structured result of executing one tool call."""

    tool_call_id: str
    name: str
    output: str
    ok: bool
    duration_ms: float
    truncated: bool = False
    spill_path: str | None = None
    error_code: str | None = None
    approval_decision: ApprovalDecision | None = None
    executed_arguments: dict[str, Any] | None = None


def _matches_json_type(value: Any, expected_type: str) -> bool:
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "object":
        return isinstance(value, dict)
    return True


def validate_tool_arguments(spec: ToolSpec, arguments: Any) -> str | None:
    """Validate required fields, types, and extra properties; return actionable hint on error."""
    if not isinstance(arguments, dict):
        return (
            f"ERROR [invalid_arguments]: Tool '{spec.name}' expects a JSON object, "
            f"got {type(arguments).__name__}."
        )

    schema = spec.parameters
    properties: dict[str, Any] = schema.get("properties", {})
    required: Sequence[str] = schema.get("required", ())

    missing = [key for key in required if key not in arguments]
    if missing:
        return (
            f"ERROR [missing_required]: Tool '{spec.name}' is missing required parameter(s): "
            f"{', '.join(missing)}. Expected properties: {', '.join(sorted(properties))}."
        )

    if schema.get("additionalProperties") is False:
        extra = sorted(set(arguments.keys()) - set(properties.keys()))
        if extra:
            return (
                f"ERROR [unknown_parameter]: Tool '{spec.name}' received unsupported parameter(s): "
                f"{', '.join(extra)}. Allowed: {', '.join(sorted(properties))}."
            )

    for key, val in arguments.items():
        prop_schema = properties.get(key)
        if not isinstance(prop_schema, dict):
            continue
        expected_type = prop_schema.get("type")
        if isinstance(expected_type, str) and not _matches_json_type(val, expected_type):
            return (
                f"ERROR [type_mismatch]: Parameter '{key}' for tool '{spec.name}' must be "
                f"type '{expected_type}', got '{type(val).__name__}'."
            )
    return None


class ToolRegistry:
    """Deterministic registry enforcing schema-first validation, approvals, timeouts, and spilling."""

    def __init__(self, tools: Sequence[ToolSpec] = ()) -> None:
        self._tools: dict[str, ToolSpec] = {}
        for spec in tools:
            self.register(spec)

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"Duplicate tool registration: {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str, aliases: Mapping[str, str] | None = None) -> ToolSpec | None:
        resolved = aliases.get(name, name) if aliases else name
        return self._tools.get(resolved)

    def schemas(self) -> list[dict[str, Any]]:
        """Return tool definitions in stable sorted order for KV-cache prefix invariance."""
        return [self._tools[name].to_schema() for name in sorted(self._tools)]

    async def execute(
        self,
        tool_call: ToolCall,
        *,
        approval_policy: ApprovalPolicy,
        spill_dir: Path,
        max_output_chars: int = 8_000,
        default_timeout_s: float = 15.0,
        aliases: Mapping[str, str] | None = None,
    ) -> ToolResult:
        started = time.monotonic()
        spec = self.get(tool_call.name, aliases=aliases)
        if spec is None:
            available = ", ".join(sorted(self._tools)) or "(none)"
            return ToolResult(
                tool_call_id=tool_call.id,
                name=tool_call.name,
                output=(
                    f"ERROR [unknown_tool]: Tool '{tool_call.name}' is not registered. "
                    f"Available tools: {available}."
                ),
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                error_code="unknown_tool",
            )

        # 1. Validate arguments against JSON schema BEFORE approval so malformed calls never prompt or trip breaker.
        validation_error = validate_tool_arguments(spec, tool_call.arguments)
        if validation_error is not None:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=spec.name,
                output=validation_error,
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                error_code="invalid_arguments",
            )

        # 2. Evaluate Inspect AI 5-decision ApprovalPolicy on a defensive copy.
        approval = approval_policy.evaluate(spec.name, tool_call.arguments)
        if not approval.approved:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=spec.name,
                output=f"ERROR [approval_denied:{approval.decision}]: {approval.reason}",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                error_code=f"approval_denied:{approval.decision}",
                approval_decision=approval.decision,
            )

        if approval.decision == "modify":
            revalidation_error = validate_tool_arguments(spec, approval.modified_arguments)
            if revalidation_error is not None:
                return ToolResult(
                    tool_call_id=tool_call.id,
                    name=spec.name,
                    output=(
                        "ERROR [invalid_modified_arguments]: Approval policy 'modify' produced "
                        f"invalid arguments: {revalidation_error}"
                    ),
                    ok=False,
                    duration_ms=(time.monotonic() - started) * 1000.0,
                    error_code="invalid_modified_arguments",
                    approval_decision=approval.decision,
                )
            effective_args = copy.deepcopy(approval.modified_arguments or {})
        else:
            effective_args = copy.deepcopy(dict(tool_call.arguments))

        timeout_s = min(spec.timeout_s, default_timeout_s) if spec.timeout_s > 0 else default_timeout_s
        try:
            raw_output = await asyncio.wait_for(
                spec.handler(copy.deepcopy(effective_args)),
                timeout=timeout_s,
            )
        except ToolExecutionError as exc:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=spec.name,
                output=f"ERROR [{exc.code}]: {exc}",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                error_code=exc.code,
                approval_decision=approval.decision,
                executed_arguments=effective_args,
            )
        except asyncio.TimeoutError:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=spec.name,
                output=(
                    f"ERROR [timeout]: Tool '{spec.name}' exceeded its {timeout_s:.2f}s timeout. "
                    "Narrow the request scope or retry with smaller input."
                ),
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                error_code="timeout",
                approval_decision=approval.decision,
                executed_arguments=effective_args,
            )
        except Exception as exc:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=spec.name,
                output=(
                    f"ERROR [execution_error]: Tool '{spec.name}' failed with "
                    f"{type(exc).__name__}: {exc}. Inspect arguments and retry safely."
                ),
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                error_code="execution_error",
                approval_decision=approval.decision,
                executed_arguments=effective_args,
            )

        bounded, truncated, spill_path = await asyncio.to_thread(
            truncate_and_spill,
            str(raw_output),
            max_output_chars,
            spill_dir,
            f"{spec.name}_{tool_call.id}",
        )
        return ToolResult(
            tool_call_id=tool_call.id,
            name=spec.name,
            output=bounded,
            ok=True,
            duration_ms=(time.monotonic() - started) * 1000.0,
            truncated=truncated,
            spill_path=spill_path,
            approval_decision=approval.decision,
            executed_arguments=effective_args,
        )


def create_default_tools(workspace: Path) -> ToolRegistry:
    """Create a minimal workspace-contained file toolset for offline runs and evals."""
    root = workspace.resolve()

    async def read_file(args: dict[str, Any]) -> str:
        def _read() -> str:
            target = resolve_in_workspace(root, args["path"])
            return target.read_text(encoding="utf-8")

        return await asyncio.to_thread(_read)

    async def write_file(args: dict[str, Any]) -> str:
        def _write() -> str:
            root_real = Path(os.path.realpath(root))
            target = resolve_in_workspace(root_real, args["path"])
            if target == root_real:
                raise ToolExecutionError(
                    "Refusing to overwrite workspace root directory.",
                    code="invalid_path",
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".write_", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(args["content"])
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_name, target)
            except Exception:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
                raise
            return f"Wrote {len(args['content'])} chars to {args['path']}."

        return await asyncio.to_thread(_write)

    async def list_files(args: dict[str, Any]) -> str:
        rel = args.get("directory", ".")

        def _list() -> str:
            root_real = Path(os.path.realpath(root))
            target = resolve_in_workspace(root_real, rel)
            if not target.exists():
                raise FileNotFoundError(f"Directory not found: {rel}")
            entries: list[str] = []
            for p in target.rglob("*"):
                if not p.is_file():
                    continue
                rel_parts = p.relative_to(root_real).parts
                if any(_is_protected_segment(part) for part in rel_parts):
                    continue
                entries.append(str(p.relative_to(root_real)).replace("\\", "/"))
            entries.sort()
            return "\n".join(entries) if entries else "(empty workspace)"

        return await asyncio.to_thread(_list)

    async def verify_file(args: dict[str, Any]) -> str:
        expected = args.get("contains", "")

        def _verify() -> str:
            target = resolve_in_workspace(root, args["path"])
            if not target.exists():
                raise FileNotFoundError(f"File not found: {args['path']}")
            text = target.read_text(encoding="utf-8")
            if expected and expected not in text:
                raise ToolExecutionError(
                    f"VERIFY_FAIL: '{args['path']}' does not contain '{expected}'.",
                    code="verify_failed",
                )
            return f"VERIFY_OK: '{args['path']}' exists ({len(text)} chars)."

        return await asyncio.to_thread(_verify)

    registry = ToolRegistry(
        [
            ToolSpec(
                name="list_files",
                description="List files inside a workspace-relative directory.",
                parameters={
                    "additionalProperties": False,
                    "properties": {"directory": {"type": "string"}},
                    "required": [],
                    "type": "object",
                },
                handler=list_files,
                input_examples=({"directory": "."},),
            ),
            ToolSpec(
                name="read_file",
                description="Read a UTF-8 text file inside the workspace.",
                parameters={
                    "additionalProperties": False,
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "type": "object",
                },
                handler=read_file,
                input_examples=({"path": "notes.txt"},),
            ),
            ToolSpec(
                name="verify_file",
                description="Deterministically verify that a workspace file exists and optionally contains text.",
                parameters={
                    "additionalProperties": False,
                    "properties": {
                        "contains": {"type": "string"},
                        "path": {"type": "string"},
                    },
                    "required": ["path"],
                    "type": "object",
                },
                handler=verify_file,
                verification=True,
                input_examples=({"contains": "OK", "path": "result.txt"},),
            ),
            ToolSpec(
                name="write_file",
                description="Atomically write UTF-8 text to a workspace-relative path.",
                parameters={
                    "additionalProperties": False,
                    "properties": {
                        "content": {"type": "string"},
                        "path": {"type": "string"},
                    },
                    "required": ["path", "content"],
                    "type": "object",
                },
                handler=write_file,
                mutating=True,
                input_examples=({"content": "hello", "path": "result.txt"},),
            ),
        ]
    )
    return registry
