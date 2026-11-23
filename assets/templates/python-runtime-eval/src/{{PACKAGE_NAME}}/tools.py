"""Tool contracts, strict validation, timeouts, output spilling, containment, and approvals."""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal, Mapping, Sequence

from {{PACKAGE_NAME}}.provider import ToolCall

ApprovalDecision = Literal[
    "allow_once",
    "allow_session",
    "ask",
    "deny_once",
    "deny_session",
]

VALID_APPROVAL_DECISIONS: frozenset[str] = frozenset(
    {"allow_once", "allow_session", "ask", "deny_once", "deny_session"}
)

DEFAULT_ENV_ALLOWLIST: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TMP", "TEMP")


def build_safe_env(
    source_env: Mapping[str, str] | None = None,
    allowlist: Sequence[str] = DEFAULT_ENV_ALLOWLIST,
) -> dict[str, str]:
    """Construct an explicit zero-credential subprocess environment from an allowlist."""
    env_source = source_env if source_env is not None else os.environ
    return {key: env_source[key] for key in allowlist if key in env_source}


def resolve_in_workspace(workspace: Path, relative_path: str) -> Path:
    """Canonicalize a path with realpath and reject escapes outside workspace."""
    if not relative_path or not isinstance(relative_path, str):
        raise ValueError("Path must be a non-empty string")
    root = Path(os.path.realpath(workspace))
    candidate = Path(os.path.realpath(root / relative_path))
    if os.path.commonpath([str(root), str(candidate)]) != str(root):
        raise ValueError(
            f"Path '{relative_path}' resolves outside workspace root. "
            "Use a relative path inside the workspace."
        )
    return candidate


def truncate_and_spill(
    text: str,
    max_chars: int,
    spill_dir: Path,
    label: str,
) -> tuple[str, bool, str | None]:
    """Bound tool output in context while spilling full content atomically to disk."""
    if max_chars < 120:
        raise ValueError("max_chars must be at least 120")
    if len(text) <= max_chars:
        return text, False, None

    spill_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    safe_label = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in label)
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

    omitted = len(text) - max_chars
    notice = (
        f"\n... [truncated {omitted} chars; full output saved to {spill_path.name} "
        f"in spill directory] ...\n"
    )
    budget = max(40, max_chars - len(notice))
    head_len = budget // 2
    tail_len = budget - head_len
    bounded = f"{text[:head_len]}{notice}{text[-tail_len:]}"
    return bounded, True, str(spill_path)


class ApprovalPolicy:
    """Five-decision HITL approval policy with 3-consecutive-rejection circuit breaker."""

    def __init__(
        self,
        default_decision: ApprovalDecision = "allow_once",
        per_tool: Mapping[str, ApprovalDecision] | None = None,
        decider: Callable[[str, Mapping[str, Any]], ApprovalDecision] | None = None,
        max_consecutive_rejections: int = 3,
    ) -> None:
        if default_decision not in VALID_APPROVAL_DECISIONS:
            raise ValueError(f"Unsupported approval decision: {default_decision}")
        if max_consecutive_rejections < 1:
            raise ValueError("max_consecutive_rejections must be >= 1")
        self.default_decision = default_decision
        self._per_tool: dict[str, ApprovalDecision] = dict(per_tool or {})
        self._session_overrides: dict[str, ApprovalDecision] = {}
        self._decider = decider
        self.max_consecutive_rejections = max_consecutive_rejections
        self.consecutive_rejections = 0
        self.circuit_open = False

    def evaluate(self, tool_name: str, arguments: Mapping[str, Any]) -> tuple[bool, ApprovalDecision, str]:
        """Evaluate whether a tool call is approved, updating session state and circuit breaker."""
        if self.circuit_open:
            return (
                False,
                "deny_session",
                "Approval circuit breaker is open after repeated rejections. Stop and ask the user.",
            )

        decision: ApprovalDecision = self._session_overrides.get(
            tool_name,
            self._per_tool.get(tool_name, self.default_decision),
        )
        if decision == "ask":
            if self._decider is not None:
                decision = self._decider(tool_name, arguments)
            else:
                decision = "deny_once"

        if decision not in VALID_APPROVAL_DECISIONS:
            decision = "deny_once"

        if decision == "allow_session":
            self._session_overrides[tool_name] = "allow_session"
            self.consecutive_rejections = 0
            return True, decision, "Allowed for session"

        if decision == "allow_once":
            self.consecutive_rejections = 0
            return True, decision, "Allowed once"

        if decision == "deny_session":
            self._session_overrides[tool_name] = "deny_session"

        self.consecutive_rejections += 1
        if self.consecutive_rejections >= self.max_consecutive_rejections:
            self.circuit_open = True
            return (
                False,
                decision,
                f"Tool '{tool_name}' denied ({decision}); circuit breaker tripped after "
                f"{self.consecutive_rejections} consecutive rejections.",
            )

        return (
            False,
            decision,
            f"Tool '{tool_name}' was denied by approval policy ({decision}). "
            "Choose a safer read-only alternative or ask the user for clarification.",
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


def _matches_json_type(value: Any, expected_type: str) -> bool:
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
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
    """Deterministic registry enforcing schema validation, approvals, timeouts, and spilling."""

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

        approved, decision, reason = approval_policy.evaluate(spec.name, tool_call.arguments)
        if not approved:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=spec.name,
                output=f"ERROR [approval_denied:{decision}]: {reason}",
                ok=False,
                duration_ms=(time.monotonic() - started) * 1000.0,
                error_code=f"approval_denied:{decision}",
            )

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

        timeout_s = min(spec.timeout_s, default_timeout_s) if spec.timeout_s > 0 else default_timeout_s
        try:
            raw_output = await asyncio.wait_for(spec.handler(dict(tool_call.arguments)), timeout=timeout_s)
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
            )

        bounded, truncated, spill_path = truncate_and_spill(
            str(raw_output),
            max_chars=max_output_chars,
            spill_dir=spill_dir,
            label=f"{spec.name}_{tool_call.id}",
        )
        return ToolResult(
            tool_call_id=tool_call.id,
            name=spec.name,
            output=bounded,
            ok=True,
            duration_ms=(time.monotonic() - started) * 1000.0,
            truncated=truncated,
            spill_path=spill_path,
        )


def create_default_tools(workspace: Path) -> ToolRegistry:
    """Create a minimal workspace-contained file toolset for offline runs and evals."""
    root = workspace.resolve()

    async def read_file(args: dict[str, Any]) -> str:
        target = resolve_in_workspace(root, args["path"])
        content = await asyncio.to_thread(target.read_text, encoding="utf-8")
        return content

    async def write_file(args: dict[str, Any]) -> str:
        target = resolve_in_workspace(root, args["path"])

        def _write() -> str:
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
        target = resolve_in_workspace(root, rel)

        def _list() -> str:
            if not target.exists():
                raise FileNotFoundError(f"Directory not found: {rel}")
            entries = sorted(
                str(p.relative_to(root)).replace("\\", "/")
                for p in target.rglob("*")
                if p.is_file()
            )
            return "\n".join(entries) if entries else "(empty workspace)"

        return await asyncio.to_thread(_list)

    async def verify_file(args: dict[str, Any]) -> str:
        target = resolve_in_workspace(root, args["path"])
        expected = args.get("contains", "")

        def _verify() -> str:
            if not target.exists():
                raise FileNotFoundError(f"File not found: {args['path']}")
            text = target.read_text(encoding="utf-8")
            if expected and expected not in text:
                return f"VERIFY_FAIL: '{args['path']}' does not contain '{expected}'."
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
