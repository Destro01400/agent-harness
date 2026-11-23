#!/usr/bin/env python3
"""Zero-dependency validator for agent harness JSONL traces, eval datasets, and eval summaries.

Usage:
  python validate_trace.py PATH [--mode {auto,trace,dataset,eval_summary}] [--strict] [--json] [--max-tool-chars 50000]
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import sys
from typing import Any

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

SECRET_LINE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("OpenAI/API secret key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("PEM private key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("Bearer token", re.compile(r"\bBearer\s+(?!(?i:\[?REDACTED\b))[A-Za-z0-9._-]{20,}")),
    (
        "Signed URL / token query param",
        re.compile(r"[?&](?:X-Amz-Signature|token|access_token|sig|api_key)=(?!(?i:\[?REDACTED\b))[^\"'\s&]{6,}"),
    ),
)

UNTRUSTED_FETCH_TOOL_RE = re.compile(
    r"(?:web_fetch|fetch_url|http_get|read_email|get_email|get_issue|read_issue|fetch_page|"
    r"browse|scrape|search_web|download|mcp_fetch|get_pr|read_comment|url_fetch|http_fetch|^fetch$)",
    re.IGNORECASE,
)

SENSITIVE_PATH_RE = re.compile(
    r"(?:~/?\.ssh|[/\\]\.ssh[/\\]|id_rsa|id_ed25519|"
    r"(?<![A-Za-z0-9_])\.env(?!\.(?:example|sample|template|dist|defaults?)\b)(?:\.[A-Za-z0-9_-]+)?(?![A-Za-z0-9_])|"
    r"mcp\.json|\.aws[/\\]credentials|\.npmrc|\.netrc|/etc/shadow|secrets\.json|credentials\.json)",
    re.IGNORECASE,
)

OUTBOUND_SEND_TOOL_RE = re.compile(
    r"(?:http_post|send_email|post_webhook|webhook|upload|send_message|slack_post|"
    r"create_comment|post_request|send_http|exfil|http_put|post_data)",
    re.IGNORECASE,
)

MUTATION_TOOL_RE = re.compile(
    r"(?:write_file|edit_file|patch_file|apply_patch|delete_file|create_file|save_file|"
    r"remove_file|rename_file|git_commit|db_write|sql_write|update_file|modify_file|write_|edit_|patch_|mutate_)",
    re.IGNORECASE,
)

VERIFICATION_TOOL_RE = re.compile(
    r"(?:run_tests?|pytest|unittest|npm_test|verify|lint|typecheck|check|build|compile|"
    r"validate|test_runner|run_eval|audit)",
    re.IGNORECASE,
)

VERIFICATION_CMD_RE = re.compile(
    r"\b(?:pytest|unittest|npm\s+test|pnpm\s+test|yarn\s+test|node\s+--test|tsc\b|eslint|ruff|"
    r"mypy|flake8|cargo\s+test|go\s+test|dotnet\s+(?:build|test)|jest|vitest|verify|validate|check)\b",
    re.IGNORECASE,
)

SHELL_TOOL_NAMES = {"bash", "shell", "run_command", "exec", "terminal", "run_shell", "subprocess"}

TOOL_CALL_EVENT_TYPES = {
    "tool_call",
    "tool_use",
    "execute_tool",
    "execute_tool_start",
    "tools/call",
    "tool/call",
    "tool_request",
}

TOOL_RESULT_EVENT_TYPES = {
    "tool_result",
    "execute_tool_end",
    "tools/result",
    "tool/result",
    "tool_response",
}

COMPLETION_EVENT_TYPES = {
    "final_answer",
    "completion",
    "task_complete",
    "session_end",
    "session/end",
    "assistant_final",
    "done",
    "run_complete",
    "agent_complete",
    "agent_end",
    "turn/end",
}

NON_COMPLETION_STOP_REASONS = {
    "budget_exhausted",
    "max_steps",
    "max_turns",
    "timeout",
    "cancelled",
    "canceled",
    "error",
    "failed",
    "approval_circuit_breaker",
    "aborted",
    "stopped",
}

EVAL_SUMMARY_KEYS = ("pass_at_1", "pass_at_k", "pass_pow_k", "trials_per_task")


@dataclass(frozen=True)
class TraceFinding:
    """Structured validation finding."""

    severity: str  # ERROR, WARN, INFO
    code: str
    file: str
    line: int | None
    message: str

    def format_line(self) -> str:
        loc = f"{self.file}:{self.line}" if self.line is not None else self.file
        return f"[{self.severity}:{self.code}] {loc} {self.message}"


@dataclass
class _SessionState:
    """Per-session (trace_id / session_id) state so multi-session JSONL files never bleed state."""

    open_tool_calls: dict[str, int] = field(default_factory=dict)  # call_id -> line_no
    matched_tool_calls: set[str] = field(default_factory=set)
    model_turns: list[tuple[int, int, int | None]] = field(default_factory=list)  # (line_no, tokens_in, tokens_cached)

    # Doom loop tracking
    last_call_sig: tuple[str, str] | None = None
    repeat_count: int = 0
    repeat_start_line: int = 0

    # Lethal Trifecta tracking
    seen_untrusted_fetch: bool = False
    seen_sensitive_read: bool = False
    trifecta_reported: bool = False

    # Unverified completion tracking
    has_mutation: bool = False
    verified_since_mutation: bool = False
    last_mutation_line: int | None = None
    pending_verify_call_ids: set[str] = field(default_factory=set)
    pending_anonymous_verify: bool = False
    saw_completion: bool = False
    completion_line: int | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _get_event_field(event: dict[str, Any], keys: tuple[str, ...]) -> tuple[bool, Any]:
    """Read field from top-level event, falling back to payload and attributes dicts."""
    for k in keys:
        if k in event and event[k] is not None:
            return True, event[k]
    payload = event.get("payload")
    if isinstance(payload, dict):
        for k in keys:
            if k in payload and payload[k] is not None:
                return True, payload[k]
    attrs = event.get("attributes")
    if isinstance(attrs, dict):
        for k in keys:
            if k in attrs and attrs[k] is not None:
                return True, attrs[k]
    return False, None


def _extract_int_field(event: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    containers: list[Any] = [event, event.get("usage")]
    payload = event.get("payload")
    if isinstance(payload, dict):
        containers.append(payload)
        containers.append(payload.get("usage"))
    containers.append(event.get("attributes"))

    for container in containers:
        if not isinstance(container, dict):
            continue
        for k in keys:
            if k in container and container[k] is not None:
                val = container[k]
                if isinstance(val, bool) or not isinstance(val, int):
                    return None
                return val
    return None


def _canonical_args(args: Any) -> str:
    try:
        return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        return str(args)


def _extract_tool_output_raw(event: dict[str, Any]) -> Any:
    for key in ("output", "content", "result", "stdout"):
        if key in event and event[key] is not None:
            return event[key]
    payload = event.get("payload")
    if isinstance(payload, dict):
        for key in ("output", "content", "result", "stdout"):
            if key in payload and payload[key] is not None:
                return payload[key]
    attrs = event.get("attributes")
    if isinstance(attrs, dict):
        for key in ("output", "content", "result", "stdout"):
            if key in attrs and attrs[key] is not None:
                return attrs[key]
    if "payload" in event and event["payload"] is not None:
        return event["payload"]
    return None


def _extract_tool_output_len(event: dict[str, Any]) -> int:
    val = _extract_tool_output_raw(event)
    if val is None:
        return 0
    if isinstance(val, str):
        return len(val)
    return len(_canonical_args(val))


def _extract_tool_output_text(event: dict[str, Any]) -> str:
    val = _extract_tool_output_raw(event)
    if isinstance(val, str):
        return val
    return ""


def _tool_result_succeeded(event: dict[str, Any]) -> bool:
    """Return True only when a tool_result indicates successful execution."""
    _, status_val = _get_event_field(event, ("status",))
    if isinstance(status_val, str) and status_val.strip().lower() in (
        "error",
        "failed",
        "fail",
        "denied",
        "blocked",
        "timeout",
    ):
        return False

    _, is_err = _get_event_field(event, ("is_error",))
    if is_err is True:
        return False

    _, ok_val = _get_event_field(event, ("ok",))
    if ok_val is False:
        return False

    _, exit_code = _get_event_field(event, ("exit_code", "returncode", "process.exit.code"))
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
        return False

    _, err_val = _get_event_field(event, ("error", "error_code"))
    if isinstance(err_val, bool):
        if err_val:
            return False
    elif isinstance(err_val, str):
        if err_val.strip():
            return False
    elif err_val is not None:
        return False

    out_text = _extract_tool_output_text(event).lstrip().upper()
    if out_text.startswith(("VERIFY_FAIL", "FAIL:")):
        return False

    return True


def _collect_tool_calls(event: dict[str, Any]) -> list[tuple[str | None, str, Any]]:
    """Return list of (call_id, tool_name, args) tuples represented by this event without double-counting."""
    calls: list[tuple[str | None, str, Any]] = []
    ev_type = str(event.get("event_type") or "").lower()

    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    attrs = event.get("attributes") if isinstance(event.get("attributes"), dict) else {}

    tc_list = event.get("tool_calls")
    if not isinstance(tc_list, list):
        tc_list = payload.get("tool_calls")
    if not isinstance(tc_list, list):
        tc_list = attrs.get("tool_calls")

    if isinstance(tc_list, list) and tc_list:
        for tc in tc_list:
            if not isinstance(tc, dict):
                continue
            cid = tc.get("id") or tc.get("tool_call_id") or tc.get("call_id")
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            name = str(tc.get("name") or tc.get("tool_name") or fn.get("name") or "")
            args = tc.get("arguments") if "arguments" in tc else tc.get("args", fn.get("arguments"))
            calls.append((str(cid) if cid is not None else None, name, args))
        return calls

    if ev_type in TOOL_CALL_EVENT_TYPES:
        _, cid = _get_event_field(event, ("tool_call_id", "call_id", "id"))
        _, name_raw = _get_event_field(event, ("tool_name", "name", "tool"))
        found_args, args = _get_event_field(event, ("arguments", "args", "input"))
        calls.append(
            (
                str(cid) if cid is not None else None,
                str(name_raw or ""),
                args if found_args else None,
            )
        )

    return calls


def _is_tool_result_event(event: dict[str, Any]) -> bool:
    ev_type = str(event.get("event_type") or "").lower()
    if ev_type in TOOL_RESULT_EVENT_TYPES:
        return True
    _, role = _get_event_field(event, ("role",))
    return role == "tool"


def _looks_like_eval_summary_dict(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if any(k in data for k in EVAL_SUMMARY_KEYS):
        return True
    summary = data.get("summary")
    if isinstance(summary, dict) and any(k in summary for k in EVAL_SUMMARY_KEYS):
        return True
    return False


def detect_mode(path: Path) -> str:
    """Detect whether a file is a trace, dataset, or eval_summary."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
        except json.JSONDecodeError:
            return "eval_summary"
        if isinstance(data, list):
            return "dataset"
        if isinstance(data, dict):
            if _looks_like_eval_summary_dict(data) or any(k in data for k in ("tasks", "summary")):
                return "eval_summary"
        return "eval_summary"

    # JSONL inspection: peek first valid JSON object line
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    if any(k in obj for k in ("event_type", "trace_id", "session_id")):
                        return "trace"
                    if "id" in obj and any(k in obj for k in ("input", "prompt", "expected", "graders")):
                        return "dataset"
                break
    except (OSError, json.JSONDecodeError):
        pass
    return "trace"


# ---------------------------------------------------------------------------
# Trace JSONL validator
# ---------------------------------------------------------------------------

def validate_trace_file(path: Path, display_name: str, max_tool_chars: int = 50000) -> dict[str, Any]:
    findings: list[TraceFinding] = []
    raw_text = path.read_text(encoding="utf-8-sig", errors="replace")
    lines = raw_text.splitlines()

    events_count = 0
    step_numbers: set[int] = set()
    total_model_turns = 0
    total_tokens_in = 0
    total_tokens_cached = 0
    total_tokens_out = 0
    total_thinking_tokens = 0
    error_events = 0
    tool_calls_count = 0

    prev_dt: datetime | None = None
    sessions: dict[str, _SessionState] = {}

    def _get_session(event: dict[str, Any]) -> _SessionState:
        key = str(event.get("trace_id") or event.get("session_id") or "__default__")
        sess = sessions.get(key)
        if sess is None:
            sess = _SessionState()
            sessions[key] = sess
        return sess

    def _flush_doom_loop(sess: _SessionState) -> None:
        if sess.last_call_sig is not None and sess.repeat_count >= 3:
            sev = "ERROR" if sess.repeat_count >= 5 else "WARN"
            findings.append(
                TraceFinding(
                    severity=sev,
                    code="TR007",
                    file=display_name,
                    line=sess.repeat_start_line,
                    message=(
                        f"Doom-loop detected: tool '{sess.last_call_sig[0]}' invoked {sess.repeat_count} "
                        "consecutive times with identical arguments."
                    ),
                )
            )
        sess.repeat_count = 0

    for line_no, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        # Secret leak check on raw serialized line
        for label, pat in SECRET_LINE_PATTERNS:
            if pat.search(raw_line):
                findings.append(
                    TraceFinding(
                        severity="ERROR",
                        code="TR009",
                        file=display_name,
                        line=line_no,
                        message=f"Secret leak detected in serialized trace ({label}); redact secrets before logging.",
                    )
                )
                break

        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as exc:
            findings.append(
                TraceFinding(
                    severity="ERROR",
                    code="TR001",
                    file=display_name,
                    line=line_no,
                    message=f"Invalid JSON on trace line: {exc.msg}.",
                )
            )
            continue

        if not isinstance(event, dict):
            findings.append(
                TraceFinding(
                    severity="ERROR",
                    code="TR001",
                    file=display_name,
                    line=line_no,
                    message="Trace line must be a JSON object.",
                )
            )
            continue

        events_count += 1
        sess = _get_session(event)

        # Required fields
        has_id = bool(event.get("trace_id") or event.get("session_id"))
        has_ts = "timestamp" in event and event["timestamp"] is not None
        has_ev_type = isinstance(event.get("event_type"), str) and bool(event["event_type"].strip())
        missing = []
        if not has_id:
            missing.append("trace_id|session_id")
        if not has_ts:
            missing.append("timestamp")
        if not has_ev_type:
            missing.append("event_type")
        if missing:
            findings.append(
                TraceFinding(
                    severity="ERROR",
                    code="TR002",
                    file=display_name,
                    line=line_no,
                    message=f"Missing required trace field(s): {', '.join(missing)}.",
                )
            )

        # Monotonic ISO-8601 timestamps
        if has_ts:
            dt = _parse_iso_timestamp(event["timestamp"])
            if dt is None:
                findings.append(
                    TraceFinding(
                        severity="ERROR",
                        code="TR003",
                        file=display_name,
                        line=line_no,
                        message=f"Invalid ISO-8601 timestamp: {event['timestamp']!r}.",
                    )
                )
            else:
                if prev_dt is not None and dt < prev_dt:
                    findings.append(
                        TraceFinding(
                            severity="ERROR",
                            code="TR003",
                            file=display_name,
                            line=line_no,
                            message=(
                                f"Non-monotonic timestamp ({event['timestamp']}) precedes previous event "
                                f"({prev_dt.isoformat()})."
                            ),
                        )
                    )
                prev_dt = dt

        ev_type = str(event.get("event_type") or "").lower()
        _, status_val = _get_event_field(event, ("status",))
        _, is_error_val = _get_event_field(event, ("is_error",))
        if (
            "error" in ev_type
            or (isinstance(status_val, str) and status_val.lower() == "error")
            or is_error_val is True
        ):
            error_events += 1

        step_val = event.get("step")
        if isinstance(step_val, int) and not isinstance(step_val, bool) and step_val >= 1:
            step_numbers.add(step_val)

        # Token accounting invariants
        tok_in = _extract_int_field(event, ("tokens_in", "input_tokens", "prompt_tokens", "gen_ai.usage.input_tokens"))
        tok_cached = _extract_int_field(
            event,
            ("tokens_cached", "cached_tokens", "cache_read_input_tokens", "gen_ai.usage.cache_read.input_tokens"),
        )
        tok_out = _extract_int_field(
            event,
            ("tokens_out", "output_tokens", "completion_tokens", "gen_ai.usage.output_tokens"),
        )
        tok_think = _extract_int_field(event, ("thinking_tokens", "reasoning_tokens"))

        if tok_in is not None:
            if tok_in < 0:
                findings.append(
                    TraceFinding("ERROR", "TR004", display_name, line_no, f"Negative tokens_in ({tok_in}).")
                )
            else:
                total_tokens_in += tok_in
        if tok_cached is not None:
            if tok_cached < 0:
                findings.append(
                    TraceFinding("ERROR", "TR004", display_name, line_no, f"Negative tokens_cached ({tok_cached}).")
                )
            else:
                total_tokens_cached += tok_cached
        if tok_in is not None and tok_cached is not None and tok_cached > tok_in:
            findings.append(
                TraceFinding(
                    "ERROR",
                    "TR004",
                    display_name,
                    line_no,
                    f"Token accounting invariant violated: tokens_cached ({tok_cached}) > tokens_in ({tok_in}).",
                )
            )
        if tok_out is not None:
            if tok_out < 0:
                findings.append(
                    TraceFinding("ERROR", "TR004", display_name, line_no, f"Negative tokens_out ({tok_out}).")
                )
            else:
                total_tokens_out += tok_out
        if tok_think is not None:
            if tok_think < 0:
                findings.append(
                    TraceFinding("ERROR", "TR004", display_name, line_no, f"Negative thinking_tokens ({tok_think}).")
                )
            else:
                total_thinking_tokens += tok_think
        if tok_out is not None and tok_think is not None and tok_think > tok_out:
            findings.append(
                TraceFinding(
                    "ERROR",
                    "TR004",
                    display_name,
                    line_no,
                    f"Token accounting invariant violated: thinking_tokens ({tok_think}) > tokens_out ({tok_out}).",
                )
            )

        if tok_in is not None and tok_in > 0:
            sess.model_turns.append((line_no, tok_in, tok_cached))
            total_model_turns += 1

        # Tool calls handling
        calls = _collect_tool_calls(event)
        for cid, tname, targs in calls:
            tool_calls_count += 1
            if cid:
                sess.open_tool_calls[cid] = line_no

            canon = _canonical_args(targs)
            sig = (tname, canon)
            if sig == sess.last_call_sig:
                sess.repeat_count += 1
            else:
                _flush_doom_loop(sess)
                sess.last_call_sig = sig
                sess.repeat_count = 1
                sess.repeat_start_line = line_no

            # Lethal Trifecta stage detection (scoped per session)
            tname_l = tname.lower()
            args_str = canon
            is_untrusted = bool(UNTRUSTED_FETCH_TOOL_RE.search(tname_l)) or (
                tname_l in SHELL_TOOL_NAMES
                and bool(re.search(r"\b(?:curl|wget)\b.*https?://", args_str, re.IGNORECASE))
            )
            is_sensitive = bool(SENSITIVE_PATH_RE.search(args_str))
            is_outbound = (
                bool(OUTBOUND_SEND_TOOL_RE.search(tname_l))
                or (
                    "fetch" in tname_l
                    and not tname_l.startswith(("git_", "git-"))
                    and bool(re.search(r"\b(?:post|put)\b", args_str, re.IGNORECASE))
                )
                or (
                    tname_l in SHELL_TOOL_NAMES
                    and bool(
                        re.search(
                            r"\bcurl\b[^\n]*(?:-X\s*POST|-d\b|--data|--upload-file|-F\b)",
                            args_str,
                            re.IGNORECASE,
                        )
                    )
                )
            )

            if is_untrusted:
                sess.seen_untrusted_fetch = True
            if is_sensitive:
                sess.seen_sensitive_read = True
            if is_outbound and sess.seen_untrusted_fetch and sess.seen_sensitive_read and not sess.trifecta_reported:
                sess.trifecta_reported = True
                findings.append(
                    TraceFinding(
                        severity="ERROR",
                        code="TR010",
                        file=display_name,
                        line=line_no,
                        message=(
                            f"Lethal Trifecta exfiltration sequence detected: untrusted external fetch + "
                            f"sensitive path access followed by outbound call '{tname}'."
                        ),
                    )
                )

            # Mutation vs verification tracking (verification only clears on succeeding tool_result)
            if MUTATION_TOOL_RE.search(tname_l):
                sess.has_mutation = True
                sess.verified_since_mutation = False
                sess.last_mutation_line = line_no
                sess.pending_verify_call_ids.clear()
                sess.pending_anonymous_verify = False
            elif VERIFICATION_TOOL_RE.search(tname_l) or (
                tname_l in SHELL_TOOL_NAMES and VERIFICATION_CMD_RE.search(args_str)
            ):
                if sess.has_mutation:
                    if cid:
                        sess.pending_verify_call_ids.add(cid)
                    else:
                        sess.pending_anonymous_verify = True

        # Tool results handling
        if _is_tool_result_event(event):
            _, cid = _get_event_field(event, ("tool_call_id", "call_id", "id"))
            cid_s = str(cid) if cid is not None else None
            if cid_s is not None:
                if cid_s in sess.open_tool_calls:
                    sess.open_tool_calls.pop(cid_s)
                    sess.matched_tool_calls.add(cid_s)
                elif cid_s not in sess.matched_tool_calls:
                    findings.append(
                        TraceFinding(
                            severity="WARN",
                            code="TR006",
                            file=display_name,
                            line=line_no,
                            message=f"Orphan tool_result for unknown tool_call_id '{cid_s}'.",
                        )
                    )

            # Update verification state only when the verification tool call actually succeeded
            if sess.has_mutation:
                is_matching_verify = False
                if cid_s is not None and cid_s in sess.pending_verify_call_ids:
                    sess.pending_verify_call_ids.discard(cid_s)
                    is_matching_verify = True
                elif cid_s is None and sess.pending_anonymous_verify:
                    sess.pending_anonymous_verify = False
                    is_matching_verify = True
                else:
                    _, res_tname = _get_event_field(event, ("tool_name", "name"))
                    if (
                        cid_s is None
                        and isinstance(res_tname, str)
                        and VERIFICATION_TOOL_RE.search(res_tname.lower())
                    ):
                        is_matching_verify = True

                if is_matching_verify and _tool_result_succeeded(event):
                    sess.verified_since_mutation = True

            out_len = _extract_tool_output_len(event)
            if out_len > max_tool_chars:
                findings.append(
                    TraceFinding(
                        severity="WARN",
                        code="TR008",
                        file=display_name,
                        line=line_no,
                        message=(
                            f"Tool output flood: tool_result payload is {out_len} chars "
                            f"(exceeds --max-tool-chars={max_tool_chars}); truncate and spill to disk."
                        ),
                    )
                )

        # Completion detection
        _, stop_reason = _get_event_field(event, ("stop_reason",))
        _, final_flag = _get_event_field(event, ("final",))
        stop_reason_l = stop_reason.lower() if isinstance(stop_reason, str) else ""
        status_l = status_val.lower() if isinstance(status_val, str) else ""

        is_completion = False
        if ev_type in COMPLETION_EVENT_TYPES:
            if stop_reason_l not in NON_COMPLETION_STOP_REASONS and not (
                ev_type in ("agent_end", "session_end", "session/end", "turn/end")
                and status_l in ("error", "failed", "stopped", "aborted")
            ):
                is_completion = True
        elif ev_type in ("assistant_message", "model_response", "assistant/message") and not calls:
            if (
                final_flag is True
                or status_l == "completed"
                or stop_reason_l in ("end_turn", "stop", "completed")
            ):
                is_completion = True

        if is_completion:
            sess.saw_completion = True
            sess.completion_line = line_no

    if events_count == 0 and not any(f.code == "TR001" for f in findings):
        findings.append(
            TraceFinding(
                severity="WARN",
                code="TR001",
                file=display_name,
                line=None,
                message="Empty trace file: contains 0 events.",
            )
        )

    for sess in sessions.values():
        _flush_doom_loop(sess)

        # Orphan tool calls without matching tool_result
        for cid, call_line in sess.open_tool_calls.items():
            findings.append(
                TraceFinding(
                    severity="ERROR",
                    code="TR006",
                    file=display_name,
                    line=call_line,
                    message=f"Orphan tool_call '{cid}' has no matching tool_result in trace.",
                )
            )

        # KV-cache hit regression:
        # 1) >= 4 model turns and 0 cached tokens across turns 2..N
        tr005_emitted = False
        if len(sess.model_turns) >= 4:
            later_turns = sess.model_turns[1:]
            if all(cached == 0 for _, _, cached in later_turns):
                tr005_emitted = True
                findings.append(
                    TraceFinding(
                        severity="WARN",
                        code="TR005",
                        file=display_name,
                        line=later_turns[0][0],
                        message=(
                            f"KV-cache hit regression: {len(sess.model_turns)} model turns with tokens_in > 0, "
                            "but tokens_cached == 0 across turns 2..N (check system prompt/tool schema prefix stability)."
                        ),
                    )
                )

        # 2) Mid-run KV-cache collapse: after >=1 turn with tokens_cached > 0,
        # >=2 consecutive subsequent turns drop back to tokens_cached == 0 while tokens_in > 0.
        if not tr005_emitted:
            seen_cache_hit = False
            zero_streak = 0
            streak_start_line: int | None = None
            for turn_line, tok_in_val, cached_val in sess.model_turns:
                if cached_val is not None and cached_val > 0:
                    seen_cache_hit = True
                    zero_streak = 0
                    streak_start_line = None
                elif seen_cache_hit and tok_in_val > 0 and cached_val == 0:
                    if zero_streak == 0:
                        streak_start_line = turn_line
                    zero_streak += 1
                    if zero_streak >= 2:
                        findings.append(
                            TraceFinding(
                                severity="WARN",
                                code="TR005",
                                file=display_name,
                                line=streak_start_line,
                                message=(
                                    "Mid-run KV-cache collapse: tokens_cached dropped to 0 for >=2 consecutive "
                                    "turns after earlier cache hits (check for mid-session prompt or tool-schema mutation)."
                                ),
                            )
                        )
                        break
                else:
                    zero_streak = 0
                    streak_start_line = None

        # Unverified completion claim after mutation
        if sess.has_mutation and sess.saw_completion and not sess.verified_since_mutation:
            findings.append(
                TraceFinding(
                    severity="WARN",
                    code="TR011",
                    file=display_name,
                    line=sess.completion_line or sess.last_mutation_line,
                    message=(
                        "Unverified completion claim: file/state mutation occurred without a subsequent "
                        "passing verification tool call (tests, lint, build, verify) before final completion."
                    ),
                )
            )

    steps_count = len(step_numbers) if step_numbers else total_model_turns
    return {
        "file": display_name,
        "mode": "trace",
        "stats": {
            "events": events_count,
            "steps": steps_count,
            "tool_calls": tool_calls_count,
            "errors": error_events,
            "total_tokens_in": total_tokens_in,
            "total_tokens_cached": total_tokens_cached,
            "total_tokens_out": total_tokens_out,
            "total_thinking_tokens": total_thinking_tokens,
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Eval dataset JSONL / JSON array validator
# ---------------------------------------------------------------------------

def _validate_dataset_item(
    item: Any,
    loc_line: int | None,
    loc_label: str,
    display_name: str,
    seen_ids: dict[str, str],
    findings: list[TraceFinding],
) -> bool:
    """Validate a single dataset task dict. Returns True if counted as a task dict."""
    if not isinstance(item, dict):
        findings.append(
            TraceFinding("ERROR", "DS001", display_name, loc_line, "Dataset task entry must be a JSON object.")
        )
        return False

    tid = item.get("id")
    if not isinstance(tid, str) or not tid.strip():
        findings.append(
            TraceFinding("ERROR", "DS002", display_name, loc_line, "Dataset task missing required non-empty string 'id'.")
        )
    else:
        if tid in seen_ids:
            findings.append(
                TraceFinding(
                    "ERROR",
                    "DS003",
                    display_name,
                    loc_line,
                    f"Duplicate dataset task id '{tid}' (first seen at {seen_ids[tid]}).",
                )
            )
        else:
            seen_ids[tid] = loc_label

    inp = item.get("input") if "input" in item else item.get("prompt")
    if not isinstance(inp, str) or not inp.strip():
        findings.append(
            TraceFinding(
                "ERROR",
                "DS004",
                display_name,
                loc_line,
                "Dataset task missing required non-empty string 'input' or 'prompt'.",
            )
        )

    has_expected = "expected" in item and item["expected"] is not None
    graders = item.get("graders")
    has_graders = (isinstance(graders, list) and len(graders) > 0) or (
        isinstance(graders, dict) and len(graders) > 0
    )
    if not has_expected and not has_graders:
        findings.append(
            TraceFinding(
                "ERROR",
                "DS005",
                display_name,
                loc_line,
                "Dataset task must define 'expected' or non-empty 'graders'.",
            )
        )
    return True


def validate_dataset_file(path: Path, display_name: str) -> dict[str, Any]:
    findings: list[TraceFinding] = []
    raw_text = path.read_text(encoding="utf-8-sig", errors="replace")
    seen_ids: dict[str, str] = {}
    task_count = 0

    stripped_full = raw_text.strip()
    if not stripped_full:
        findings.append(
            TraceFinding("WARN", "DS001", display_name, None, "Empty dataset file: contains 0 tasks.")
        )
        return {
            "file": display_name,
            "mode": "dataset",
            "stats": {"tasks": 0, "unique_ids": 0},
            "findings": findings,
        }

    if path.suffix.lower() == ".json" or stripped_full.startswith("["):
        try:
            data = json.loads(stripped_full)
        except json.JSONDecodeError as exc:
            findings.append(
                TraceFinding("ERROR", "DS001", display_name, 1, f"Invalid JSON in dataset file: {exc.msg}.")
            )
            return {
                "file": display_name,
                "mode": "dataset",
                "stats": {"tasks": 0, "unique_ids": 0},
                "findings": findings,
            }
        if not isinstance(data, list):
            findings.append(
                TraceFinding(
                    "ERROR",
                    "DS001",
                    display_name,
                    1,
                    "JSON dataset file must contain a JSON array of task objects.",
                )
            )
            return {
                "file": display_name,
                "mode": "dataset",
                "stats": {"tasks": 0, "unique_ids": 0},
                "findings": findings,
            }
        for idx, item in enumerate(data, 1):
            if _validate_dataset_item(item, idx, f"entry {idx}", display_name, seen_ids, findings):
                task_count += 1
    else:
        for line_no, raw_line in enumerate(raw_text.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
            except json.JSONDecodeError as exc:
                findings.append(
                    TraceFinding("ERROR", "DS001", display_name, line_no, f"Invalid JSON on dataset line: {exc.msg}.")
                )
                continue
            if _validate_dataset_item(item, line_no, f"line {line_no}", display_name, seen_ids, findings):
                task_count += 1

    if task_count == 0 and not any(f.code == "DS001" for f in findings):
        findings.append(
            TraceFinding("WARN", "DS001", display_name, None, "Empty dataset file: contains 0 tasks.")
        )

    return {
        "file": display_name,
        "mode": "dataset",
        "stats": {"tasks": task_count, "unique_ids": len(seen_ids)},
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Eval summary JSON validator
# ---------------------------------------------------------------------------

def _check_finite_extra_metrics(
    obj: dict[str, Any],
    label: str,
    display_name: str,
    findings: list[TraceFinding],
) -> None:
    for key in ("pass_rate", "clustered_stderr"):
        if key in obj and obj[key] is not None:
            raw = obj[key]
            if not isinstance(raw, bool) and isinstance(raw, (int, float)):
                fval = float(raw)
                if not math.isfinite(fval):
                    findings.append(
                        TraceFinding(
                            "ERROR",
                            "ES002",
                            display_name,
                            None,
                            f"{label}.{key} must be a finite number (got {raw}).",
                        )
                    )
    ci = obj.get("wilson_ci_95")
    if isinstance(ci, list):
        for idx, elem in enumerate(ci):
            if not isinstance(elem, bool) and isinstance(elem, (int, float)):
                if not math.isfinite(float(elem)):
                    findings.append(
                        TraceFinding(
                            "ERROR",
                            "ES002",
                            display_name,
                            None,
                            f"{label}.wilson_ci_95[{idx}] must be a finite number (got {elem}).",
                        )
                    )


def _check_pass_metrics(
    obj: dict[str, Any],
    label: str,
    display_name: str,
    findings: list[TraceFinding],
) -> None:
    vals: dict[str, float] = {}
    for key in ("pass_pow_k", "pass_at_1", "pass_at_k"):
        if key in obj and obj[key] is not None:
            raw = obj[key]
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                findings.append(
                    TraceFinding("ERROR", "ES003", display_name, None, f"{label}.{key} must be a number in [0, 1].")
                )
                continue
            fval = float(raw)
            if not math.isfinite(fval):
                findings.append(
                    TraceFinding(
                        "ERROR",
                        "ES002",
                        display_name,
                        None,
                        f"{label}.{key} must be a finite number in [0, 1] (got {raw}).",
                    )
                )
                continue
            if fval < 0.0 or fval > 1.0:
                findings.append(
                    TraceFinding(
                        "ERROR",
                        "ES003",
                        display_name,
                        None,
                        f"{label}.{key}={fval} out of valid probability range [0, 1].",
                    )
                )
            else:
                vals[key] = fval

    _check_finite_extra_metrics(obj, label, display_name, findings)

    eps = 1e-9
    if "pass_pow_k" in vals and "pass_at_1" in vals and vals["pass_pow_k"] > vals["pass_at_1"] + eps:
        findings.append(
            TraceFinding(
                "ERROR",
                "ES003",
                display_name,
                None,
                f"{label} violates probability invariant: pass_pow_k ({vals['pass_pow_k']}) > pass_at_1 ({vals['pass_at_1']}).",
            )
        )
    if "pass_at_1" in vals and "pass_at_k" in vals and vals["pass_at_1"] > vals["pass_at_k"] + eps:
        findings.append(
            TraceFinding(
                "ERROR",
                "ES003",
                display_name,
                None,
                f"{label} violates probability invariant: pass_at_1 ({vals['pass_at_1']}) > pass_at_k ({vals['pass_at_k']}).",
            )
        )
    if "pass_pow_k" in vals and "pass_at_k" in vals and vals["pass_pow_k"] > vals["pass_at_k"] + eps:
        findings.append(
            TraceFinding(
                "ERROR",
                "ES003",
                display_name,
                None,
                f"{label} violates probability invariant: pass_pow_k ({vals['pass_pow_k']}) > pass_at_k ({vals['pass_at_k']}).",
            )
        )


def validate_eval_summary_file(path: Path, display_name: str) -> dict[str, Any]:
    findings: list[TraceFinding] = []
    raw_text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        findings.append(
            TraceFinding("ERROR", "ES001", display_name, None, f"Invalid JSON in eval summary: {exc.msg}.")
        )
        return {"file": display_name, "mode": "eval_summary", "stats": {}, "findings": findings}

    if not isinstance(data, dict):
        findings.append(
            TraceFinding("ERROR", "ES001", display_name, None, "Eval summary root must be a JSON object.")
        )
        return {"file": display_name, "mode": "eval_summary", "stats": {}, "findings": findings}

    # Check trials_per_task (top-level or under summary)
    summary_obj = data.get("summary") if isinstance(data.get("summary"), dict) else data
    trials = data.get("trials_per_task")
    if trials is None and isinstance(summary_obj, dict):
        trials = summary_obj.get("trials_per_task")
    if trials is None:
        trials = data.get("trials")

    if trials is None:
        findings.append(
            TraceFinding("WARN", "ES002", display_name, None, "Eval summary missing 'trials_per_task' field.")
        )
    elif isinstance(trials, bool) or not isinstance(trials, int) or trials < 1:
        findings.append(
            TraceFinding("ERROR", "ES002", display_name, None, f"Invalid trials_per_task value: {trials!r} (expected int >= 1).")
        )
    elif trials < 3:
        findings.append(
            TraceFinding(
                "WARN",
                "ES003",
                display_name,
                None,
                f"Low-trial eval summary (trials_per_task={trials}) hides stochastic variance; run k >= 3 trials.",
            )
        )

    _check_pass_metrics(data, "summary", display_name, findings)
    if summary_obj is not data and isinstance(summary_obj, dict):
        _check_pass_metrics(summary_obj, "summary", display_name, findings)

    tasks = data.get("tasks")
    zero_pass_count = 0
    task_count = 0
    if isinstance(tasks, list):
        task_count = len(tasks)
        for idx, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            tid = str(task.get("id") or task.get("task_id") or f"task[{idx}]")
            _check_pass_metrics(task, f"task '{tid}'", display_name, findings)

            # Detect 0%-pass task missing gold_verified
            is_zero_pass = False
            if "passed" in task and isinstance(task["passed"], int) and not isinstance(task["passed"], bool) and task["passed"] == 0:
                is_zero_pass = True
            elif "pass_at_k" in task and isinstance(task["pass_at_k"], (int, float)) and not isinstance(task["pass_at_k"], bool) and task["pass_at_k"] == 0:
                is_zero_pass = True
            elif "pass_rate" in task and isinstance(task["pass_rate"], (int, float)) and not isinstance(task["pass_rate"], bool) and task["pass_rate"] == 0:
                is_zero_pass = True

            if is_zero_pass:
                zero_pass_count += 1
                if not task.get("gold_verified"):
                    findings.append(
                        TraceFinding(
                            "WARN",
                            "ES004",
                            display_name,
                            None,
                            f"Task '{tid}' has 0% pass rate without gold_verified=true; verify task & grader against a gold reference solution.",
                        )
                    )

    return {
        "file": display_name,
        "mode": "eval_summary",
        "stats": {
            "trials_per_task": trials,
            "tasks": task_count,
            "zero_pass_tasks": zero_pass_count,
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Runner & CLI
# ---------------------------------------------------------------------------

def collect_target_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files: list[Path] = []
    for p in sorted(target.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(target).parts
        if any(part in IGNORE_DIRS for part in rel_parts[:-1]):
            continue
        lower = p.name.lower()
        if lower.endswith(".jsonl"):
            files.append(p)
        elif lower.endswith(".json"):
            if "eval_summary" in lower:
                files.append(p)
            else:
                try:
                    data = json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
                except (OSError, json.JSONDecodeError):
                    continue
                if _looks_like_eval_summary_dict(data):
                    files.append(p)
    return files


def run_validation(
    target: Path,
    mode: str = "auto",
    max_tool_chars: int = 50000,
) -> dict[str, Any]:
    files = collect_target_files(target)
    base_dir = target if target.is_dir() else target.parent

    file_reports: list[dict[str, Any]] = []
    all_findings: list[TraceFinding] = []

    for f in files:
        display = f.relative_to(base_dir).as_posix() if target.is_dir() else f.name
        effective_mode = detect_mode(f) if mode == "auto" else mode
        if effective_mode == "trace":
            rep = validate_trace_file(f, display, max_tool_chars=max_tool_chars)
        elif effective_mode == "dataset":
            rep = validate_dataset_file(f, display)
        else:
            rep = validate_eval_summary_file(f, display)

        f_list: list[TraceFinding] = rep["findings"]
        all_findings.extend(f_list)
        file_reports.append(
            {
                "file": rep["file"],
                "mode": rep["mode"],
                "stats": rep["stats"],
                "findings": [item.format_line() for item in f_list],
                "details": [asdict(item) for item in f_list],
            }
        )

    counts = {
        "error": sum(1 for f in all_findings if f.severity == "ERROR"),
        "warn": sum(1 for f in all_findings if f.severity == "WARN"),
        "info": sum(1 for f in all_findings if f.severity == "INFO"),
    }

    return {
        "target": str(target),
        "mode": mode,
        "files_checked": len(files),
        "counts": counts,
        "files": file_reports,
        "findings": [f.format_line() for f in all_findings],
        "details": [asdict(f) for f in all_findings],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate agent harness JSONL traces, eval datasets, and eval summary reports."
    )
    parser.add_argument("path", help="Path to a .jsonl/.json file or directory")
    parser.add_argument(
        "--mode",
        choices=("auto", "trace", "dataset", "eval_summary"),
        default="auto",
        help="Validation mode (default: auto)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 on any ERROR or WARN finding",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output",
    )
    parser.add_argument(
        "--max-tool-chars",
        type=int,
        default=50000,
        help="Maximum allowed characters in a single tool_result before emitting a flood warning (default: 50000)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Path not found: {target}", file=sys.stderr)
        return 2
    if args.max_tool_chars < 1:
        print("--max-tool-chars must be >= 1", file=sys.stderr)
        return 2

    result = run_validation(target, mode=args.mode, max_tool_chars=args.max_tool_chars)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        counts = result["counts"]
        print(
            f"Validated {result['files_checked']} file(s) at {target} (mode={result['mode']}): "
            f"error={counts['error']}, warn={counts['warn']}, info={counts['info']}"
        )
        for rep in result["files"]:
            print(f"  - {rep['file']} [{rep['mode']}] stats={json.dumps(rep['stats'], sort_keys=True)}")
        if result["findings"]:
            print()
            for line in result["findings"]:
                print(line)

    counts = result["counts"]
    if counts["error"] > 0:
        return 1
    if args.strict and counts["warn"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
