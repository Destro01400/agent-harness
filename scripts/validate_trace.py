#!/usr/bin/env python3
"""Zero-dependency validator for agent harness JSONL traces, eval datasets, and eval summaries.

Usage:
  python validate_trace.py PATH [--mode {auto,trace,dataset,eval_summary}] [--strict] [--json] [--max-tool-chars 50000]
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
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
    ("GitHub personal access token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("PEM private key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}")),
    ("Signed URL / token query param", re.compile(r"[?&](?:X-Amz-Signature|token|access_token|api_key)=[^\"'\s&]{6,}")),
)

UNTRUSTED_FETCH_TOOL_RE = re.compile(
    r"(?:web_fetch|fetch_url|http_get|read_email|get_email|get_issue|read_issue|fetch_page|"
    r"browse|scrape|search_web|download|mcp_fetch|get_pr|read_comment|fetch)",
    re.IGNORECASE,
)

SENSITIVE_PATH_RE = re.compile(
    r"(?:~/?\.ssh|[/\\]\.ssh[/\\]|id_rsa|id_ed25519|(?<![A-Za-z0-9_])\.env(?:\.[A-Za-z0-9_-]+)?(?![A-Za-z0-9_])|"
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

COMPLETION_EVENT_TYPES = {
    "final_answer",
    "completion",
    "task_complete",
    "session_end",
    "assistant_final",
    "done",
    "run_complete",
    "agent_complete",
}


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


def _extract_int_field(event: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for k in keys:
        if k in event and event[k] is not None:
            val = event[k]
            if isinstance(val, bool) or not isinstance(val, int):
                return None
            return val
    usage = event.get("usage")
    if isinstance(usage, dict):
        for k in keys:
            if k in usage and usage[k] is not None:
                val = usage[k]
                if isinstance(val, bool) or not isinstance(val, int):
                    return None
                return val
    attrs = event.get("attributes")
    if isinstance(attrs, dict):
        for k in keys:
            if k in attrs and attrs[k] is not None:
                val = attrs[k]
                if isinstance(val, bool) or not isinstance(val, int):
                    return None
                return val
    return None


def _canonical_args(args: Any) -> str:
    try:
        return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        return str(args)


def _extract_tool_output_len(event: dict[str, Any]) -> int:
    for key in ("output", "content", "result", "stdout", "payload"):
        if key in event and event[key] is not None:
            val = event[key]
            if isinstance(val, str):
                return len(val)
            return len(_canonical_args(val))
    return 0


def _collect_tool_calls(event: dict[str, Any]) -> list[tuple[str | None, str, Any]]:
    """Return list of (call_id, tool_name, args) tuples represented by this event."""
    calls: list[tuple[str | None, str, Any]] = []
    ev_type = str(event.get("event_type") or "").lower()

    if ev_type in ("tool_call", "tool_use", "execute_tool", "execute_tool_start", "tools/call", "tool_request"):
        cid = event.get("tool_call_id") or event.get("call_id") or event.get("id")
        name = str(event.get("tool_name") or event.get("name") or event.get("tool") or "")
        args = event.get("arguments") if "arguments" in event else event.get("args", event.get("input"))
        calls.append((str(cid) if cid is not None else None, name, args))

    tc_list = event.get("tool_calls")
    if isinstance(tc_list, list):
        for tc in tc_list:
            if not isinstance(tc, dict):
                continue
            cid = tc.get("id") or tc.get("tool_call_id") or tc.get("call_id")
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            name = str(tc.get("name") or tc.get("tool_name") or fn.get("name") or "")
            args = tc.get("arguments") if "arguments" in tc else tc.get("args", fn.get("arguments"))
            calls.append((str(cid) if cid is not None else None, name, args))

    return calls


def _is_tool_result_event(event: dict[str, Any]) -> bool:
    ev_type = str(event.get("event_type") or "").lower()
    return ev_type in ("tool_result", "execute_tool_end", "tools/result", "tool_response") or (
        event.get("role") == "tool"
    )


def detect_mode(path: Path) -> str:
    """Detect whether a file is a trace, dataset, or eval_summary."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return "eval_summary"
        if isinstance(data, list):
            return "dataset"
        if isinstance(data, dict):
            if any(k in data for k in ("trials_per_task", "pass_at_k", "pass_pow_k", "pass_at_1", "tasks", "summary")):
                return "eval_summary"
        return "eval_summary"

    # JSONL inspection: peek first valid JSON object line
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
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
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    lines = raw_text.splitlines()

    events_count = 0
    step_numbers: set[int] = set()
    model_turns: list[tuple[int, int, int | None]] = []  # (line_no, tokens_in, tokens_cached)
    total_tokens_in = 0
    total_tokens_cached = 0
    total_tokens_out = 0
    total_thinking_tokens = 0
    error_events = 0
    tool_calls_count = 0

    prev_dt: datetime | None = None
    open_tool_calls: dict[str, int] = {}  # call_id -> line_no
    matched_tool_calls: set[str] = set()

    # Doom loop tracking
    last_call_sig: tuple[str, str] | None = None
    repeat_count = 0
    repeat_start_line = 0

    def _flush_doom_loop() -> None:
        nonlocal repeat_count
        if last_call_sig is not None and repeat_count >= 3:
            sev = "ERROR" if repeat_count >= 5 else "WARN"
            findings.append(
                TraceFinding(
                    severity=sev,
                    code="TR007",
                    file=display_name,
                    line=repeat_start_line,
                    message=(
                        f"Doom-loop detected: tool '{last_call_sig[0]}' invoked {repeat_count} "
                        "consecutive times with identical arguments."
                    ),
                )
            )
        repeat_count = 0

    # Lethal Trifecta tracking (per trace)
    seen_untrusted_fetch = False
    seen_sensitive_read = False
    trifecta_reported = False

    # Unverified completion tracking
    has_mutation = False
    verified_since_mutation = False
    last_mutation_line: int | None = None
    saw_completion = False
    completion_line: int | None = None

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
        if "error" in ev_type or event.get("status") == "error" or event.get("is_error") is True:
            error_events += 1

        step_val = event.get("step")
        if isinstance(step_val, int) and not isinstance(step_val, bool):
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
            model_turns.append((line_no, tok_in, tok_cached))

        # Tool calls handling
        calls = _collect_tool_calls(event)
        for cid, tname, targs in calls:
            tool_calls_count += 1
            if cid:
                open_tool_calls[cid] = line_no

            canon = _canonical_args(targs)
            sig = (tname, canon)
            if sig == last_call_sig:
                repeat_count += 1
            else:
                _flush_doom_loop()
                last_call_sig = sig
                repeat_count = 1
                repeat_start_line = line_no

            # Lethal Trifecta stage detection
            tname_l = tname.lower()
            args_str = canon
            is_untrusted = bool(UNTRUSTED_FETCH_TOOL_RE.search(tname_l)) or (
                tname_l in SHELL_TOOL_NAMES and bool(re.search(r"\b(?:curl|wget)\b.*https?://", args_str, re.IGNORECASE))
            )
            is_sensitive = bool(SENSITIVE_PATH_RE.search(args_str))
            is_outbound = bool(OUTBOUND_SEND_TOOL_RE.search(tname_l)) or (
                "fetch" in tname_l and bool(re.search(r"\b(?:post|put)\b", args_str, re.IGNORECASE))
            ) or (
                tname_l in SHELL_TOOL_NAMES
                and bool(re.search(r"\bcurl\b[^\n]*(?:-X\s*POST|-d\b|--data|--upload-file|-F\b)", args_str, re.IGNORECASE))
            )

            if is_untrusted:
                seen_untrusted_fetch = True
            if is_sensitive:
                seen_sensitive_read = True
            if is_outbound and seen_untrusted_fetch and seen_sensitive_read and not trifecta_reported:
                trifecta_reported = True
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

            # Mutation vs verification tracking
            if MUTATION_TOOL_RE.search(tname_l):
                has_mutation = True
                verified_since_mutation = False
                last_mutation_line = line_no
            elif VERIFICATION_TOOL_RE.search(tname_l) or (
                tname_l in SHELL_TOOL_NAMES and VERIFICATION_CMD_RE.search(args_str)
            ):
                if has_mutation:
                    verified_since_mutation = True

        # Tool results handling
        if _is_tool_result_event(event):
            cid = event.get("tool_call_id") or event.get("call_id") or event.get("id")
            if cid is not None:
                cid_s = str(cid)
                if cid_s in open_tool_calls:
                    open_tool_calls.pop(cid_s)
                    matched_tool_calls.add(cid_s)
                elif cid_s not in matched_tool_calls:
                    findings.append(
                        TraceFinding(
                            severity="WARN",
                            code="TR006",
                            file=display_name,
                            line=line_no,
                            message=f"Orphan tool_result for unknown tool_call_id '{cid_s}'.",
                        )
                    )

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
        is_completion = ev_type in COMPLETION_EVENT_TYPES or (
            ev_type in ("assistant_message", "model_response", "assistant/message")
            and not calls
            and (
                event.get("final") is True
                or event.get("status") == "completed"
                or event.get("stop_reason") in ("end_turn", "stop", "completed")
            )
        )
        if is_completion:
            saw_completion = True
            completion_line = line_no

    _flush_doom_loop()

    # Orphan tool calls without matching tool_result
    for cid, call_line in open_tool_calls.items():
        findings.append(
            TraceFinding(
                severity="ERROR",
                code="TR006",
                file=display_name,
                line=call_line,
                message=f"Orphan tool_call '{cid}' has no matching tool_result in trace.",
            )
        )

    # KV-cache hit regression: >= 4 model turns and 0 cached tokens on turns 2..N
    if len(model_turns) >= 4:
        later_turns = model_turns[1:]
        if all(cached == 0 for _, _, cached in later_turns):
            findings.append(
                TraceFinding(
                    severity="WARN",
                    code="TR005",
                    file=display_name,
                    line=later_turns[0][0],
                    message=(
                        f"KV-cache hit regression: {len(model_turns)} model turns with tokens_in > 0, "
                        "but tokens_cached == 0 across turns 2..N (check system prompt/tool schema prefix stability)."
                    ),
                )
            )

    # Unverified completion claim after mutation
    if has_mutation and saw_completion and not verified_since_mutation:
        findings.append(
            TraceFinding(
                severity="WARN",
                code="TR011",
                file=display_name,
                line=completion_line or last_mutation_line,
                message=(
                    "Unverified completion claim: file/state mutation occurred with zero subsequent "
                    "verification tool calls (tests, lint, build, check) before final completion."
                ),
            )
        )

    steps_count = len(step_numbers) if step_numbers else len(model_turns)
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
# Eval dataset JSONL validator
# ---------------------------------------------------------------------------

def validate_dataset_file(path: Path, display_name: str) -> dict[str, Any]:
    findings: list[TraceFinding] = []
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    seen_ids: dict[str, int] = {}
    task_count = 0

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

        if not isinstance(item, dict):
            findings.append(
                TraceFinding("ERROR", "DS001", display_name, line_no, "Dataset task entry must be a JSON object.")
            )
            continue

        task_count += 1
        tid = item.get("id")
        if not isinstance(tid, str) or not tid.strip():
            findings.append(
                TraceFinding("ERROR", "DS002", display_name, line_no, "Dataset task missing required non-empty string 'id'.")
            )
        else:
            if tid in seen_ids:
                findings.append(
                    TraceFinding(
                        "ERROR",
                        "DS003",
                        display_name,
                        line_no,
                        f"Duplicate dataset task id '{tid}' (first seen on line {seen_ids[tid]}).",
                    )
                )
            else:
                seen_ids[tid] = line_no

        inp = item.get("input") if "input" in item else item.get("prompt")
        if not isinstance(inp, str) or not inp.strip():
            findings.append(
                TraceFinding(
                    "ERROR",
                    "DS004",
                    display_name,
                    line_no,
                    "Dataset task missing required non-empty string 'input' or 'prompt'.",
                )
            )

        has_expected = "expected" in item and item["expected"] is not None
        graders = item.get("graders")
        has_graders = (isinstance(graders, list) and len(graders) > 0) or (isinstance(graders, dict) and len(graders) > 0)
        if not has_expected and not has_graders:
            findings.append(
                TraceFinding(
                    "ERROR",
                    "DS005",
                    display_name,
                    line_no,
                    "Dataset task must define 'expected' or non-empty 'graders'.",
                )
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
    raw_text = path.read_text(encoding="utf-8", errors="replace")
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
    elif trials == 1:
        findings.append(
            TraceFinding(
                "WARN",
                "ES002",
                display_name,
                None,
                "Single-trial eval summary (trials_per_task=1) hides stochastic variance; run k >= 3 trials.",
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
            if "passed" in task and isinstance(task["passed"], int) and task["passed"] == 0:
                is_zero_pass = True
            elif "pass_at_k" in task and isinstance(task["pass_at_k"], (int, float)) and task["pass_at_k"] == 0:
                is_zero_pass = True
            elif "pass_rate" in task and isinstance(task["pass_rate"], (int, float)) and task["pass_rate"] == 0:
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
        if lower.endswith(".jsonl") or (lower.endswith(".json") and "eval_summary" in lower):
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
