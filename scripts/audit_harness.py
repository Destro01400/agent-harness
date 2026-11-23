#!/usr/bin/env python3
"""Static auditor for AI Agent Harnesses (Python, JS/TS, Docker, MCP configs).

Implements 16 high-signal, low-false-positive rules (AH001-AH016) with
Text, JSON, and SARIF 2.1.0 output formats and per-line inline suppression
(`# harness-audit: ignore AH001` or `// harness-audit: ignore ALL`).

Usage:
  python audit_harness.py PROJECT_DIR [--strict] [--json | --sarif] [--ignore-dir DIR ...]
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sys

DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
}

PY_EXTS = {".py"}
JS_TS_EXTS = {".ts", ".tsx", ".js", ".mjs"}

HELP_BASE = "https://github.com/Destro01400/agent-harness/blob/main/references"


@dataclass(frozen=True)
class RuleMeta:
    """Metadata for a static audit rule (used for SARIF 2.1.0 & reporting)."""

    id: str
    name: str
    default_severity: str  # ERROR, WARN, INFO
    short_description: str
    full_description: str
    remediation: str
    help_uri: str
    tags: tuple[str, ...]


RULES: tuple[RuleMeta, ...] = (
    RuleMeta(
        id="AH001",
        name="UnboundedAgentLoop",
        default_severity="ERROR",
        short_description="Unbounded agent loop without step, turn, token, or time budget guard.",
        full_description=(
            "An infinite loop (while True / while (true)) invokes an LLM or tool without a "
            "code-enforced step, turn, token, cost, or deadline guard that breaks or raises."
        ),
        remediation=(
            "Enforce orthogonal runtime budgets (max_steps, max_tokens, max_cost, wall_clock_deadline) "
            "checked on every turn before model/tool execution."
        ),
        help_uri=f"{HELP_BASE}/agent-loop-and-budgets.md",
        tags=("reliability", "budgets", "loop"),
    ),
    RuleMeta(
        id="AH002",
        name="UnsafeShellExecution",
        default_severity="ERROR",
        short_description="Unsafe shell command execution (shell=True, os.system, os.popen, interpolated exec).",
        full_description=(
            "Invoking a system shell with string interpolation or shell=True exposes the harness "
            "to command injection when tool arguments originate from model or external untrusted inputs."
        ),
        remediation=(
            "Use argv lists with shell=False (subprocess.run([...], shell=False) or execFile/spawn) "
            "inside an OS/container sandbox."
        ),
        help_uri=f"{HELP_BASE}/sandboxing-and-security.md",
        tags=("security", "command-injection", "owasp-asi02"),
    ),
    RuleMeta(
        id="AH003",
        name="DynamicCodeExecution",
        default_severity="ERROR",
        short_description="Dynamic code execution via eval(), exec(), or new Function() in harness/tool code.",
        full_description=(
            "Evaluating arbitrary strings in the host harness process grants full process privileges "
            "and credential access if untrusted or model-generated input reaches the call."
        ),
        remediation=(
            "Replace eval/exec with structured parsers (json.loads, ast.literal_eval) or execute "
            "untrusted code inside an isolated ephemeral sandbox container."
        ),
        help_uri=f"{HELP_BASE}/sandboxing-and-security.md",
        tags=("security", "code-execution", "owasp-asi02"),
    ),
    RuleMeta(
        id="AH004",
        name="BlacklistSandboxIllusion",
        default_severity="ERROR",
        short_description="String/regex command blacklist used as a substitute for OS/container sandboxing.",
        full_description=(
            "Filtering shell commands with a denylist (e.g., BLOCKED_COMMANDS) is trivially bypassed "
            "via quoting, encoding, interpreters, or indirection and does not constitute a security boundary."
        ),
        remediation=(
            "Enforce dual-boundary OS/container isolation (bubblewrap/Landlock, Seatbelt, hardened Docker "
            "with network_mode: none, or Windows Restricted Token + ACLs)."
        ),
        help_uri=f"{HELP_BASE}/sandboxing-and-security.md",
        tags=("security", "sandbox", "owasp-asi05"),
    ),
    RuleMeta(
        id="AH005",
        name="HardcodedSecretOrEnvLeak",
        default_severity="ERROR",
        short_description="Hardcoded secret/API key or raw os.environ/process.env leaked to subprocess.",
        full_description=(
            "Hardcoded credentials risk public leakage, and passing raw os.environ / process.env "
            "into tool subprocesses exposes host API keys and cloud tokens to sandboxed code."
        ),
        remediation=(
            "Vault secrets outside the sandbox and pass an explicit minimal allowlist env dict "
            "(e.g., PATH, LANG, HOME) to tool subprocesses."
        ),
        help_uri=f"{HELP_BASE}/sandboxing-and-security.md",
        tags=("security", "secrets", "credentials"),
    ),
    RuleMeta(
        id="AH006",
        name="InsecureSandboxConfig",
        default_severity="ERROR",
        short_description="Insecure Docker/sandbox configuration (privileged, docker.sock, writable mount, :latest, or network enabled).",
        full_description=(
            "Container sandboxes with privileged mode, Docker socket mounts, writable host bind mounts, "
            "unpinned :latest tags, or default network access allow host breakout or data exfiltration."
        ),
        remediation=(
            "Pin base images by @sha256 digest, mount host directories read-only (:ro), never mount "
            "docker.sock or set privileged: true, and set network_mode: none for untrusted sandboxes."
        ),
        help_uri=f"{HELP_BASE}/sandboxing-and-security.md",
        tags=("security", "docker", "sandbox"),
    ),
    RuleMeta(
        id="AH007",
        name="MissingTimeoutOrAbortSignal",
        default_severity="WARN",
        short_description="Missing timeout or AbortSignal on subprocess or HTTP/LLM network call.",
        full_description=(
            "Subprocess and HTTP calls without explicit timeouts or AbortSignal can hang indefinitely, "
            "stalling the agent loop and leaking worker capacity."
        ),
        remediation=(
            "Pass explicit timeout=... in Python subprocess/HTTP calls and AbortSignal.timeout(...) "
            "or a propagated AbortSignal in JS/TS fetch and child-process calls."
        ),
        help_uri=f"{HELP_BASE}/resilience-and-streaming.md",
        tags=("reliability", "timeouts", "resilience"),
    ),
    RuleMeta(
        id="AH008",
        name="SilentSwallowOrHistoryErasure",
        default_severity="WARN",
        short_description="Silent exception swallowing or erasing failed turns from message history.",
        full_description=(
            "Empty except/catch blocks hide tool and runtime failures, and popping failed turns from "
            "conversation history destroys the error evidence the model needs to self-correct."
        ),
        remediation=(
            "Log and return structured, actionable error messages to the model and keep failed tool "
            "attempts in the append-only session history."
        ),
        help_uri=f"{HELP_BASE}/resilience-and-streaming.md",
        tags=("reliability", "observability", "error-handling"),
    ),
    RuleMeta(
        id="AH009",
        name="NaiveOrNestedRetry",
        default_severity="WARN",
        short_description="Retry loop without exponential backoff + jitter, or nested multi-layer retries.",
        full_description=(
            "Constant-delay or tight retry loops cause thundering herds on rate limits, and nested "
            "retry layers multiply load exponentially (e.g., 3^N amplification)."
        ),
        remediation=(
            "Centralize retries in a single layer with capped exponential backoff, full jitter, and "
            "a retry budget; never retry 4xx errors or non-idempotent writes without idempotency keys."
        ),
        help_uri=f"{HELP_BASE}/resilience-and-streaming.md",
        tags=("reliability", "retries", "resilience"),
    ),
    RuleMeta(
        id="AH010",
        name="PromptCachePrefixBuster",
        default_severity="WARN",
        short_description="Volatile value in system prompt prefix or non-deterministic JSON key ordering.",
        full_description=(
            "Injecting timestamps/UUIDs into the system prompt or serializing tool schemas/messages "
            "with sort_keys=False invalidates KV prompt caches on every turn (up to 10x input cost)."
        ),
        remediation=(
            "Keep the system prompt and tool definitions byte-identical across turns; place dynamic "
            "timestamps in later user/tool messages and serialize JSON with sort_keys=True."
        ),
        help_uri=f"{HELP_BASE}/context-and-memory.md",
        tags=("performance", "cost", "kv-cache"),
    ),
    RuleMeta(
        id="AH011",
        name="ReasoningStrippedOrToolAsUser",
        default_severity="WARN",
        short_description="Reasoning/thinking fields stripped from history or tool results cast as role='user'.",
        full_description=(
            "Stripping reasoning_content/thinking blocks breaks multi-turn thinking APIs, and casting "
            "tool outputs as role='user' causes models (e.g., DeepSeek-V3.2) to drop prior reasoning "
            "and blurs user vs. untrusted tool boundaries."
        ),
        remediation=(
            "Preserve reasoning/thinking blocks verbatim on assistant turns and emit tool outputs "
            "strictly with the dedicated tool role/result structure."
        ),
        help_uri=f"{HELP_BASE}/context-and-memory.md",
        tags=("correctness", "context", "reasoning"),
    ),
    RuleMeta(
        id="AH012",
        name="UnboundedToolOutput",
        default_severity="WARN",
        short_description="Unbounded tool output (stdout, file read, HTTP body) returned directly into context.",
        full_description=(
            "Returning raw command output, files, or HTTP bodies without size caps floods the context "
            "window, accelerating context rot and spiking token spend."
        ),
        remediation=(
            "Cap tool output size and spill oversized payloads to disk, returning a bounded preview "
            "plus file locator and byte/line counts."
        ),
        help_uri=f"{HELP_BASE}/tool-contracts-and-execution.md",
        tags=("context", "tools", "cost"),
    ),
    RuleMeta(
        id="AH013",
        name="UnpinnedMcpOrToolBloat",
        default_severity="WARN",
        short_description="Unpinned MCP server package (npx -y / @latest) or static tool catalog bloat (>15 tools).",
        full_description=(
            "Running unpinned MCP servers via npx -y or @latest enables rug-pull supply-chain attacks, "
            "and loading >15 static tools without deferred discovery wastes tens of thousands of tokens."
        ),
        remediation=(
            "Pin MCP packages to exact versions/hashes and use deferred tool loading (tool search) "
            "or workflow consolidation when exposing >15 tools."
        ),
        help_uri=f"{HELP_BASE}/mcp-and-dynamic-tools.md",
        tags=("security", "mcp", "context"),
    ),
    RuleMeta(
        id="AH014",
        name="BlockingSyncIoInAsync",
        default_severity="WARN",
        short_description="Blocking synchronous I/O (time.sleep, requests, subprocess.run) inside async def.",
        full_description=(
            "Calling blocking sleep, HTTP, or subprocess functions directly inside an asyncio coroutine "
            "freezes the event loop, breaking concurrent tool dispatch, streaming, and cancellation."
        ),
        remediation=(
            "Use async equivalents (asyncio.sleep, asyncio.create_subprocess_exec, async HTTP clients) "
            "or offload blocking calls via await asyncio.to_thread(...)."
        ),
        help_uri=f"{HELP_BASE}/resilience-and-streaming.md",
        tags=("reliability", "async", "performance"),
    ),
    RuleMeta(
        id="AH015",
        name="UnprotectedLlmJudge",
        default_severity="WARN",
        short_description="LLM-as-a-judge missing nonce delimiters, temperature=0, or last-match verdict parsing.",
        full_description=(
            "Interpolating untrusted submissions without random nonce delimiters enables judge prompt "
            "injection, temperature > 0 adds grading variance, and re.search matches injected early verdicts."
        ),
        remediation=(
            "Wrap evaluated submissions in per-call random nonce boundaries, call the judge with "
            "temperature=0, and extract the final verdict match (re.findall(...)[-1])."
        ),
        help_uri=f"{HELP_BASE}/graders-and-regression.md",
        tags=("evals", "security", "graders"),
    ),
    RuleMeta(
        id="AH016",
        name="MissingEvalOrSingleTrial",
        default_severity="INFO",
        short_description="Missing evaluation suite or single-trial (k=1) eval runner without pass@k/pass^k.",
        full_description=(
            "Harnesses without an evaluation suite cannot measure regressions, and single-trial (k=1) "
            "eval runners hide stochastic model variance."
        ),
        remediation=(
            "Add a deterministic + multi-trial eval suite (k >= 3) reporting unbiased pass@k, pass^k, "
            "and confidence intervals."
        ),
        help_uri=f"{HELP_BASE}/eval-harness-design.md",
        tags=("evals", "quality", "reliability"),
    ),
)

RULE_BY_ID: dict[str, RuleMeta] = {r.id: r for r in RULES}
RULE_INDEX: dict[str, int] = {r.id: idx for idx, r in enumerate(RULES)}
SARIF_LEVEL_MAP = {"ERROR": "error", "WARN": "warning", "INFO": "note"}


@dataclass(frozen=True)
class Finding:
    """Structured static audit finding."""

    rule_id: str
    severity: str  # ERROR, WARN, INFO
    file: str | None
    line: int | None
    message: str

    def format_line(self) -> str:
        loc = ""
        if self.file and self.line is not None:
            loc = f"{self.file}:{self.line} "
        elif self.file:
            loc = f"{self.file} "
        return f"[{self.severity}:{self.rule_id}] {loc}{self.message}".strip()


# ---------------------------------------------------------------------------
# Inline suppression & file discovery helpers
# ---------------------------------------------------------------------------

SUPPRESS_RE = re.compile(
    r"(?:#|//)\s*harness-audit\s*:\s*ignore\s+([A-Za-z0-9_,\s-]+)",
    re.IGNORECASE,
)
COMMENT_ONLY_SUPPRESS_RE = re.compile(
    r"^\s*(?:#|//)\s*harness-audit\s*:\s*ignore\s+([A-Za-z0-9_,\s-]+)\s*$",
    re.IGNORECASE,
)


def parse_suppressions(text: str) -> dict[int, set[str]]:
    """Map 1-based line numbers to sets of suppressed rule IDs (or 'ALL')."""
    suppressions: dict[int, set[str]] = {}
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        m = SUPPRESS_RE.search(line)
        if not m:
            continue
        raw_tokens = re.findall(r"ALL|AH\d{3}", m.group(1).upper())
        if not raw_tokens:
            continue
        tok_set = set(raw_tokens)
        suppressions.setdefault(idx, set()).update(tok_set)
        # If the line is a standalone suppression comment, also apply to the next line.
        if COMMENT_ONLY_SUPPRESS_RE.match(line):
            suppressions.setdefault(idx + 1, set()).update(tok_set)
    return suppressions


def is_suppressed(suppressions: dict[int, set[str]], line: int | None, rule_id: str) -> bool:
    if line is None:
        return False
    sup = suppressions.get(line)
    if not sup:
        return False
    return "ALL" in sup or rule_id.upper() in sup


def is_test_path(rel_posix: str) -> bool:
    parts = [p.lower() for p in rel_posix.split("/")]
    if any(p in ("tests", "test", "__tests__") for p in parts[:-1]):
        return True
    name = parts[-1]
    if name.startswith("test_") and name.endswith(".py"):
        return True
    if name.endswith("_test.py"):
        return True
    if re.search(r"\.(?:test|spec)\.(?:[cm]?[jt]sx?)$", name):
        return True
    return False


def is_dockerfile(path: Path) -> bool:
    lower = path.name.lower()
    return lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile")


def is_compose_file(path: Path) -> bool:
    lower = path.name.lower()
    return bool(re.match(r"^(?:docker-)?compose[^/]*\.ya?ml$", lower))


def is_mcp_config(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith(".json") and ("mcp" in lower)


def iter_scanned_files(root: Path, extra_ignore_dirs: set[str]) -> dict[str, list[Path]]:
    ignore = DEFAULT_IGNORE_DIRS | extra_ignore_dirs
    buckets: dict[str, list[Path]] = {
        "python": [],
        "js_ts": [],
        "docker": [],
        "compose": [],
        "mcp": [],
        "all": [],
    }
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if any(part in ignore for part in rel_parts[:-1]):
            continue
        buckets["all"].append(p)
        suffix = p.suffix.lower()
        if suffix in PY_EXTS:
            buckets["python"].append(p)
        elif suffix in JS_TS_EXTS:
            buckets["js_ts"].append(p)
        elif is_dockerfile(p):
            buckets["docker"].append(p)
        elif is_compose_file(p):
            buckets["compose"].append(p)
        elif is_mcp_config(p):
            buckets["mcp"].append(p)
    return buckets


# ---------------------------------------------------------------------------
# Shared secret patterns (AH005)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("OpenAI/API secret key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub personal access token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("PEM private key header", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
)


def scan_hardcoded_secrets(text: str, rel: str, suppressions: dict[int, set[str]]) -> list[Finding]:
    findings: list[Finding] = []
    for idx, line in enumerate(text.splitlines(), 1):
        if is_suppressed(suppressions, idx, "AH005"):
            continue
        for label, pat in SECRET_PATTERNS:
            if pat.search(line):
                findings.append(
                    Finding(
                        rule_id="AH005",
                        severity="ERROR",
                        file=rel,
                        line=idx,
                        message=f"Potential hardcoded secret detected ({label}); move credentials to a vault/env outside the repo.",
                    )
                )
                break
    return findings


# ---------------------------------------------------------------------------
# JS/TS comment & balanced-block utilities
# ---------------------------------------------------------------------------

def strip_js_comments(text: str, blank_strings: bool = False) -> str:
    """Strip JS/TS // and /* */ comments while preserving exact line numbers."""
    out: list[str] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue

        if ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue

        if ch in ('"', "'", "`"):
            quote = ch
            out.append(quote)
            i += 1
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    if text[i + 1] == "\n":
                        out.append(" \n" if blank_strings else "\\\n")
                    else:
                        out.append("  " if blank_strings else text[i : i + 2])
                    i += 2
                    continue
                if c == quote:
                    out.append(quote)
                    i += 1
                    break
                out.append("\n" if c == "\n" else (" " if blank_strings else c))
                i += 1
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def _skip_js_string(text: str, i: int) -> int:
    n = len(text)
    if i >= n or text[i] not in ('"', "'", "`"):
        return i
    quote = text[i]
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\" and j + 1 < n:
            j += 2
            continue
        if c == quote:
            return j + 1
        j += 1
    return n


def _scan_balanced_js(text: str, pos: int, open_ch: str, close_ch: str) -> tuple[str, int] | None:
    n = len(text)
    if pos >= n or text[pos] != open_ch:
        return None
    depth = 1
    i = pos + 1
    while i < n and depth > 0:
        nxt_i = _skip_js_string(text, i)
        if nxt_i > i:
            i = nxt_i
            continue
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return text[pos + 1 : i], i + 1
        i += 1
    return None


def _line_of(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


# ---------------------------------------------------------------------------
# Python AST auditor
# ---------------------------------------------------------------------------

LLM_OR_TOOL_CALL_RE = re.compile(
    r"(?:^|_|\.)(?:complete|chat|generate|invoke|respond|call_model|call_llm|llm_call|"
    r"create_message|execute_tool|run_tool|dispatch_tool|call_tool|tool_call|step_model|"
    r"messages\.create|responses\.create|completions\.create)$",
    re.IGNORECASE,
)

LOOP_GUARD_TOKEN_RE = re.compile(
    r"\b(?:max_steps|max_turns|max_iterations|max_tokens|max_cost|max_attempts|budget|"
    r"deadline|time_limit|timeout|remaining|exhausted|exceeded|check_budget|enforce_budget|"
    r"consume_step|consume_turn|record_step|step|steps|turn|turns|iteration|iterations|"
    r"attempt|attempts|cancel|cancelled|abort)\b",
    re.IGNORECASE,
)

BLACKLIST_NAME_RE = re.compile(
    r"(?:blocked|dangerous|forbidden|banned|disallowed|deny|black)[_-]?(?:cmd|cmds|command|commands|shell|patterns|list)|"
    r"(?:command|shell|cmd)[_-]?(?:blacklist|denylist)",
    re.IGNORECASE,
)

SHELL_CMD_HINT_RE = re.compile(
    r"(?:\brm\s+-|\bsudo\b|\bcurl\b|\bwget\b|\bchmod\b|\bmkfs\b|\bdd\s+if=|\bshutdown\b|"
    r"\breboot\b|\bnc\b|\bbash\b|\bsh\s+-c|\bkill\s+-9|/etc/passwd|;\s*|\|\s*)",
    re.IGNORECASE,
)

SANDBOX_REAL_RE = re.compile(
    r"\b(?:bwrap|bubblewrap|docker|podman|sandbox-exec|landlock|seccomp|firejail|nsjail|"
    r"restricted_token|sandbox_windows|create_sandbox)\b",
    re.IGNORECASE,
)

HISTORY_NAME_RE = re.compile(
    r"(?:^|_)(?:messages|history|turns|conversation|events|transcript)$",
    re.IGNORECASE,
)

SYSTEM_PROMPT_NAME_RE = re.compile(
    r"(?:system_prompt|system_message|prompt_prefix|base_prompt)",
    re.IGNORECASE,
)

TOOL_RESULT_NAME_RE = re.compile(
    r"(?:tool_result|tool_output|tool_response|tool_obs|fn_result|tool_stdout)",
    re.IGNORECASE,
)

TRUNCATION_HINT_RE = re.compile(
    r"\b(?:truncate|spill|clamp|limit|max_chars|max_bytes|max_output|preview|cap_output|"
    r"bounded|trim_output|slice_output|spill_output|head_tail)\b",
    re.IGNORECASE,
)

RETRY_NAME_RE = re.compile(r"\b(?:retry|retries|attempt|attempts|tries|backoff)\b", re.IGNORECASE)
BACKOFF_HINT_RE = re.compile(r"\b(?:backoff|jitter|uniform|random|randint|exp|exponential)\b", re.IGNORECASE)
DEFERRED_TOOL_HINT_RE = re.compile(
    r"\b(?:defer_loading|tool_search|search_tools|lazy_load|dynamic_load|deferred)\b",
    re.IGNORECASE,
)
JUDGE_NAME_RE = re.compile(r"(?:judge|grader|llm_grade|grade_with_llm|eval_judge)", re.IGNORECASE)
NONCE_HINT_RE = re.compile(r"\b(?:nonce|grader_nonce|delimiter|boundary|token_hex|sentinel)\b", re.IGNORECASE)
JUDGE_UNSAFE_INTERP_RE = re.compile(r"\{(?:submission|answer|response|candidate|output|agent_output)\}")
VERDICT_LABEL_RE = re.compile(r"(?:GRADE|VERDICT|SCORE)\s*:", re.IGNORECASE)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _call_has_kw(call: ast.Call, name: str) -> ast.keyword | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw
    return None


def _is_raw_os_environ_expr(node: ast.AST) -> bool:
    dn = _dotted_name(node)
    if dn in ("os.environ", "environ"):
        return True
    if isinstance(node, ast.Call):
        fn = _dotted_name(node.func)
        if fn in ("os.environ.copy", "environ.copy"):
            return True
        if fn == "dict" and len(node.args) == 1 and _dotted_name(node.args[0]) in ("os.environ", "environ"):
            return True
    if isinstance(node, ast.Dict):
        # {**os.environ, ...} has key=None and value=os.environ
        for k, v in zip(node.keys, node.values):
            if k is None and _dotted_name(v) in ("os.environ", "environ"):
                return True
    return False


def _node_contains_volatile_call(node: ast.AST) -> str | None:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = _dotted_name(sub.func)
            if fn in (
                "datetime.now",
                "datetime.datetime.now",
                "datetime.utcnow",
                "datetime.datetime.utcnow",
                "time.time",
                "uuid.uuid4",
                "uuid4",
                "random.random",
                "random.randint",
                "random.randrange",
            ) or fn.endswith((".now", ".utcnow", ".uuid4")):
                return fn
    return None


def _expr_contains_tool_result_ref(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and TOOL_RESULT_NAME_RE.search(sub.id):
            return True
        if isinstance(sub, ast.Attribute) and TOOL_RESULT_NAME_RE.search(sub.attr):
            return True
    return False


def _while_has_budget_guard(while_node: ast.While, source: str) -> bool:
    # Check if body contains an If with a budget/step/turn/limit guard leading to break/return/raise
    # OR calls a budget enforcement method (e.g., budget.check(), check_budget()).
    for sub in ast.walk(while_node):
        if isinstance(sub, ast.Call):
            fn = _dotted_name(sub.func)
            if re.search(r"(?:check|enforce|consume|assert|verify)_(?:budget|turn|step|limit)|budget\.(?:check|consume|enforce|record)", fn, re.IGNORECASE):
                return True
        if isinstance(sub, ast.If):
            test_src = ast.get_source_segment(source, sub.test) or ""
            if LOOP_GUARD_TOKEN_RE.search(test_src):
                for stmt in ast.walk(sub):
                    if isinstance(stmt, (ast.Break, ast.Return, ast.Raise)):
                        return True
    return False


def _while_calls_llm_or_tool(while_node: ast.While) -> bool:
    for sub in ast.walk(while_node):
        if isinstance(sub, ast.Call):
            fn = _dotted_name(sub.func)
            if fn and LLM_OR_TOOL_CALL_RE.search(fn):
                return True
    return False


def _is_retry_loop(loop_node: ast.AST, func_name: str, source: str) -> bool:
    if RETRY_NAME_RE.search(func_name):
        return True
    if isinstance(loop_node, ast.For):
        tgt = ast.get_source_segment(source, loop_node.target) or ""
        itr = ast.get_source_segment(source, loop_node.iter) or ""
        if RETRY_NAME_RE.search(tgt) or RETRY_NAME_RE.search(itr):
            return True
    elif isinstance(loop_node, ast.While):
        tst = ast.get_source_segment(source, loop_node.test) or ""
        if RETRY_NAME_RE.search(tst):
            return True
    return False


def _check_python_retry_loops(
    tree: ast.AST,
    raw_text: str,
    rel: str,
    suppressions: dict[int, set[str]],
    findings: list[Finding],
) -> None:
    def _walk_scope(node: ast.AST, func_name: str, in_retry_depth: int, decorated_retry: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_dec_retry = any(
                RETRY_NAME_RE.search(_dotted_name(d.func if isinstance(d, ast.Call) else d))
                for d in node.decorator_list
            )
            for child in node.body:
                _walk_scope(child, node.name, 1 if fn_dec_retry else 0, fn_dec_retry)
            return

        if isinstance(node, (ast.For, ast.While)):
            has_try = any(isinstance(sub, ast.Try) for sub in node.body)
            is_retry = has_try and _is_retry_loop(node, func_name, raw_text)
            if is_retry:
                if in_retry_depth >= 1 and not is_suppressed(suppressions, node.lineno, "AH009"):
                    findings.append(
                        Finding(
                            rule_id="AH009",
                            severity="WARN",
                            file=rel,
                            line=node.lineno,
                            message="Nested multi-layer retry detected; consolidate retries into a single layer with a retry budget.",
                        )
                    )
                else:
                    loop_src = ast.get_source_segment(raw_text, node) or ""
                    sleep_calls: list[ast.Call] = []
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            fn = _dotted_name(sub.func)
                            if fn in ("time.sleep", "asyncio.sleep", "sleep"):
                                sleep_calls.append(sub)
                    has_backoff = bool(BACKOFF_HINT_RE.search(loop_src))
                    if not sleep_calls and not has_backoff:
                        if not is_suppressed(suppressions, node.lineno, "AH009"):
                            findings.append(
                                Finding(
                                    rule_id="AH009",
                                    severity="WARN",
                                    file=rel,
                                    line=node.lineno,
                                    message="Retry loop has no sleep/backoff/jitter delay between attempts.",
                                )
                            )
                    else:
                        for sc in sleep_calls:
                            if sc.args and isinstance(sc.args[0], ast.Constant) and isinstance(sc.args[0].value, (int, float)):
                                if not has_backoff and not is_suppressed(suppressions, sc.lineno, "AH009"):
                                    findings.append(
                                        Finding(
                                            rule_id="AH009",
                                            severity="WARN",
                                            file=rel,
                                            line=sc.lineno,
                                            message="Retry loop sleeps a constant delay without exponential backoff + jitter.",
                                        )
                                    )
                    # Check SDK client with max_retries > 0 inside manual retry loop
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            mr_kw = _call_has_kw(sub, "max_retries")
                            if (
                                mr_kw is not None
                                and isinstance(mr_kw.value, ast.Constant)
                                and isinstance(mr_kw.value.value, int)
                                and mr_kw.value.value > 0
                            ):
                                if not is_suppressed(suppressions, sub.lineno, "AH009"):
                                    findings.append(
                                        Finding(
                                            rule_id="AH009",
                                            severity="WARN",
                                            file=rel,
                                            line=sub.lineno,
                                            message="Nested retry: SDK client configured with max_retries > 0 inside a manual retry loop.",
                                        )
                                    )
                for child in node.body:
                    _walk_scope(child, func_name, in_retry_depth + 1, decorated_retry)
                return

        for child in ast.iter_child_nodes(node):
            _walk_scope(child, func_name, in_retry_depth, decorated_retry)

    _walk_scope(tree, "", 0, False)


def _walk_async_blocking_io(
    async_fn: ast.AsyncFunctionDef,
    rel: str,
    suppressions: dict[int, set[str]],
    findings: list[Finding],
) -> None:
    """Inspect an async def body without descending into nested sync defs."""

    def _visit(node: ast.AST) -> None:
        if isinstance(node, ast.FunctionDef):
            return
        if isinstance(node, ast.Call):
            fn = _dotted_name(node.func)
            blocking = (
                fn == "time.sleep"
                or fn in (
                    "requests.get",
                    "requests.post",
                    "requests.put",
                    "requests.delete",
                    "requests.patch",
                    "requests.head",
                    "requests.request",
                    "subprocess.run",
                    "subprocess.check_output",
                    "subprocess.check_call",
                    "subprocess.call",
                    "urllib.request.urlopen",
                )
            )
            if blocking and not is_suppressed(suppressions, node.lineno, "AH014"):
                findings.append(
                    Finding(
                        rule_id="AH014",
                        severity="WARN",
                        file=rel,
                        line=node.lineno,
                        message=(
                            f"Blocking synchronous call '{fn}()' inside async def '{async_fn.name}'; "
                            "use an async equivalent or await asyncio.to_thread(...)."
                        ),
                    )
                )
        for child in ast.iter_child_nodes(node):
            _visit(child)

    for stmt in async_fn.body:
        _visit(stmt)


def _is_tool_handler_fn(node: ast.FunctionDef | ast.AsyncFunctionDef, rel: str) -> bool:
    name_l = node.name.lower()
    if name_l.startswith(("tool_", "handle_", "execute_tool", "run_tool")):
        return True
    for dec in node.decorator_list:
        dname = _dotted_name(dec.func if isinstance(dec, ast.Call) else dec).lower()
        if any(tok in dname for tok in ("tool", "register")):
            return True
    if "tool" in Path(rel).name.lower() and not name_l.startswith("_"):
        return True
    return False


def _is_raw_unbounded_output_expr(expr: ast.AST, tainted_vars: set[str]) -> str | None:
    if isinstance(expr, ast.Name) and expr.id in tainted_vars:
        return expr.id
    if isinstance(expr, ast.Attribute) and expr.attr in ("stdout", "stderr", "text"):
        return _dotted_name(expr) or f".{expr.attr}"
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr in ("read_text", "read"):
            fn = _dotted_name(expr.func) or expr.func.attr
            return f"{fn}()"
    return None


def _check_unbounded_tool_output_py(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    raw_text: str,
    rel: str,
    suppressions: dict[int, set[str]],
    findings: list[Finding],
) -> None:
    if not _is_tool_handler_fn(fn_node, rel):
        return
    fn_src = ast.get_source_segment(raw_text, fn_node) or ""
    if TRUNCATION_HINT_RE.search(fn_src):
        return
    # Any explicit slicing (e.g., output[:4000]) counts as bounded truncation
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Slice):
            return

    tainted: set[str] = set()
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Assign):
            if _is_raw_unbounded_output_expr(sub.value, tainted):
                for tgt in sub.targets:
                    if isinstance(tgt, ast.Name):
                        tainted.add(tgt.id)
        elif isinstance(sub, ast.Return) and sub.value is not None:
            raw_ref = _is_raw_unbounded_output_expr(sub.value, tainted)
            if raw_ref and not is_suppressed(suppressions, sub.lineno, "AH012"):
                findings.append(
                    Finding(
                        rule_id="AH012",
                        severity="WARN",
                        file=rel,
                        line=sub.lineno,
                        message=(
                            f"Tool handler '{fn_node.name}' returns raw unbounded output ({raw_ref}) "
                            "without truncation or disk spilling."
                        ),
                    )
                )


def audit_python_file(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []

    # Always scan hardcoded secrets (even in tests)
    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))

    if is_test_path(rel):
        return findings

    try:
        tree = ast.parse(raw_text, filename=rel)
    except SyntaxError:
        return findings

    has_real_sandbox = bool(SANDBOX_REAL_RE.search(raw_text))
    file_is_judge = bool(JUDGE_NAME_RE.search(rel))
    file_has_nonce = bool(NONCE_HINT_RE.search(raw_text))
    file_has_deferred_tools = bool(DEFERRED_TOOL_HINT_RE.search(raw_text))
    file_is_eval_runner = bool(re.search(r"(?:eval|bench)", Path(rel).name, re.IGNORECASE))
    file_has_pass_k = bool(re.search(r"\b(?:pass_at_k|pass_pow_k|pass@k|pass\^k)\b", raw_text))

    # Track tool registrations for AH013 bloat check
    static_tool_count = 0
    first_tool_reg_line: int | None = None

    # Track per-function tainted raw-env variables for AH005
    def _check_function_body(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        raw_env_vars: set[str] = set()
        for sub in ast.walk(fn_node):
            if isinstance(sub, ast.Assign):
                if _is_raw_os_environ_expr(sub.value):
                    for tgt in sub.targets:
                        if isinstance(tgt, ast.Name):
                            raw_env_vars.add(tgt.id)
            elif isinstance(sub, ast.Call):
                fn = _dotted_name(sub.func)
                if fn in (
                    "subprocess.run",
                    "subprocess.Popen",
                    "subprocess.check_output",
                    "subprocess.check_call",
                    "subprocess.call",
                    "asyncio.create_subprocess_exec",
                    "asyncio.create_subprocess_shell",
                ):
                    env_kw = _call_has_kw(sub, "env")
                    if (
                        env_kw is not None
                        and isinstance(env_kw.value, ast.Name)
                        and env_kw.value.id in raw_env_vars
                        and not _is_raw_os_environ_expr(env_kw.value)
                    ):
                        if not is_suppressed(suppressions, sub.lineno, "AH005"):
                            findings.append(
                                Finding(
                                    rule_id="AH005",
                                    severity="ERROR",
                                    file=rel,
                                    line=sub.lineno,
                                    message=(
                                        f"Raw host environment (os.environ) passed via '{env_kw.value.id}' to {fn}(..., env=...); "
                                        "pass a minimal allowlisted env dict instead."
                                    ),
                                )
                            )

        # AH012: Unbounded tool output
        _check_unbounded_tool_output_py(fn_node, raw_text, rel, suppressions, findings)

        # AH014: Blocking sync I/O inside async def
        if isinstance(fn_node, ast.AsyncFunctionDef):
            _walk_async_blocking_io(fn_node, rel, suppressions, findings)

        # AH015: Unprotected LLM-as-a-judge inside judge function
        if file_is_judge or JUDGE_NAME_RE.search(fn_node.name):
            fn_src = ast.get_source_segment(raw_text, fn_node) or ""
            fn_has_nonce = file_has_nonce or bool(NONCE_HINT_RE.search(fn_src))
            for sub in ast.walk(fn_node):
                if isinstance(sub, ast.Call):
                    temp_kw = _call_has_kw(sub, "temperature")
                    if (
                        temp_kw is not None
                        and isinstance(temp_kw.value, ast.Constant)
                        and isinstance(temp_kw.value.value, (int, float))
                        and temp_kw.value.value > 0
                    ):
                        if not is_suppressed(suppressions, sub.lineno, "AH015"):
                            findings.append(
                                Finding(
                                    rule_id="AH015",
                                    severity="WARN",
                                    file=rel,
                                    line=sub.lineno,
                                    message=(
                                        f"LLM judge call uses temperature={temp_kw.value.value} (> 0); "
                                        "set temperature=0 for reproducible grading."
                                    ),
                                )
                            )
                    cname = _dotted_name(sub.func)
                    if cname == "re.search" and sub.args:
                        pat_src = ast.get_source_segment(raw_text, sub.args[0]) or ""
                        if VERDICT_LABEL_RE.search(pat_src):
                            if not is_suppressed(suppressions, sub.lineno, "AH015"):
                                findings.append(
                                    Finding(
                                        rule_id="AH015",
                                        severity="WARN",
                                        file=rel,
                                        line=sub.lineno,
                                        message=(
                                            "Judge verdict parsed with re.search() (first match); "
                                            "use re.findall(...)[-1] to defend against injected early verdicts."
                                        ),
                                    )
                                )
                elif isinstance(sub, ast.JoinedStr) and not fn_has_nonce:
                    j_src = ast.get_source_segment(raw_text, sub) or ""
                    if JUDGE_UNSAFE_INTERP_RE.search(j_src):
                        if not is_suppressed(suppressions, sub.lineno, "AH015"):
                            findings.append(
                                Finding(
                                    rule_id="AH015",
                                    severity="WARN",
                                    file=rel,
                                    line=sub.lineno,
                                    message=(
                                        "Judge prompt interpolates submission/answer without nonce delimiters; "
                                        "wrap evaluated content in a per-call random nonce boundary."
                                    ),
                                )
                            )

    # Retry loop check across file (AH009)
    _check_python_retry_loops(tree, raw_text, rel, suppressions, findings)

    # Walk module AST
    for node in ast.walk(tree):
        # Function-level checks
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_function_body(node)
            for dec in node.decorator_list:
                dname = _dotted_name(dec.func if isinstance(dec, ast.Call) else dec)
                if dname in ("tool", "register_tool") or dname.endswith((".tool", ".register_tool")):
                    static_tool_count += 1
                    first_tool_reg_line = first_tool_reg_line or node.lineno

        # AH001: Unbounded while True loop
        elif isinstance(node, ast.While):
            if isinstance(node.test, ast.Constant) and bool(node.test.value):
                if _while_calls_llm_or_tool(node) and not _while_has_budget_guard(node, raw_text):
                    if not is_suppressed(suppressions, node.lineno, "AH001"):
                        findings.append(
                            Finding(
                                rule_id="AH001",
                                severity="ERROR",
                                file=rel,
                                line=node.lineno,
                                message=(
                                    "Unbounded 'while True' agent loop invokes model/tool without a "
                                    "step, turn, token, or deadline budget guard."
                                ),
                            )
                        )

        # AH002, AH003, AH005 (module-level), AH007, AH010, AH011, AH013, AH015 (module-level)
        elif isinstance(node, ast.Call):
            fn = _dotted_name(node.func)

            # AH002: Unsafe shell execution
            if fn in ("os.system", "os.popen", "asyncio.create_subprocess_shell"):
                if not is_suppressed(suppressions, node.lineno, "AH002"):
                    findings.append(
                        Finding(
                            rule_id="AH002",
                            severity="ERROR",
                            file=rel,
                            line=node.lineno,
                            message=f"Unsafe shell execution via {fn}(); use subprocess argv lists with shell=False inside a sandbox.",
                        )
                    )
            elif fn.startswith("subprocess."):
                shell_kw = _call_has_kw(node, "shell")
                if shell_kw is not None and isinstance(shell_kw.value, ast.Constant) and shell_kw.value.value is True:
                    if not is_suppressed(suppressions, node.lineno, "AH002"):
                        findings.append(
                            Finding(
                                rule_id="AH002",
                                severity="ERROR",
                                file=rel,
                                line=node.lineno,
                                message=f"{fn}(..., shell=True) enables shell injection; pass an argv list with shell=False.",
                            )
                        )

            # AH003: Dynamic code execution (excludes ast.literal_eval and regex .exec)
            if fn in ("eval", "exec", "builtins.eval", "builtins.exec"):
                if not is_suppressed(suppressions, node.lineno, "AH003"):
                    findings.append(
                        Finding(
                            rule_id="AH003",
                            severity="ERROR",
                            file=rel,
                            line=node.lineno,
                            message=f"Dynamic code execution via {fn}() in harness/tool code; use safe parsers or an isolated sandbox.",
                        )
                    )

            # AH005: Direct raw os.environ passed to subprocess (module-level or inside functions)
            if fn in (
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.check_output",
                "subprocess.check_call",
                "subprocess.call",
                "asyncio.create_subprocess_exec",
                "asyncio.create_subprocess_shell",
            ):
                env_kw = _call_has_kw(node, "env")
                if env_kw is not None and _is_raw_os_environ_expr(env_kw.value):
                    if not is_suppressed(suppressions, node.lineno, "AH005"):
                        findings.append(
                            Finding(
                                rule_id="AH005",
                                severity="ERROR",
                                file=rel,
                                line=node.lineno,
                                message=(
                                    f"Raw host environment (os.environ) passed to {fn}(..., env=...); "
                                    "pass a minimal allowlisted env dict instead."
                                ),
                            )
                        )

            # AH007: Missing timeout on subprocess / requests / httpx / urlopen
            if fn in ("subprocess.run", "subprocess.check_output", "subprocess.check_call", "subprocess.call"):
                if _call_has_kw(node, "timeout") is None and not is_suppressed(suppressions, node.lineno, "AH007"):
                    findings.append(
                        Finding(
                            rule_id="AH007",
                            severity="WARN",
                            file=rel,
                            line=node.lineno,
                            message=f"{fn}() called without timeout=; hung tool commands can stall the harness indefinitely.",
                        )
                    )
            elif fn in (
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.delete",
                "requests.patch",
                "requests.head",
                "requests.request",
                "httpx.get",
                "httpx.post",
                "httpx.put",
                "httpx.delete",
                "httpx.patch",
                "httpx.head",
                "httpx.request",
            ):
                if _call_has_kw(node, "timeout") is None and not is_suppressed(suppressions, node.lineno, "AH007"):
                    findings.append(
                        Finding(
                            rule_id="AH007",
                            severity="WARN",
                            file=rel,
                            line=node.lineno,
                            message=f"{fn}() called without explicit timeout= parameter.",
                        )
                    )
            elif fn in ("urllib.request.urlopen", "urlopen"):
                if (
                    _call_has_kw(node, "timeout") is None
                    and len(node.args) < 3
                    and not is_suppressed(suppressions, node.lineno, "AH007")
                ):
                    findings.append(
                        Finding(
                            rule_id="AH007",
                            severity="WARN",
                            file=rel,
                            line=node.lineno,
                            message=f"{fn}() called without explicit timeout= parameter.",
                        )
                    )

            # AH010: json.dumps(..., sort_keys=False)
            if fn == "json.dumps":
                sk_kw = _call_has_kw(node, "sort_keys")
                if sk_kw is not None and isinstance(sk_kw.value, ast.Constant) and sk_kw.value.value is False:
                    if not is_suppressed(suppressions, node.lineno, "AH010"):
                        findings.append(
                            Finding(
                                rule_id="AH010",
                                severity="WARN",
                                file=rel,
                                line=node.lineno,
                                message="json.dumps(..., sort_keys=False) breaks deterministic prompt-cache serialization; use sort_keys=True.",
                            )
                        )

            # AH011: Stripping reasoning_content / thinking via .pop()
            if isinstance(node.func, ast.Attribute) and node.func.attr == "pop" and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and arg0.value in ("reasoning_content", "thinking"):
                    if not is_suppressed(suppressions, node.lineno, "AH011"):
                        findings.append(
                            Finding(
                                rule_id="AH011",
                                severity="WARN",
                                file=rel,
                                line=node.lineno,
                                message=f"Stripping '{arg0.value}' from message history breaks multi-turn reasoning APIs.",
                            )
                        )

            # AH013: Tool registrations via .register() / ToolSpec()
            if (
                (isinstance(node.func, ast.Attribute) and node.func.attr in ("register", "register_tool", "add_tool"))
                or fn in ("ToolSpec", "ToolDefinition")
            ):
                static_tool_count += 1
                first_tool_reg_line = first_tool_reg_line or node.lineno

        # AH004, AH010, AH013 (TOOLS list), AH015 (prompt templates), AH016 (hardcoded trials=1)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                if not isinstance(tgt, ast.Name):
                    continue
                tname = tgt.id

                # AH004: Blacklist sandbox illusion
                if BLACKLIST_NAME_RE.search(tname) and not has_real_sandbox:
                    val_src = ast.get_source_segment(raw_text, node.value) or ""
                    if SHELL_CMD_HINT_RE.search(val_src):
                        if not is_suppressed(suppressions, node.lineno, "AH004"):
                            findings.append(
                                Finding(
                                    rule_id="AH004",
                                    severity="ERROR",
                                    file=rel,
                                    line=node.lineno,
                                    message=(
                                        f"Command denylist '{tname}' without OS/container sandboxing is a bypassable "
                                        "sandbox illusion; enforce OS/container confinement."
                                    ),
                                )
                            )

                # AH010: Volatile value in SYSTEM_PROMPT / system_prompt
                if SYSTEM_PROMPT_NAME_RE.search(tname):
                    volatile_fn = _node_contains_volatile_call(node.value)
                    if volatile_fn and not is_suppressed(suppressions, node.lineno, "AH010"):
                        findings.append(
                            Finding(
                                rule_id="AH010",
                                severity="WARN",
                                file=rel,
                                line=node.lineno,
                                message=(
                                    f"Volatile call '{volatile_fn}()' in '{tname}' invalidates prompt KV-cache "
                                    "prefix on every turn; keep system prompt static."
                                ),
                            )
                        )

                # AH013: Large static TOOLS = [...] list
                if tname.lower() in ("tools", "tool_specs", "tool_schemas", "tool_definitions"):
                    if isinstance(node.value, (ast.List, ast.Tuple)) and len(node.value.elts) > 15:
                        if not file_has_deferred_tools and not is_suppressed(suppressions, node.lineno, "AH013"):
                            findings.append(
                                Finding(
                                    rule_id="AH013",
                                    severity="WARN",
                                    file=rel,
                                    line=node.lineno,
                                    message=(
                                        f"Static tool catalog '{tname}' defines {len(node.value.elts)} tools (>15) "
                                        "without deferred/lazy loading (defer_loading / tool_search)."
                                    ),
                                )
                            )

                # AH015: Module-level judge prompt template interpolating {submission}/{answer} without nonce
                if (file_is_judge or JUDGE_NAME_RE.search(tname)) and not file_has_nonce:
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if JUDGE_UNSAFE_INTERP_RE.search(node.value.value):
                            if not is_suppressed(suppressions, node.lineno, "AH015"):
                                findings.append(
                                    Finding(
                                        rule_id="AH015",
                                        severity="WARN",
                                        file=rel,
                                        line=node.lineno,
                                        message=(
                                            f"Judge prompt '{tname}' interpolates submission/answer without "
                                            "random nonce delimiters."
                                        ),
                                    )
                                )

                # AH016: Hardcoded trials=1 / k=1 in eval runner
                if file_is_eval_runner and not file_has_pass_k:
                    if tname.lower() in ("trials", "num_trials", "trials_per_task", "k"):
                        if isinstance(node.value, ast.Constant) and node.value.value == 1:
                            if not is_suppressed(suppressions, node.lineno, "AH016"):
                                findings.append(
                                    Finding(
                                        rule_id="AH016",
                                        severity="WARN",
                                        file=rel,
                                        line=node.lineno,
                                        message=(
                                            f"Eval runner hardcodes {tname}=1 without pass@k/pass^k; "
                                            "run multiple trials (k >= 3) to capture stochastic variance."
                                        ),
                                    )
                                )

        # AH008: Silent exception swallowing & history erasure in except
        elif isinstance(node, ast.ExceptHandler):
            is_broad = node.type is None or _dotted_name(node.type) in ("Exception", "BaseException")
            if is_broad and len(node.body) == 1:
                only = node.body[0]
                is_empty = isinstance(only, ast.Pass) or (
                    isinstance(only, ast.Expr) and isinstance(only.value, ast.Constant) and only.value.value is Ellipsis
                )
                if is_empty and not is_suppressed(suppressions, node.lineno, "AH008"):
                    findings.append(
                        Finding(
                            rule_id="AH008",
                            severity="WARN",
                            file=rel,
                            line=node.lineno,
                            message="Silent broad exception swallowing ('except ...: pass') hides harness/tool failures.",
                        )
                    )
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "pop":
                    target_name = _dotted_name(sub.func.value)
                    if HISTORY_NAME_RE.search(target_name.split(".")[-1]):
                        if not is_suppressed(suppressions, sub.lineno, "AH008"):
                            findings.append(
                                Finding(
                                    rule_id="AH008",
                                    severity="WARN",
                                    file=rel,
                                    line=sub.lineno,
                                    message=(
                                        f"Erasing failed turn via '{target_name}.pop()' inside except block "
                                        "destroys error-recovery signal; keep failed turns in history."
                                    ),
                                )
                            )

        # AH010 & AH011 on dict literals
        elif isinstance(node, ast.Dict):
            kv: dict[str, ast.AST] = {}
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    kv[k.value] = v
            role_node = kv.get("role")
            content_node = kv.get("content")
            if isinstance(role_node, ast.Constant) and content_node is not None:
                if role_node.value == "system":
                    volatile_fn = _node_contains_volatile_call(content_node)
                    if volatile_fn and not is_suppressed(suppressions, node.lineno, "AH010"):
                        findings.append(
                            Finding(
                                rule_id="AH010",
                                severity="WARN",
                                file=rel,
                                line=node.lineno,
                                message=(
                                    f"Volatile call '{volatile_fn}()' inside role='system' message "
                                    "invalidates prompt KV-cache prefix."
                                ),
                            )
                        )
                elif role_node.value == "user" and _expr_contains_tool_result_ref(content_node):
                    if not is_suppressed(suppressions, node.lineno, "AH011"):
                        findings.append(
                            Finding(
                                rule_id="AH011",
                                severity="WARN",
                                file=rel,
                                line=node.lineno,
                                message=(
                                    "Tool result cast as role='user'; use dedicated role='tool' so reasoning "
                                    "traces are preserved and trust boundaries stay explicit."
                                ),
                            )
                        )

        # AH011: del msg["reasoning_content"] / del msg["thinking"]
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:
                if isinstance(tgt, ast.Subscript) and isinstance(tgt.slice, ast.Constant):
                    if tgt.slice.value in ("reasoning_content", "thinking"):
                        if not is_suppressed(suppressions, node.lineno, "AH011"):
                            findings.append(
                                Finding(
                                    rule_id="AH011",
                                    severity="WARN",
                                    file=rel,
                                    line=node.lineno,
                                    message=f"Deleting '{tgt.slice.value}' from message history breaks multi-turn reasoning APIs.",
                                )
                            )

    if static_tool_count > 15 and not file_has_deferred_tools and first_tool_reg_line is not None:
        if not is_suppressed(suppressions, first_tool_reg_line, "AH013"):
            findings.append(
                Finding(
                    rule_id="AH013",
                    severity="WARN",
                    file=rel,
                    line=first_tool_reg_line,
                    message=(
                        f"File statically registers {static_tool_count} tools (>15) without deferred/lazy "
                        "loading (defer_loading / tool_search)."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# JS/TS auditor
# ---------------------------------------------------------------------------

JS_LLM_TOOL_RE = re.compile(
    r"\b(?:complete|chat|generate|invoke|respond|callModel|callLlm|createMessage|"
    r"executeTool|runTool|dispatchTool|callTool|messages\.create|responses\.create|completions\.create)\s*\(",
    re.IGNORECASE,
)

JS_LOOP_GUARD_RE = re.compile(
    r"\b(?:maxSteps|maxTurns|maxIterations|maxTokens|maxCost|budget|deadline|timeout|"
    r"remaining|exhausted|aborted|step|steps|turn|turns|iteration|iterations|attempts)\b",
    re.IGNORECASE,
)

JS_VOLATILE_RE = re.compile(r"\b(?:Date\.now\s*\(|new\s+Date\s*\(|crypto\.randomUUID\s*\(|Math\.random\s*\()")


def audit_js_ts_file(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []

    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))
    if is_test_path(rel):
        return findings

    no_comments = strip_js_comments(raw_text, blank_strings=False)
    code_only = strip_js_comments(raw_text, blank_strings=True)

    has_real_sandbox = bool(SANDBOX_REAL_RE.search(no_comments))
    file_is_judge = bool(JUDGE_NAME_RE.search(rel))
    file_has_nonce = bool(NONCE_HINT_RE.search(no_comments))
    file_has_deferred = bool(DEFERRED_TOOL_HINT_RE.search(no_comments))
    file_is_eval_runner = bool(re.search(r"(?:eval|bench)", Path(rel).name, re.IGNORECASE))
    file_has_pass_k = bool(re.search(r"\b(?:passAtK|passPowK|pass_at_k|pass_pow_k)\b", no_comments))

    # AH001: while (true) { ... }
    for m in re.finditer(r"\bwhile\s*\(\s*true\s*\)\s*\{", code_only):
        open_brace = m.end() - 1
        parsed = _scan_balanced_js(code_only, open_brace, "{", "}")
        if not parsed:
            continue
        body, _ = parsed
        line_no = _line_of(code_only, m.start())
        if JS_LLM_TOOL_RE.search(body):
            has_guard = bool(
                JS_LOOP_GUARD_RE.search(body)
                and re.search(r"\b(?:break|return|throw)\b", body)
            ) or bool(re.search(r"\b(?:checkBudget|enforceBudget|consumeStep|budget\.check)\s*\(", body))
            if not has_guard and not is_suppressed(suppressions, line_no, "AH001"):
                findings.append(
                    Finding(
                        rule_id="AH001",
                        severity="ERROR",
                        file=rel,
                        line=line_no,
                        message="Unbounded 'while (true)' agent loop invokes model/tool without a step, turn, or budget guard.",
                    )
                )

    # AH002: exec( / execSync( with template literal / concatenation (excluding regex .exec())
    imports_cp = bool(re.search(r"""(?:from\s+["'](?:node:)?child_process["']|require\s*\(\s*["'](?:node:)?child_process["']\s*\))""", no_comments))
    for m in re.finditer(r"(?:(?P<obj>[A-Za-z_$][\w$]*)\s*\.\s*)?\b(?P<fn>execSync|exec)\s*\(", no_comments):
        obj = m.group("obj")
        fn = m.group("fn")
        if obj and obj not in ("child_process", "childProcess", "cp", "proc"):
            continue
        if not obj and fn == "exec" and not imports_cp:
            continue
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "(", ")")
        if not parsed:
            continue
        args_str, _ = parsed
        if "${" in args_str or "+" in strip_js_comments(args_str, blank_strings=True):
            line_no = _line_of(no_comments, m.start())
            if not is_suppressed(suppressions, line_no, "AH002"):
                findings.append(
                    Finding(
                        rule_id="AH002",
                        severity="ERROR",
                        file=rel,
                        line=line_no,
                        message=f"Unsafe shell execution via {fn}() with interpolated/concatenated command; use execFile/spawn with argv array.",
                    )
                )

    # AH003: eval( / new Function(
    for m in re.finditer(r"(?<!\.)\beval\s*\(|\bnew\s+Function\s*\(", code_only):
        line_no = _line_of(code_only, m.start())
        if not is_suppressed(suppressions, line_no, "AH003"):
            findings.append(
                Finding(
                    rule_id="AH003",
                    severity="ERROR",
                    file=rel,
                    line=line_no,
                    message="Dynamic code execution via eval() or new Function() in harness/tool code.",
                )
            )

    # AH004: Blacklist sandbox illusion
    if not has_real_sandbox:
        for m in re.finditer(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(\[[^\]]*\]|new\s+Set\s*\([^)]*\))",
            no_comments,
            re.DOTALL,
        ):
            vname, vval = m.group(1), m.group(2)
            if BLACKLIST_NAME_RE.search(vname) and SHELL_CMD_HINT_RE.search(vval):
                line_no = _line_of(no_comments, m.start())
                if not is_suppressed(suppressions, line_no, "AH004"):
                    findings.append(
                        Finding(
                            rule_id="AH004",
                            severity="ERROR",
                            file=rel,
                            line=line_no,
                            message=f"Command denylist '{vname}' without OS/container sandbox is a bypassable sandbox illusion.",
                        )
                    )

    # AH005: Raw process.env passed to subprocess spawn/execFile/exec/fork
    for m in re.finditer(r"\b(?:spawn|spawnSync|execFile|execFileSync|exec|execSync|fork)\s*\(", no_comments):
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "(", ")")
        if not parsed:
            continue
        args_str, _ = parsed
        if re.search(r"\benv\s*:\s*(?:process\.env\b|\{\s*\.\.\.process\.env\b)", args_str):
            line_no = _line_of(no_comments, m.start())
            if not is_suppressed(suppressions, line_no, "AH005"):
                findings.append(
                    Finding(
                        rule_id="AH005",
                        severity="ERROR",
                        file=rel,
                        line=line_no,
                        message="Raw process.env passed to child process; pass an explicit allowlisted env object instead.",
                    )
                )

    # AH007: fetch() without signal / AbortSignal
    for m in re.finditer(r"(?<!\.)\bfetch\s*\(", no_comments):
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "(", ")")
        if not parsed:
            continue
        args_str, _ = parsed
        line_no = _line_of(no_comments, m.start())
        # If there's no comma at top-level, fetch(url) has no options/signal;
        # if 2nd arg is an inline object literal without 'signal', also flag.
        has_signal = bool(re.search(r"\bsignal\b|AbortSignal", args_str))
        if not has_signal:
            # Avoid false positive if passing a pre-built init variable (e.g. fetch(url, init))
            stripped_args = strip_js_comments(args_str, blank_strings=True)
            if "," not in stripped_args or "{" in stripped_args:
                if not is_suppressed(suppressions, line_no, "AH007"):
                    findings.append(
                        Finding(
                            rule_id="AH007",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message="fetch() called without AbortSignal / timeout; pass signal: AbortSignal.timeout(...).",
                        )
                    )

    # AH008: Empty catch {} or messages.pop() inside catch
    for m in re.finditer(r"\bcatch\s*(?:\([^)]*\))?\s*\{", code_only):
        parsed = _scan_balanced_js(code_only, m.end() - 1, "{", "}")
        if not parsed:
            continue
        body, _ = parsed
        line_no = _line_of(code_only, m.start())
        if not body.strip():
            if not is_suppressed(suppressions, line_no, "AH008"):
                findings.append(
                    Finding(
                        rule_id="AH008",
                        severity="WARN",
                        file=rel,
                        line=line_no,
                        message="Silent empty catch block swallows harness/tool errors.",
                    )
                )
        elif re.search(r"\b(?:messages|history|turns|conversation|events|transcript)\s*\.\s*pop\s*\(", body):
            if not is_suppressed(suppressions, line_no, "AH008"):
                findings.append(
                    Finding(
                        rule_id="AH008",
                        severity="WARN",
                        file=rel,
                        line=line_no,
                        message="Erasing failed turn via .pop() inside catch block destroys error-recovery evidence.",
                    )
                )

    # AH009: Naive retry loop without backoff/jitter
    for m in re.finditer(r"\b(?:for|while)\s*\(([^)]*)\)\s*\{", code_only):
        header = m.group(1)
        if not RETRY_NAME_RE.search(header):
            continue
        parsed = _scan_balanced_js(code_only, m.end() - 1, "{", "}")
        if not parsed:
            continue
        body, _ = parsed
        if "catch" not in body:
            continue
        line_no = _line_of(code_only, m.start())
        has_backoff = bool(re.search(r"Math\.pow|\*\*|<<|Math\.random|jitter|backoff", body))
        has_delay = bool(re.search(r"setTimeout|sleep|delay", body))
        if not has_backoff and (not has_delay or re.search(r"setTimeout\s*\([^,]+,\s*\d+\s*\)", body)):
            if not is_suppressed(suppressions, line_no, "AH009"):
                findings.append(
                    Finding(
                        rule_id="AH009",
                        severity="WARN",
                        file=rel,
                        line=line_no,
                        message="Retry loop lacks exponential backoff + jitter (constant or zero delay between attempts).",
                    )
                )

    # AH010: Prompt-cache prefix buster in JS/TS
    for m in re.finditer(
        r"(?:\b(?:systemPrompt|SYSTEM_PROMPT|system_prompt|systemMessage|promptPrefix)\b\s*=|role\s*:\s*['\"]system['\"])[^;\n]{0,300}",
        no_comments,
    ):
        snippet = m.group(0)
        if JS_VOLATILE_RE.search(snippet):
            line_no = _line_of(no_comments, m.start())
            if not is_suppressed(suppressions, line_no, "AH010"):
                findings.append(
                    Finding(
                        rule_id="AH010",
                        severity="WARN",
                        file=rel,
                        line=line_no,
                        message="Volatile timestamp/UUID inside system prompt breaks prompt KV-cache prefix invariance.",
                    )
                )

    # AH011: Tool result cast as role: "user" or deleting reasoning/thinking
    for m in re.finditer(
        r"\{\s*role\s*:\s*['\"]user['\"]\s*,\s*content\s*:\s*([^}]+)\}",
        no_comments,
    ):
        if re.search(r"\b(?:toolResult|tool_result|toolOutput|tool_output|toolResponse)\b", m.group(1)):
            line_no = _line_of(no_comments, m.start())
            if not is_suppressed(suppressions, line_no, "AH011"):
                findings.append(
                    Finding(
                        rule_id="AH011",
                        severity="WARN",
                        file=rel,
                        line=line_no,
                        message="Tool result cast as role: 'user'; use role: 'tool' to preserve reasoning and trust boundaries.",
                    )
                )
    for m in re.finditer(r"\bdelete\s+[A-Za-z_$][\w$.]*\.(?:reasoning_content|thinking)\b", code_only):
        line_no = _line_of(code_only, m.start())
        if not is_suppressed(suppressions, line_no, "AH011"):
            findings.append(
                Finding(
                    rule_id="AH011",
                    severity="WARN",
                    file=rel,
                    line=line_no,
                    message="Deleting reasoning_content/thinking from history breaks multi-turn reasoning APIs.",
                )
            )

    # AH012: Unbounded tool output returned in JS/TS tool handler
    for m in re.finditer(
        r"\b(?:async\s+)?function\s+((?:tool|handle|executeTool|runTool)[A-Za-z0-9_$]*)\s*\([^)]*\)\s*(?::[^{]+)?\{",
        no_comments,
    ):
        fname = m.group(1)
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "{", "}")
        if not parsed:
            continue
        body, _ = parsed
        if TRUNCATION_HINT_RE.search(body) or ".slice(" in body or ".substring(" in body:
            continue
        ret_m = re.search(
            r"\breturn\s+(?:await\s+)?(?:[A-Za-z_$][\w$.]*\.stdout\b|readFileSync\s*\(|(?:fs\.)?readFile\s*\(|[A-Za-z_$][\w$.]*\.text\s*\()",
            body,
        )
        if ret_m:
            line_no = _line_of(no_comments, m.end() + ret_m.start())
            if not is_suppressed(suppressions, line_no, "AH012"):
                findings.append(
                    Finding(
                        rule_id="AH012",
                        severity="WARN",
                        file=rel,
                        line=line_no,
                        message=f"Tool handler '{fname}' returns raw unbounded output without truncation or disk spilling.",
                    )
                )

    # AH013: Static tool bloat (>15 registerTool calls without deferred loading)
    reg_matches = list(re.finditer(r"\b(?:registerTool|register_tool|addTool)\s*\(", code_only))
    if len(reg_matches) > 15 and not file_has_deferred:
        line_no = _line_of(code_only, reg_matches[0].start())
        if not is_suppressed(suppressions, line_no, "AH013"):
            findings.append(
                Finding(
                    rule_id="AH013",
                    severity="WARN",
                    file=rel,
                    line=line_no,
                    message=f"File registers {len(reg_matches)} static tools (>15) without deferred/lazy loading.",
                )
            )

    # AH015: Unprotected LLM-as-a-judge in JS/TS
    if file_is_judge:
        if not file_has_nonce:
            for m in re.finditer(r"\$\{\s*(?:submission|answer|response|candidate|output)\s*\}", no_comments):
                line_no = _line_of(no_comments, m.start())
                if not is_suppressed(suppressions, line_no, "AH015"):
                    findings.append(
                        Finding(
                            rule_id="AH015",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message="Judge prompt interpolates submission/answer without nonce boundary delimiters.",
                        )
                    )
        for m in re.finditer(r"\btemperature\s*:\s*([0-9]*\.?[0-9]+)", no_comments):
            try:
                val = float(m.group(1))
            except ValueError:
                continue
            if val > 0:
                line_no = _line_of(no_comments, m.start())
                if not is_suppressed(suppressions, line_no, "AH015"):
                    findings.append(
                        Finding(
                            rule_id="AH015",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message=f"LLM judge call sets temperature: {val} (> 0); set temperature: 0.",
                        )
                    )

    # AH016: Hardcoded trials = 1 in JS/TS eval runner without passAtK/passPowK
    if file_is_eval_runner and not file_has_pass_k:
        for m in re.finditer(r"\b(?:const|let|var)\s+(?:trials|numTrials|trialsPerTask)\s*=\s*1\b", code_only):
            line_no = _line_of(code_only, m.start())
            if not is_suppressed(suppressions, line_no, "AH016"):
                findings.append(
                    Finding(
                        rule_id="AH016",
                        severity="WARN",
                        file=rel,
                        line=line_no,
                        message="Eval runner hardcodes trials = 1 without pass@k/pass^k; use multi-trial evaluation (k >= 3).",
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Docker & Compose auditor (AH005 + AH006)
# ---------------------------------------------------------------------------

def audit_dockerfile(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []

    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))

    for idx, line in enumerate(raw_text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", stripped, re.IGNORECASE)
        if m:
            img = m.group(1)
            if img.lower() == "scratch":
                continue
            if img.endswith(":latest") and "@sha256:" not in img:
                if not is_suppressed(suppressions, idx, "AH006"):
                    findings.append(
                        Finding(
                            rule_id="AH006",
                            severity="ERROR",
                            file=rel,
                            line=idx,
                            message=f"Dockerfile uses mutable ':latest' tag ('{img}') without @sha256 digest pin.",
                        )
                    )
    return findings


def audit_compose_file(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []

    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))

    lines = raw_text.splitlines()
    has_services = False
    has_network_none = False
    in_volumes = False
    volumes_indent = -1

    for idx, raw_line in enumerate(lines, 1):
        # Strip YAML inline comments (outside quotes)
        line = re.sub(r"\s+#.*$", "", raw_line)
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))

        if re.match(r"^services\s*:", stripped):
            has_services = True

        if re.match(r"^network_mode\s*:\s*['\"]?none['\"]?$", stripped, re.IGNORECASE):
            has_network_none = True

        if re.match(r"^privileged\s*:\s*true\b", stripped, re.IGNORECASE):
            if not is_suppressed(suppressions, idx, "AH006"):
                findings.append(
                    Finding(
                        rule_id="AH006",
                        severity="ERROR",
                        file=rel,
                        line=idx,
                        message="Compose service sets 'privileged: true', breaking container sandbox isolation.",
                    )
                )

        if "docker.sock" in stripped:
            if not is_suppressed(suppressions, idx, "AH006"):
                findings.append(
                    Finding(
                        rule_id="AH006",
                        severity="ERROR",
                        file=rel,
                        line=idx,
                        message="Compose mounts docker.sock into sandbox container, granting host root equivalence.",
                    )
                )

        img_m = re.match(r"^image\s*:\s*['\"]?([^\s'\"]+)['\"]?", stripped)
        if img_m:
            img = img_m.group(1)
            if img.endswith(":latest") and "@sha256:" not in img:
                if not is_suppressed(suppressions, idx, "AH006"):
                    findings.append(
                        Finding(
                            rule_id="AH006",
                            severity="ERROR",
                            file=rel,
                            line=idx,
                            message=f"Compose image '{img}' uses mutable ':latest' tag without @sha256 digest pin.",
                        )
                    )

        if re.match(r"^volumes\s*:", stripped):
            in_volumes = True
            volumes_indent = indent
            continue

        if in_volumes:
            if indent <= volumes_indent and not stripped.startswith("-"):
                in_volumes = False
            elif stripped.startswith("-"):
                mount = stripped.lstrip("-").strip().strip("'\"")
                if "docker.sock" not in mount:
                    # Host bind mount starts with /, ./, ../, ~, or ${...}
                    if re.match(r"^(?:/|\.\.?/|~|\$\{)", mount) and ":" in mount:
                        parts = mount.split(":")
                        mode = parts[2].lower() if len(parts) >= 3 else ""
                        if "ro" not in mode.split(","):
                            if not is_suppressed(suppressions, idx, "AH006"):
                                findings.append(
                                    Finding(
                                        rule_id="AH006",
                                        severity="ERROR",
                                        file=rel,
                                        line=idx,
                                        message=f"Writable host bind mount '{mount}' in compose sandbox; mount read-only (:ro).",
                                    )
                                )

    if has_services and not has_network_none:
        if not is_suppressed(suppressions, 1, "AH006"):
            findings.append(
                Finding(
                    rule_id="AH006",
                    severity="ERROR",
                    file=rel,
                    line=1,
                    message="Compose sandbox missing 'network_mode: none'; isolate egress or route via an allowlisting proxy.",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# MCP JSON config auditor (AH005 + AH013)
# ---------------------------------------------------------------------------

def _is_pinned_npm_pkg(arg: str) -> bool:
    # Scoped: @scope/pkg@1.2.3 -> must have @<digit> after the first slash
    if arg.startswith("@"):
        if "/" not in arg:
            return False
        after_slash = arg.split("/", 1)[1]
        return bool(re.search(r"@\d+\.\d+", after_slash))
    return bool(re.search(r"@\d+\.\d+", arg))


def audit_mcp_config(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []

    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return findings

    if not isinstance(data, dict):
        return findings

    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return findings

    raw_lines = raw_text.splitlines()

    def _find_line(needle: str) -> int:
        for idx, ln in enumerate(raw_lines, 1):
            if needle in ln:
                return idx
        return 1

    for srv_name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command") or "")
        args = cfg.get("args") or []
        if not isinstance(args, list):
            args = []
        str_args = [str(a) for a in args]

        flagged_srv = False
        # Check @latest / :latest in any arg
        for a in str_args:
            if "@latest" in a or a.endswith(":latest"):
                line_no = _find_line(a)
                if not is_suppressed(suppressions, line_no, "AH013"):
                    findings.append(
                        Finding(
                            rule_id="AH013",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message=f"MCP server '{srv_name}' references mutable tag '{a}'; pin to an exact version or hash.",
                        )
                    )
                    flagged_srv = True
                break

        if flagged_srv:
            continue

        # Check npx -y / --yes without pinned semver package
        if Path(cmd).name.lower() in ("npx", "npx.cmd"):
            has_yes = any(a in ("-y", "--yes") for a in str_args)
            pkg_args = [a for a in str_args if not a.startswith("-")]
            if has_yes and pkg_args and not _is_pinned_npm_pkg(pkg_args[0]):
                line_no = _find_line(pkg_args[0])
                if not is_suppressed(suppressions, line_no, "AH013"):
                    findings.append(
                        Finding(
                            rule_id="AH013",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message=(
                                f"MCP server '{srv_name}' runs unpinned 'npx -y {pkg_args[0]}'; "
                                "pin an explicit version (e.g., pkg@1.2.3) to mitigate rug-pull updates."
                            ),
                        )
                    )

    return findings


# ---------------------------------------------------------------------------
# Project-level eval check (AH016)
# ---------------------------------------------------------------------------

def _project_has_eval_suite(root: Path, all_files: list[Path]) -> bool:
    for p in all_files:
        rel_l = p.relative_to(root).as_posix().lower()
        if any(tok in rel_l for tok in ("eval", "benchmark", "grader")):
            return True
    return False


# ---------------------------------------------------------------------------
# SARIF 2.1.0 & audit runner
# ---------------------------------------------------------------------------

def build_sarif_rules() -> list[dict[str, object]]:
    sarif_rules: list[dict[str, object]] = []
    for r in RULES:
        sarif_rules.append(
            {
                "id": r.id,
                "name": r.name,
                "shortDescription": {"text": r.short_description},
                "fullDescription": {"text": r.full_description},
                "defaultConfiguration": {"level": SARIF_LEVEL_MAP[r.default_severity]},
                "helpUri": r.help_uri,
                "help": {"text": r.remediation},
                "properties": {
                    "tags": ["agent-harness", *r.tags],
                    "remediation": r.remediation,
                },
            }
        )
    return sarif_rules


def build_sarif_report(result: dict[str, object]) -> dict[str, object]:
    """Convert a run_audit() dictionary into a valid SARIF 2.1.0 report."""
    details = result.get("details") or []
    sarif_results: list[dict[str, object]] = []

    for detail in details:
        if not isinstance(detail, dict):
            continue
        rule_id = str(detail.get("rule_id") or "AH001")
        rule_index = RULE_INDEX.get(rule_id, 0)
        severity = str(detail.get("severity") or "WARN").upper()
        level = SARIF_LEVEL_MAP.get(severity, "warning")
        message_text = str(detail.get("message") or "")
        file_rel = detail.get("file")
        line_raw = detail.get("line")

        uri = file_rel.replace("\\", "/") if isinstance(file_rel, str) and file_rel else "."
        start_line = int(line_raw) if isinstance(line_raw, int) and line_raw >= 1 else 1

        sarif_results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": start_line},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-harness-auditor",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Destro01400/agent-harness",
                        "rules": build_sarif_rules(),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def run_audit(root: Path, ignore_dirs: set[str] | None = None) -> dict[str, object]:
    extra_ignore = ignore_dirs or set()
    buckets = iter_scanned_files(root, extra_ignore)

    findings: list[Finding] = []
    for pf in buckets["python"]:
        findings.extend(audit_python_file(pf, root))
    for jf in buckets["js_ts"]:
        findings.extend(audit_js_ts_file(jf, root))
    for df in buckets["docker"]:
        findings.extend(audit_dockerfile(df, root))
    for cf in buckets["compose"]:
        findings.extend(audit_compose_file(cf, root))
    for mf in buckets["mcp"]:
        findings.extend(audit_mcp_config(mf, root))

    code_file_count = len(buckets["python"]) + len(buckets["js_ts"])
    if code_file_count > 0 and not _project_has_eval_suite(root, buckets["all"]):
        findings.append(
            Finding(
                rule_id="AH016",
                severity="INFO",
                file=None,
                line=None,
                message=(
                    "No evaluation suite detected in project (evals/, benchmarks/, or graders); "
                    "add multi-trial evals reporting pass@k and pass^k."
                ),
            )
        )

    counts = {
        "error": sum(1 for f in findings if f.severity == "ERROR"),
        "warn": sum(1 for f in findings if f.severity == "WARN"),
        "info": sum(1 for f in findings if f.severity == "INFO"),
    }

    return {
        "root": str(root),
        "scanned": {
            "python": len(buckets["python"]),
            "js_ts": len(buckets["js_ts"]),
            "docker": len(buckets["docker"]),
            "compose": len(buckets["compose"]),
            "mcp": len(buckets["mcp"]),
        },
        "counts": counts,
        "findings": [f.format_line() for f in findings],
        "details": [asdict(f) for f in findings],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static auditor for AI Agent Harnesses (16 rules AH001-AH016, Text/JSON/SARIF 2.1.0)."
    )
    parser.add_argument("project_dir", help="Path to the agent harness project directory")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 on any ERROR or WARN finding (INFO notes never fail)",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="Print findings as JSON")
    output_group.add_argument("--sarif", action="store_true", help="Print findings as SARIF 2.1.0 JSON")
    parser.add_argument(
        "--ignore-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="Additional directory name to ignore (may be passed multiple times)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(args.project_dir).resolve()
    if not root.is_dir():
        print(f"Directory not found: {root}", file=sys.stderr)
        return 2

    result = run_audit(root, ignore_dirs=set(args.ignore_dir))

    if args.json:
        print(json.dumps(result, indent=2))
    elif args.sarif:
        print(json.dumps(build_sarif_report(result), indent=2))
    else:
        sc = result["scanned"]
        counts = result["counts"]
        print(
            f"Scanned {sc['python']} Python, {sc['js_ts']} JS/TS, {sc['docker']} Dockerfile, "
            f"{sc['compose']} Compose, {sc['mcp']} MCP files in {root}"
        )
        print(
            f"Total findings: {len(result['findings'])} "
            f"(error={counts['error']}, warn={counts['warn']}, info={counts['info']})"
        )
        if result["findings"]:
            print()
            for item in result["findings"]:
                print(item)

    counts = result["counts"]
    if counts["error"] > 0:
        return 1
    if args.strict and counts["warn"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
