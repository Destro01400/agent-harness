#!/usr/bin/env python3
"""Static auditor for AI Agent Harnesses (Python, JS/TS, Docker, MCP configs).

Implements 16 high-signal, low-false-positive rules (AH001-AH016) with
Text, JSON, and SARIF 2.1.0 output formats, `--output FILE` UTF-8 export,
and per-line inline suppression (`# harness-audit: ignore AH001` or `// harness-audit: ignore ALL`).

Usage:
  python audit_harness.py PROJECT_DIR [--strict] [--json | --sarif] [--output FILE] [--ignore-dir DIR ...]
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import asdict, dataclass, field
import io
import json
from pathlib import Path
import re
import sys
import tokenize
import urllib.parse

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".agent",
    ".agents",
    ".claude",
    ".opencode",
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
JS_TS_EXTS = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}

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
            "An unbounded loop (while True / while running / while response.tool_calls) invokes an LLM "
            "or tool without a code-enforced numeric step, turn, token, cost, or deadline guard that breaks or raises."
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
        tags=("security", "command-injection", "owasp-asi05"),
    ),
    RuleMeta(
        id="AH003",
        name="DynamicCodeExecution",
        default_severity="ERROR",
        short_description="Dynamic code execution via eval(), exec(), or Function() in harness/tool code.",
        full_description=(
            "Evaluating arbitrary strings in the host harness process grants full process privileges "
            "and credential access if untrusted or model-generated input reaches the call."
        ),
        remediation=(
            "Replace eval/exec with structured parsers (json.loads, ast.literal_eval) or execute "
            "untrusted code inside an isolated ephemeral sandbox container."
        ),
        help_uri=f"{HELP_BASE}/sandboxing-and-security.md",
        tags=("security", "code-execution", "owasp-asi05"),
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
            "with network_mode: none or internal-only proxy network, or Windows Restricted Token + ACLs)."
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
        short_description="Insecure Docker/sandbox configuration (privileged, docker.sock, writable mount, unpinned tag, root user, or unisolated network).",
        full_description=(
            "Container sandboxes with privileged mode, Docker socket mounts, writable host bind mounts, "
            "unpinned tags, root user, or host/unisolated network access allow host breakout or data exfiltration."
        ),
        remediation=(
            "Pin base images by @sha256 digest, run as a non-root user, mount host directories read-only (:ro), "
            "never mount docker.sock or set privileged: true or network_mode: host, and isolate egress via "
            "network_mode: none or an internal: true network behind an allowlisting egress proxy."
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
            "or a propagated AbortSignal/timeout in JS/TS fetch and child-process calls."
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
            "Stripping reasoning_content/thinking/encrypted_content blocks breaks multi-turn thinking APIs, "
            "and casting tool outputs as role='user' causes models (e.g., DeepSeek-V3.2) to drop prior reasoning "
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
        short_description="Unpinned MCP server package (npx/uvx/@latest) or static tool catalog bloat (>15 tools).",
        full_description=(
            "Running unpinned MCP servers via npx/uvx or @latest enables rug-pull supply-chain attacks, "
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
        short_description="Blocking synchronous I/O (time.sleep, requests, httpx, subprocess.run, fs.*Sync) inside async functions.",
        full_description=(
            "Calling blocking sleep, HTTP, file, or subprocess functions directly inside an async function "
            "freezes the event loop, breaking concurrent tool dispatch, streaming, and cancellation."
        ),
        remediation=(
            "Use async equivalents (asyncio.sleep, asyncio.create_subprocess_exec, async HTTP clients, fs/promises) "
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
            "injection, temperature > 0 adds grading variance, and first-match regex parsing matches injected early verdicts."
        ),
        remediation=(
            "Wrap evaluated submissions in per-call random nonce boundaries, call the judge with "
            "temperature=0, and extract the final verdict match (re.findall(...)[-1] / matchAll)."
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
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("PEM private key header", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    (
        "Signed URL / token query param",
        re.compile(r"[?&](?:X-Amz-Signature|token|access_token|sig|api_key)=(?!(?i:\[?REDACTED\b))[^\"'\s&]{6,}"),
    ),
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


def _split_js_top_level_args(args_str: str) -> list[str]:
    """Split a JS/TS call argument list on top-level commas only."""
    parts: list[str] = []
    cur: list[str] = []
    depth_p = 0
    depth_b = 0
    depth_k = 0
    i = 0
    n = len(args_str)
    while i < n:
        nxt_i = _skip_js_string(args_str, i)
        if nxt_i > i:
            cur.append(args_str[i:nxt_i])
            i = nxt_i
            continue
        ch = args_str[i]
        if ch == "(":
            depth_p += 1
        elif ch == ")" and depth_p > 0:
            depth_p -= 1
        elif ch == "{":
            depth_b += 1
        elif ch == "}" and depth_b > 0:
            depth_b -= 1
        elif ch == "[":
            depth_k += 1
        elif ch == "]" and depth_k > 0:
            depth_k -= 1
        elif ch == "," and depth_p == 0 and depth_b == 0 and depth_k == 0:
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail or parts:
        parts.append(tail)
    return [p for p in parts if p]


def _line_of(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


# ---------------------------------------------------------------------------
# Python comment/docstring stripping & AST helpers
# ---------------------------------------------------------------------------

def _strip_python_comments_and_docstrings(raw_text: str, tree: ast.AST) -> list[str]:
    """Return 0-indexed list of lines with Python # comments and docstrings blanked out."""
    lines = raw_text.splitlines()
    if not lines:
        return []
    char_grid = [list(line) for line in lines]

    def _blank_span(srow: int, scol: int, erow: int, ecol: int) -> None:
        for row in range(max(1, srow), min(len(char_grid), erow) + 1):
            row_chars = char_grid[row - 1]
            start_c = scol if row == srow else 0
            end_c = ecol if row == erow else len(row_chars)
            for c in range(max(0, start_c), min(len(row_chars), end_c)):
                row_chars[c] = " "

    # Strip # comments via tokenize
    try:
        for tok in tokenize.generate_tokens(io.StringIO(raw_text).readline):
            if tok.type == tokenize.COMMENT:
                _blank_span(tok.start[0], tok.start[1], tok.end[0], tok.end[1])
    except tokenize.TokenError:
        pass

    # Strip docstrings (first statement of Module, ClassDef, FunctionDef, AsyncFunctionDef)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body:
                first = node.body[0]
                if (
                    isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)
                ):
                    end_l = getattr(first, "end_lineno", first.lineno) or first.lineno
                    for row in range(first.lineno, min(len(char_grid), end_l) + 1):
                        char_grid[row - 1] = [" " for _ in char_grid[row - 1]]

    return ["".join(r) for r in char_grid]


def _node_no_comment_source(no_comment_lines: list[str], node: ast.AST) -> str:
    start = getattr(node, "lineno", None)
    if start is None:
        return ""
    end = getattr(node, "end_lineno", start) or start
    return "\n".join(no_comment_lines[max(0, start - 1) : min(len(no_comment_lines), end)])


def _collect_python_imports(tree: ast.AST) -> dict[str, str]:
    """Map local imported identifiers/aliases to their canonical dotted module/symbol names."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    imports[top] = top
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                imports[local] = f"{node.module}.{alias.name}"
    return imports


def _resolve_py_name(dotted: str, py_imports: dict[str, str]) -> str:
    if not dotted:
        return ""
    parts = dotted.split(".")
    if parts[0] in py_imports:
        base = py_imports[parts[0]]
        return f"{base}.{'.'.join(parts[1:])}" if len(parts) > 1 else base
    return dotted


def _iter_assign_targets_and_value(node: ast.AST) -> list[tuple[ast.AST, ast.AST]]:
    if isinstance(node, ast.Assign):
        return [(tgt, node.value) for tgt in node.targets]
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return [(node.target, node.value)]
    return []


# ---------------------------------------------------------------------------
# Python AST auditor
# ---------------------------------------------------------------------------

LLM_OR_TOOL_CALL_RE = re.compile(
    r"(?:^|_|\.)(?:complete|chat|generate|invoke|respond|call_model|call_llm|llm_call|"
    r"create_message|execute_tool|run_tool|dispatch_tool|call_tool|tool_call|step_model|"
    r"messages\.create|responses\.create|completions\.create)$",
    re.IGNORECASE,
)

STRICT_BUDGET_TOKEN_RE = re.compile(
    r"\b(?:max_steps|max_turns|max_iterations|max_tokens|max_cost|max_attempts|"
    r"turn_limit|step_limit|time_limit|token_limit|cost_limit|budget|deadline|timeout|"
    r"remaining|exhausted|exceeded|cancel_event|cancelled|canceled|aborted|is_cancelled|stop_event)\b",
    re.IGNORECASE,
)

BUDGET_METHOD_RE = re.compile(
    r"(?:check|enforce|consume|assert|verify|ensure|within|has)_?(?:budget|turn|step|limit|deadline)|"
    r"budget\.(?:check|consume|enforce|ensure|record|assert|verify|can_continue|remaining|exhausted)",
    re.IGNORECASE,
)

COUNTER_NAME_RE = re.compile(
    r"(?:^|_)(?:step|steps|turn|turns|iter|iteration|iterations|attempt|attempts|"
    r"count|counter|elapsed|tokens|cost|calls|remaining|limit|max_[a-z0-9_]+|n|i|k)$",
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
    r"bounded|trim_output|slice_output|spill_output|head_tail|cap_text)\b",
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
JUDGE_UNSAFE_INTERP_RE = re.compile(
    r"\{\s*(?:submission|answer|response|candidate|output|agent_output)(?:\.[A-Za-z_]\w*(?:\([^)]*\))?)?\s*\}"
)
VERDICT_LABEL_RE = re.compile(r"(?:GRADE|VERDICT|SCORE)\s*:", re.IGNORECASE)
REASONING_FIELD_NAMES = frozenset({"reasoning_content", "thinking", "encrypted_content"})

NON_TOOL_ROUTER_RE = re.compile(
    r"(?:^|_)(?:router|app|blueprint|bp|api|server|http|views?|urls?|routes?|admin|cli|"
    r"subparsers?|signals?|events?|hooks?|plugins?|middleware|metrics?|codecs?|serializers?)$",
    re.IGNORECASE,
)
TOOL_REGISTRY_RECEIVER_RE = re.compile(
    r"(?:^|_)(?:tools?|tool_registry|tool_reg|tool_manager|tool_set|mcp|registry)$",
    re.IGNORECASE,
)
SCHEMA_CONFIG_HELPER_RE = re.compile(
    r"(?:^|_)(?:schema|config|settings|manifest|metadata|template|fixture|spec|definition)(?:$|_)",
    re.IGNORECASE,
)
TOOL_HANDLER_PARAM_NAMES = frozenset({"args", "arguments", "params", "tool_input", "tool_call", "payload"})

EVAL_PATH_BOUNDARY_RE = re.compile(r"(?:^|[/\\_-])(?:evals?|benchmarks?|graders?)(?:$|[/\\._-])", re.IGNORECASE)
EVAL_RUNNER_NAME_RE = re.compile(r"(?:^|[_-])(?:evals?|bench(?:marks?)?)(?:$|[._-])", re.IGNORECASE)

SUBPROCESS_EXEC_FUNCS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.call",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
    }
)
SUBPROCESS_SYNC_WAIT_FUNCS = frozenset(
    {
        "subprocess.run",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.call",
    }
)
SYNC_HTTP_FUNCS = frozenset(
    {
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
    }
)


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


def _is_raw_os_environ_expr(node: ast.AST, py_imports: dict[str, str]) -> bool:
    dn = _resolve_py_name(_dotted_name(node), py_imports)
    if dn in ("os.environ", "environ"):
        return True
    if isinstance(node, ast.Call):
        fn = _resolve_py_name(_dotted_name(node.func), py_imports)
        if fn in ("os.environ.copy", "environ.copy"):
            return True
        if fn == "dict" and len(node.args) == 1:
            arg_dn = _resolve_py_name(_dotted_name(node.args[0]), py_imports)
            if arg_dn in ("os.environ", "environ"):
                return True
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if k is None and _is_raw_os_environ_expr(v, py_imports):
                return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_raw_os_environ_expr(node.left, py_imports) or _is_raw_os_environ_expr(node.right, py_imports)
    return False


def _node_contains_volatile_call(node: ast.AST, py_imports: dict[str, str]) -> str | None:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            fn = _resolve_py_name(_dotted_name(sub.func), py_imports)
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


def _expr_is_real_budget_guard(expr: ast.AST, source: str) -> bool:
    """Return True only for a genuine numeric/budget/deadline guard (not mere `if not step.tool_calls:`)."""
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Call):
            fn = _dotted_name(sub.func)
            if BUDGET_METHOD_RE.search(fn):
                return True
        if isinstance(sub, ast.Name) and STRICT_BUDGET_TOKEN_RE.fullmatch(sub.id):
            return True
        if isinstance(sub, ast.Attribute) and STRICT_BUDGET_TOKEN_RE.fullmatch(sub.attr):
            return True
        if isinstance(sub, ast.Compare):
            has_ordering = any(isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in sub.ops)
            has_eq = any(isinstance(op, (ast.Eq, ast.NotEq)) for op in sub.ops)
            operands = [sub.left, *sub.comparators]
            operand_names = [_dotted_name(o) for o in operands]
            # Ignore comparisons on .tool_calls (e.g. len(resp.tool_calls) == 0)
            if any("tool_calls" in nm.lower() or "toolcalls" in nm.lower() for nm in operand_names):
                continue
            has_counter_or_num = any(
                (isinstance(o, ast.Constant) and isinstance(o.value, (int, float)) and not isinstance(o.value, bool))
                or any(
                    (isinstance(part, ast.Name) and (COUNTER_NAME_RE.search(part.id) or STRICT_BUDGET_TOKEN_RE.search(part.id)))
                    or (isinstance(part, ast.Attribute) and (COUNTER_NAME_RE.search(part.attr) or STRICT_BUDGET_TOKEN_RE.search(part.attr)))
                    for part in ast.walk(o)
                )
                for o in operands
            )
            if has_ordering and has_counter_or_num:
                return True
            if has_eq:
                has_named_counter = any(
                    isinstance(o, (ast.Name, ast.Attribute))
                    and (
                        COUNTER_NAME_RE.search(_dotted_name(o).split(".")[-1])
                        or STRICT_BUDGET_TOKEN_RE.search(_dotted_name(o).split(".")[-1])
                    )
                    for o in operands
                )
                if has_named_counter and has_counter_or_num:
                    return True
    test_src = ast.get_source_segment(source, expr) or ""
    if STRICT_BUDGET_TOKEN_RE.search(test_src) and not re.search(r"\btool_calls\b", test_src, re.IGNORECASE):
        return True
    return False


def _while_has_budget_guard(while_node: ast.While, source: str) -> bool:
    if _expr_is_real_budget_guard(while_node.test, source):
        return True
    for sub in ast.walk(while_node):
        if isinstance(sub, ast.Call):
            fn = _dotted_name(sub.func)
            if BUDGET_METHOD_RE.search(fn):
                return True
        if isinstance(sub, ast.If):
            if _expr_is_real_budget_guard(sub.test, source):
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
    no_comment_lines: list[str],
    py_imports: dict[str, str],
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
                    loop_code = _node_no_comment_source(no_comment_lines, node)
                    sleep_calls: list[ast.Call] = []
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            fn = _resolve_py_name(_dotted_name(sub.func), py_imports)
                            if fn in ("time.sleep", "asyncio.sleep", "sleep"):
                                sleep_calls.append(sub)
                    has_backoff = bool(BACKOFF_HINT_RE.search(loop_code))
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
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            mr_kw = _call_has_kw(sub, "max_retries")
                            if (
                                mr_kw is not None
                                and isinstance(mr_kw.value, ast.Constant)
                                and isinstance(mr_kw.value.value, int)
                                and not isinstance(mr_kw.value.value, bool)
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


def _is_thread_offload_call(fn_resolved: str) -> bool:
    return (
        fn_resolved in ("asyncio.to_thread", "to_thread", "run_in_executor")
        or fn_resolved.endswith((".to_thread", ".run_in_executor"))
    )


def _walk_async_blocking_io(
    async_fn: ast.AsyncFunctionDef,
    py_imports: dict[str, str],
    rel: str,
    suppressions: dict[int, set[str]],
    findings: list[Finding],
) -> None:
    """Inspect an async def body without descending into nested defs or offloaded lambdas."""
    # Collect local lambda variable names passed directly to to_thread / run_in_executor
    offloaded_var_names: set[str] = set()
    for sub in ast.walk(async_fn):
        if isinstance(sub, ast.Call):
            fn_r = _resolve_py_name(_dotted_name(sub.func), py_imports)
            if _is_thread_offload_call(fn_r):
                for arg in sub.args:
                    if isinstance(arg, ast.Name):
                        offloaded_var_names.add(arg.id)

    def _visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            for tgt, val in _iter_assign_targets_and_value(node):
                if isinstance(tgt, ast.Name) and tgt.id in offloaded_var_names and isinstance(val, ast.Lambda):
                    return
        if isinstance(node, ast.Call):
            fn = _resolve_py_name(_dotted_name(node.func), py_imports)
            if _is_thread_offload_call(fn):
                # Skip lambda callbacks passed to to_thread / run_in_executor (they run off the event loop)
                for arg in node.args:
                    if not isinstance(arg, ast.Lambda):
                        _visit(arg)
                for kw in node.keywords:
                    if not isinstance(kw.value, ast.Lambda):
                        _visit(kw.value)
                return

            blocking = (
                fn == "time.sleep"
                or fn in SYNC_HTTP_FUNCS
                or fn in SUBPROCESS_SYNC_WAIT_FUNCS
                or fn == "urllib.request.urlopen"
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


def _is_tool_registration_call(node: ast.Call) -> bool:
    """Return True for tool registrations while excluding web/HTTP routers (router/app/blueprint/api)."""
    fn = _dotted_name(node.func)
    if fn in ("ToolSpec", "ToolDefinition"):
        return True
    if isinstance(node.func, ast.Attribute):
        attr = node.func.attr
        if attr in ("register_tool", "add_tool"):
            return True
        if attr == "register":
            receiver = _dotted_name(node.func.value)
            leaf = receiver.split(".")[-1] if receiver else ""
            if not leaf:
                return False
            if NON_TOOL_ROUTER_RE.search(leaf):
                return False
            if TOOL_REGISTRY_RECEIVER_RE.search(leaf) or "tool" in receiver.lower():
                return True
    return False


def _collect_registered_tool_fn_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_tool_registration_call(node):
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    names.add(arg.id)
            for kw in node.keywords:
                if kw.arg in ("handler", "func", "fn", "callback", "executor") and isinstance(kw.value, ast.Name):
                    names.add(kw.value.id)
    return names


def _is_tool_handler_fn(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel: str,
    registered_tool_fns: set[str],
) -> bool:
    name_l = node.name.lower()
    if node.name in registered_tool_fns:
        return True
    for dec in node.decorator_list:
        d_target = dec.func if isinstance(dec, ast.Call) else dec
        dname = _dotted_name(d_target)
        dname_l = dname.lower()
        if dname_l in ("tool", "register_tool") or dname_l.endswith((".tool", ".register_tool")):
            return True
        if dname_l.endswith(".register"):
            recv_leaf = dname_l.rsplit(".", 1)[0].split(".")[-1]
            if not NON_TOOL_ROUTER_RE.search(recv_leaf) and (
                TOOL_REGISTRY_RECEIVER_RE.search(recv_leaf) or "tool" in dname_l
            ):
                return True

    if name_l.startswith("_"):
        return False
    if SCHEMA_CONFIG_HELPER_RE.search(name_l):
        return False
    if name_l.startswith(("tool_", "handle_", "execute_", "run_tool")):
        return True

    if "tool" in Path(rel).name.lower():
        param_names = {
            a.arg.lower()
            for a in (*node.args.args, *node.args.kwonlyargs)
            if a.arg not in ("self", "cls")
        }
        if param_names & TOOL_HANDLER_PARAM_NAMES:
            return True
    return False


def _is_raw_unbounded_output_expr(expr: ast.AST, tainted_vars: set[str]) -> str | None:
    if isinstance(expr, ast.Await):
        return _is_raw_unbounded_output_expr(expr.value, tainted_vars)
    if isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Slice):
        return None
    if isinstance(expr, ast.Name) and expr.id in tainted_vars:
        return expr.id
    if isinstance(expr, ast.Attribute) and expr.attr in ("stdout", "stderr", "text"):
        return _dotted_name(expr) or f".{expr.attr}"
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr in ("read_text", "read", "text"):
            fn = _dotted_name(expr.func) or expr.func.attr
            return f"{fn}()"
    return None


def _fn_has_length_guard_for(fn_node: ast.AST, var_name: str) -> bool:
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.If):
            for c in ast.walk(sub.test):
                if (
                    isinstance(c, ast.Call)
                    and isinstance(c.func, ast.Name)
                    and c.func.id == "len"
                    and c.args
                    and isinstance(c.args[0], ast.Name)
                    and c.args[0].id == var_name
                ):
                    return True
    return False


def _check_unbounded_tool_output_py(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    no_comment_lines: list[str],
    rel: str,
    registered_tool_fns: set[str],
    suppressions: dict[int, set[str]],
    findings: list[Finding],
) -> None:
    if not _is_tool_handler_fn(fn_node, rel, registered_tool_fns):
        return
    fn_code = _node_no_comment_source(no_comment_lines, fn_node)
    if TRUNCATION_HINT_RE.search(fn_code):
        return

    tainted: set[str] = set()

    def _scan_stmts(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                for tgt, val in _iter_assign_targets_and_value(stmt):
                    if isinstance(tgt, ast.Name):
                        if _is_raw_unbounded_output_expr(val, tainted):
                            tainted.add(tgt.id)
                        else:
                            tainted.discard(tgt.id)
            elif isinstance(stmt, ast.Return) and stmt.value is not None:
                raw_ref = _is_raw_unbounded_output_expr(stmt.value, tainted)
                if raw_ref:
                    if isinstance(stmt.value, ast.Name) and _fn_has_length_guard_for(fn_node, stmt.value.id):
                        continue
                    if not is_suppressed(suppressions, stmt.lineno, "AH012"):
                        findings.append(
                            Finding(
                                rule_id="AH012",
                                severity="WARN",
                                file=rel,
                                line=stmt.lineno,
                                message=(
                                    f"Tool handler '{fn_node.name}' returns raw unbounded output ({raw_ref}) "
                                    "without truncation or disk spilling."
                                ),
                            )
                        )
            elif isinstance(stmt, ast.If):
                _scan_stmts(stmt.body)
                _scan_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                _scan_stmts(stmt.body)
                _scan_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                _scan_stmts(stmt.body)
            elif isinstance(stmt, ast.Try):
                _scan_stmts(stmt.body)
                for h in stmt.handlers:
                    _scan_stmts(h.body)
                _scan_stmts(stmt.orelse)
                _scan_stmts(stmt.finalbody)

    _scan_stmts(fn_node.body)


def _dictcomp_strips_reasoning(node: ast.DictComp) -> str | None:
    """Return stripped field name if dict comprehension filters out reasoning_content/thinking/encrypted_content."""
    for gen in node.generators:
        for cond in gen.ifs:
            for sub in ast.walk(cond):
                if isinstance(sub, ast.Compare):
                    has_neg = any(isinstance(op, (ast.NotEq, ast.NotIn)) for op in sub.ops)
                    if not has_neg:
                        continue
                    for comp in sub.comparators:
                        if isinstance(comp, ast.Constant) and comp.value in REASONING_FIELD_NAMES:
                            return str(comp.value)
                        if isinstance(comp, (ast.Tuple, ast.Set, ast.List)):
                            for elt in comp.elts:
                                if isinstance(elt, ast.Constant) and elt.value in REASONING_FIELD_NAMES:
                                    return str(elt.value)
    return None


def audit_python_file(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []

    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))

    if is_test_path(rel):
        return findings

    try:
        tree = ast.parse(raw_text, filename=rel)
    except SyntaxError:
        return findings

    no_comment_lines = _strip_python_comments_and_docstrings(raw_text, tree)
    no_comment_text = "\n".join(no_comment_lines)
    py_imports = _collect_python_imports(tree)
    registered_tool_fns = _collect_registered_tool_fn_names(tree)

    has_real_sandbox = bool(SANDBOX_REAL_RE.search(no_comment_text))
    file_is_judge = bool(JUDGE_NAME_RE.search(rel))
    file_has_nonce = bool(NONCE_HINT_RE.search(no_comment_text))
    file_has_deferred_tools = bool(DEFERRED_TOOL_HINT_RE.search(no_comment_text))
    file_is_eval_runner = bool(EVAL_RUNNER_NAME_RE.search(Path(rel).name))
    file_has_pass_k = bool(re.search(r"\b(?:pass_at_k|pass_pow_k|pass@k|pass\^k)\b", no_comment_text))

    # Collect compiled verdict regex variables across the module (both Assign and AnnAssign)
    compiled_verdict_res: set[str] = set()
    module_raw_env_vars: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            for tgt, val in _iter_assign_targets_and_value(stmt):
                if not isinstance(tgt, ast.Name):
                    continue
                if _is_raw_os_environ_expr(val, py_imports):
                    module_raw_env_vars.add(tgt.id)
                if isinstance(val, ast.Call):
                    cfn = _resolve_py_name(_dotted_name(val.func), py_imports)
                    if cfn == "re.compile" and val.args:
                        pat_src = _node_no_comment_source(no_comment_lines, val.args[0])
                        if VERDICT_LABEL_RE.search(pat_src):
                            compiled_verdict_res.add(tgt.id)

    static_tool_count = 0
    first_tool_reg_line: int | None = None

    def _check_function_body(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        raw_env_vars: set[str] = set(module_raw_env_vars)
        local_verdict_res: set[str] = set(compiled_verdict_res)

        for sub in ast.walk(fn_node):
            if isinstance(sub, (ast.Assign, ast.AnnAssign)):
                for tgt, val in _iter_assign_targets_and_value(sub):
                    if not isinstance(tgt, ast.Name):
                        continue
                    if _is_raw_os_environ_expr(val, py_imports):
                        raw_env_vars.add(tgt.id)
                    if isinstance(val, ast.Call):
                        cfn = _resolve_py_name(_dotted_name(val.func), py_imports)
                        if cfn == "re.compile" and val.args:
                            pat_src = _node_no_comment_source(no_comment_lines, val.args[0])
                            if VERDICT_LABEL_RE.search(pat_src):
                                local_verdict_res.add(tgt.id)
            elif isinstance(sub, ast.Call):
                fn = _resolve_py_name(_dotted_name(sub.func), py_imports)
                if fn in SUBPROCESS_EXEC_FUNCS:
                    env_kw = _call_has_kw(sub, "env")
                    if (
                        env_kw is not None
                        and isinstance(env_kw.value, ast.Name)
                        and env_kw.value.id in raw_env_vars
                        and not _is_raw_os_environ_expr(env_kw.value, py_imports)
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
        _check_unbounded_tool_output_py(fn_node, no_comment_lines, rel, registered_tool_fns, suppressions, findings)

        # AH014: Blocking sync I/O inside async def
        if isinstance(fn_node, ast.AsyncFunctionDef):
            _walk_async_blocking_io(fn_node, py_imports, rel, suppressions, findings)

        # AH015: Unprotected LLM-as-a-judge inside judge function
        fn_code = _node_no_comment_source(no_comment_lines, fn_node)
        is_judge_fn = (
            file_is_judge
            or bool(JUDGE_NAME_RE.search(fn_node.name))
            or bool(JUDGE_UNSAFE_INTERP_RE.search(fn_code) and VERDICT_LABEL_RE.search(fn_code))
        )
        if is_judge_fn:
            fn_has_nonce = file_has_nonce or bool(NONCE_HINT_RE.search(fn_code))
            for sub in ast.walk(fn_node):
                if isinstance(sub, ast.Call):
                    temp_kw = _call_has_kw(sub, "temperature")
                    if (
                        temp_kw is not None
                        and isinstance(temp_kw.value, ast.Constant)
                        and isinstance(temp_kw.value.value, (int, float))
                        and not isinstance(temp_kw.value.value, bool)
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
                    cname = _resolve_py_name(_dotted_name(sub.func), py_imports)
                    if cname in ("re.search", "re.match") and sub.args:
                        pat_src = _node_no_comment_source(no_comment_lines, sub.args[0])
                        if VERDICT_LABEL_RE.search(pat_src):
                            if not is_suppressed(suppressions, sub.lineno, "AH015"):
                                findings.append(
                                    Finding(
                                        rule_id="AH015",
                                        severity="WARN",
                                        file=rel,
                                        line=sub.lineno,
                                        message=(
                                            f"Judge verdict parsed with {cname}() (first match); "
                                            "use re.findall(...)[-1] to defend against injected early verdicts."
                                        ),
                                    )
                                )
                    elif isinstance(sub.func, ast.Attribute) and sub.func.attr in ("search", "match"):
                        recv_name = _dotted_name(sub.func.value)
                        recv_leaf = recv_name.split(".")[-1] if recv_name else ""
                        if recv_leaf in local_verdict_res or re.search(
                            r"(?:verdict|grade|score)", recv_leaf, re.IGNORECASE
                        ):
                            if not is_suppressed(suppressions, sub.lineno, "AH015"):
                                findings.append(
                                    Finding(
                                        rule_id="AH015",
                                        severity="WARN",
                                        file=rel,
                                        line=sub.lineno,
                                        message=(
                                            f"Judge verdict parsed with {recv_name}.{sub.func.attr}() (first match); "
                                            "use .findall(...)[-1] to defend against injected early verdicts."
                                        ),
                                    )
                                )
                elif isinstance(sub, ast.JoinedStr) and not fn_has_nonce:
                    j_src = ast.get_source_segment(raw_text, sub) or _node_no_comment_source(no_comment_lines, sub)
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

        # AH016: Single-trial default parameter in eval runner (def run_eval(..., trials=1))
        if file_is_eval_runner and not file_has_pass_k:
            pos_args = fn_node.args.args
            pos_defaults = fn_node.args.defaults
            offset = len(pos_args) - len(pos_defaults)
            param_defaults: list[tuple[ast.arg, ast.expr | None]] = [
                (pos_args[offset + idx], d) for idx, d in enumerate(pos_defaults)
            ]
            param_defaults.extend(zip(fn_node.args.kwonlyargs, fn_node.args.kw_defaults))
            for arg_node, default_node in param_defaults:
                if (
                    arg_node.arg.lower() in ("trials", "num_trials", "trials_per_task", "k")
                    and isinstance(default_node, ast.Constant)
                    and type(default_node.value) is int
                    and default_node.value == 1
                ):
                    line_no = getattr(default_node, "lineno", fn_node.lineno)
                    if not is_suppressed(suppressions, line_no, "AH016"):
                        findings.append(
                            Finding(
                                rule_id="AH016",
                                severity="WARN",
                                file=rel,
                                line=line_no,
                                message=(
                                    f"Eval runner function '{fn_node.name}' defaults {arg_node.arg}=1 without "
                                    "pass@k/pass^k; run multiple trials (k >= 3) to capture stochastic variance."
                                ),
                            )
                        )

    # Retry loop check across file (AH009)
    _check_python_retry_loops(tree, raw_text, no_comment_lines, py_imports, rel, suppressions, findings)

    # Walk module AST
    for node in ast.walk(tree):
        # Function-level checks
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_function_body(node)
            for dec in node.decorator_list:
                d_target = dec.func if isinstance(dec, ast.Call) else dec
                dname = _dotted_name(d_target)
                dname_l = dname.lower()
                if dname_l in ("tool", "register_tool") or dname_l.endswith((".tool", ".register_tool")):
                    static_tool_count += 1
                    first_tool_reg_line = first_tool_reg_line or node.lineno
                elif dname_l.endswith(".register"):
                    recv_leaf = dname_l.rsplit(".", 1)[0].split(".")[-1]
                    if not NON_TOOL_ROUTER_RE.search(recv_leaf) and (
                        TOOL_REGISTRY_RECEIVER_RE.search(recv_leaf) or "tool" in dname_l
                    ):
                        static_tool_count += 1
                        first_tool_reg_line = first_tool_reg_line or node.lineno

        # AH001: Unbounded while loops (while True, while running, while response.tool_calls, etc.)
        elif isinstance(node, ast.While):
            if _while_calls_llm_or_tool(node) and not _while_has_budget_guard(node, raw_text):
                if not is_suppressed(suppressions, node.lineno, "AH001"):
                    findings.append(
                        Finding(
                            rule_id="AH001",
                            severity="ERROR",
                            file=rel,
                            line=node.lineno,
                            message=(
                                "Unbounded agent loop invokes model/tool without a "
                                "numeric step, turn, token, or deadline budget guard."
                            ),
                        )
                    )

        # AH002, AH003, AH005, AH007, AH010, AH011, AH013
        elif isinstance(node, ast.Call):
            raw_fn = _dotted_name(node.func)
            fn = _resolve_py_name(raw_fn, py_imports)

            # AH002: Unsafe shell execution (alias-aware)
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

            # AH003: Dynamic code execution
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

            # AH005: Direct raw os.environ (or os.environ | {...}) passed to subprocess
            if fn in SUBPROCESS_EXEC_FUNCS:
                env_kw = _call_has_kw(node, "env")
                if env_kw is not None and _is_raw_os_environ_expr(env_kw.value, py_imports):
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
            if fn in SUBPROCESS_SYNC_WAIT_FUNCS:
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
            elif fn in SYNC_HTTP_FUNCS:
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

            # AH011: Stripping reasoning_content / thinking / encrypted_content via .pop()
            if isinstance(node.func, ast.Attribute) and node.func.attr == "pop" and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and arg0.value in REASONING_FIELD_NAMES:
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

            # AH013: Tool registrations (excluding non-tool routers & avoiding double-counting registry.register(ToolSpec(...)))
            if _is_tool_registration_call(node):
                wraps_tool_spec = any(
                    isinstance(arg, ast.Call) and _dotted_name(arg.func) in ("ToolSpec", "ToolDefinition")
                    for arg in node.args
                )
                if not wraps_tool_spec:
                    static_tool_count += 1
                    first_tool_reg_line = first_tool_reg_line or node.lineno

        # AH004, AH010, AH013 (TOOLS list), AH015 (prompt templates), AH016 (hardcoded trials=1)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for tgt, val in _iter_assign_targets_and_value(node):
                if not isinstance(tgt, ast.Name):
                    continue
                tname = tgt.id

                # AH004: Blacklist sandbox illusion
                if BLACKLIST_NAME_RE.search(tname) and not has_real_sandbox:
                    val_src = ast.get_source_segment(raw_text, val) or _node_no_comment_source(no_comment_lines, val)
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
                    volatile_fn = _node_contains_volatile_call(val, py_imports)
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
                if re.search(
                    r"(?:^|_)(?:tools|tool_specs|tool_schemas|tool_definitions|tool_catalog)(?:$|_)",
                    tname.lower(),
                ):
                    if isinstance(val, (ast.List, ast.Tuple)) and len(val.elts) > 15:
                        if not file_has_deferred_tools and not is_suppressed(suppressions, node.lineno, "AH013"):
                            findings.append(
                                Finding(
                                    rule_id="AH013",
                                    severity="WARN",
                                    file=rel,
                                    line=node.lineno,
                                    message=(
                                        f"Static tool catalog '{tname}' defines {len(val.elts)} tools (>15) "
                                        "without deferred/lazy loading (defer_loading / tool_search)."
                                    ),
                                )
                            )

                # AH015: Module-level judge prompt template interpolating {submission}/{answer} without nonce
                if (file_is_judge or JUDGE_NAME_RE.search(tname)) and not file_has_nonce:
                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                        if JUDGE_UNSAFE_INTERP_RE.search(val.value):
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
                        if isinstance(val, ast.Constant) and type(val.value) is int and val.value == 1:
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
                    volatile_fn = _node_contains_volatile_call(content_node, py_imports)
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

        # AH011: Dict comprehension stripping reasoning_content / thinking / encrypted_content
        elif isinstance(node, ast.DictComp):
            stripped_key = _dictcomp_strips_reasoning(node)
            if stripped_key and not is_suppressed(suppressions, node.lineno, "AH011"):
                findings.append(
                    Finding(
                        rule_id="AH011",
                        severity="WARN",
                        file=rel,
                        line=node.lineno,
                        message=f"Dict comprehension strips '{stripped_key}' from message history, breaking multi-turn reasoning APIs.",
                    )
                )

        # AH011: del msg["reasoning_content"] / del msg["thinking"] / del msg["encrypted_content"]
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:
                if isinstance(tgt, ast.Subscript) and isinstance(tgt.slice, ast.Constant):
                    if tgt.slice.value in REASONING_FIELD_NAMES:
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

JS_STRICT_BUDGET_RE = re.compile(
    r"\b(?:maxSteps|maxTurns|maxIterations|maxTokens|maxCost|maxAttempts|"
    r"turnLimit|stepLimit|timeLimit|tokenLimit|costLimit|budget|deadline|timeout|"
    r"remaining|exhausted|exceeded|aborted|cancelled|canceled)\b",
    re.IGNORECASE,
)

JS_BUDGET_CALL_RE = re.compile(
    r"\b(?:checkBudget|enforceBudget|ensureBudget|consumeStep|consumeTurn|"
    r"budget\.(?:check|ensure|consume|enforce|record))\s*\(",
    re.IGNORECASE,
)

JS_COUNTER_COMPARE_RE = re.compile(
    r"(?:<=|>=|(?<!=)<|(?<!=)>)",
)

JS_VOLATILE_RE = re.compile(r"\b(?:Date\.now\s*\(|new\s+Date\s*\(|crypto\.randomUUID\s*\(|Math\.random\s*\()")

JS_BLOCKING_SYNC_RE = re.compile(
    r"\b(readFileSync|writeFileSync|appendFileSync|execFileSync|execSync)\s*\("
)

JS_JUDGE_UNSAFE_INTERP_RE = re.compile(
    r"\$\{\s*(?:submission|answer|response|candidate|output|agentOutput)(?:\.[A-Za-z_$][\w$]*(?:\([^)]*\))?)?\s*\}"
)


def _js_cond_is_real_budget_guard(cond: str) -> bool:
    if JS_BUDGET_CALL_RE.search(cond):
        return True
    if JS_STRICT_BUDGET_RE.search(cond) and not re.search(r"toolCalls|tool_calls", cond, re.IGNORECASE):
        return True
    if JS_COUNTER_COMPARE_RE.search(cond) and not re.search(r"toolCalls|tool_calls", cond, re.IGNORECASE):
        if re.search(
            r"\b(?:step|steps|turn|turns|iter|iteration|iterations|attempt|attempts|count|elapsed|tokens|cost|\d+)\b",
            cond,
            re.IGNORECASE,
        ):
            return True
    return False


def _js_loop_has_real_budget_guard(cond: str, body: str) -> bool:
    if _js_cond_is_real_budget_guard(cond):
        return True
    if JS_BUDGET_CALL_RE.search(body):
        return True
    for if_m in re.finditer(r"\bif\s*\(", body):
        parsed = _scan_balanced_js(body, if_m.end() - 1, "(", ")")
        if not parsed:
            continue
        if_cond, after_pos = parsed
        if not _js_cond_is_real_budget_guard(if_cond):
            continue
        rest = body[after_pos:].lstrip()
        if rest.startswith("{"):
            blk = _scan_balanced_js(rest, 0, "{", "}")
            if blk and re.search(r"\b(?:break|return|throw)\b", blk[0]):
                return True
        else:
            stmt_end = rest.find(";")
            stmt = rest[:stmt_end] if stmt_end != -1 else rest.splitlines()[0] if rest else ""
            if re.search(r"\b(?:break|return|throw)\b", stmt):
                return True
    return False


def _is_js_method_or_decl(code_only: str, match_start: int, open_paren_pos: int) -> bool:
    """Return True if `eval(...)` or `Function(...)` is a method/function declaration rather than a call."""
    # Check preceding token (e.g. `function eval(`, `async eval(`, `public eval(`)
    prefix = code_only[max(0, match_start - 40) : match_start]
    if re.search(
        r"\b(?:function|async|public|private|protected|static|override|readonly|abstract|get|set)\s+$",
        prefix,
    ):
        return True

    parsed = _scan_balanced_js(code_only, open_paren_pos, "(", ")")
    if not parsed:
        return False
    _, after_paren = parsed
    tail = code_only[after_paren:].lstrip()
    if tail.startswith("{"):
        return True
    # TypeScript return type followed by method body brace: `eval(expr: string): number {`
    # Guard against ternary `cond ? eval(a) : { ... }` by checking no `?` precedes on the same statement.
    stmt_prefix = code_only[max(0, code_only.rfind("\n", 0, match_start) + 1) : match_start]
    if "?" not in stmt_prefix and re.match(r"^:\s*[^;={}()]+?\{", tail):
        return True
    return False


def _iter_js_innermost_objects(text: str) -> list[tuple[int, str]]:
    """Yield (start_offset, inner_body) for object literals `{ ... }` across JS/TS text."""
    objects: list[tuple[int, str]] = []
    i = 0
    n = len(text)
    while i < n:
        nxt = _skip_js_string(text, i)
        if nxt > i:
            i = nxt
            continue
        if text[i] == "{":
            parsed = _scan_balanced_js(text, i, "{", "}")
            if parsed:
                body, _ = parsed
                objects.append((i, body))
        i += 1
    return objects


def audit_js_ts_file(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []
    seen_findings: set[tuple[str, int, str]] = set()

    def _emit(rule_id: str, severity: str, line: int, message: str) -> None:
        key = (rule_id, line, message)
        if key in seen_findings or is_suppressed(suppressions, line, rule_id):
            return
        seen_findings.add(key)
        findings.append(Finding(rule_id=rule_id, severity=severity, file=rel, line=line, message=message))

    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))
    if is_test_path(rel):
        return findings

    no_comments = strip_js_comments(raw_text, blank_strings=False)
    code_only = strip_js_comments(raw_text, blank_strings=True)

    has_real_sandbox = bool(SANDBOX_REAL_RE.search(no_comments))
    file_is_judge = bool(JUDGE_NAME_RE.search(rel))
    file_has_nonce = bool(NONCE_HINT_RE.search(no_comments))
    file_has_deferred = bool(DEFERRED_TOOL_HINT_RE.search(no_comments))
    file_is_eval_runner = bool(EVAL_RUNNER_NAME_RE.search(Path(rel).name))
    file_has_pass_k = bool(re.search(r"\b(?:passAtK|passPowK|pass_at_k|pass_pow_k)\b", no_comments))

    # Collect child_process imports, namespace aliases & named function aliases
    imports_cp = bool(
        re.search(
            r"""(?:from\s+["'](?:node:)?child_process["']|require\s*\(\s*["'](?:node:)?child_process["']\s*\))""",
            no_comments,
        )
    )
    cp_namespaces: set[str] = {"child_process", "childProcess", "cp", "proc", "childProc"}
    cp_named_aliases: dict[str, str] = {}
    for m in re.finditer(
        r"""import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+["'](?:node:)?child_process["']""",
        no_comments,
    ):
        cp_namespaces.add(m.group(1))
    for m in re.finditer(
        r"""import\s*\{([^}]+)\}\s*from\s+["'](?:node:)?child_process["']""",
        no_comments,
    ):
        for part in m.group(1).split(","):
            am = re.match(r"^\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*$", part)
            if am:
                orig, alias = am.group(1), am.group(2) or am.group(1)
                if orig in ("execSync", "exec", "spawnSync", "spawn", "execFileSync", "execFile"):
                    cp_named_aliases[alias] = orig
    for m in re.finditer(
        r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)""",
        no_comments,
    ):
        cp_namespaces.add(m.group(1))

    # Collect local variable declarations (balanced across multiline literals) for scope checks
    local_var_rhs: dict[str, str] = {}
    tainted_cmd_vars: set[str] = set()
    raw_env_vars_js: set[str] = set()
    first_match_verdict_res: set[str] = set()
    for m in re.finditer(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=;\n]+)?\s*=\s*",
        no_comments,
    ):
        vname = m.group(1)
        pos = m.end()
        if pos >= len(no_comments):
            continue
        ch = no_comments[pos]
        if ch in ("{", "[", "("):
            close_ch = {"{": "}", "[": "]", "(": ")"}[ch]
            bal = _scan_balanced_js(no_comments, pos, ch, close_ch)
            rhs = f"{ch}{bal[0]}{close_ch}" if bal else no_comments[pos : no_comments.find("\n", pos)]
        elif ch in ('"', "'", "`"):
            end_s = _skip_js_string(no_comments, pos)
            rhs = no_comments[pos:end_s]
        else:
            line_end = no_comments.find("\n", pos)
            semi_end = no_comments.find(";", pos)
            ends = [e for e in (line_end, semi_end) if e != -1]
            rhs = no_comments[pos : min(ends)] if ends else no_comments[pos:]
        rhs = rhs.strip()
        local_var_rhs[vname] = rhs
        if "${" in rhs or "+" in strip_js_comments(rhs, blank_strings=True):
            tainted_cmd_vars.add(vname)
        if re.search(r"\bprocess\.env\b(?!\s*\.\s*[A-Za-z_$][\w$]*)", rhs):
            raw_env_vars_js.add(vname)
        reg_m = re.match(r"^/(.+?)/([a-z]*)\b", rhs)
        if reg_m and VERDICT_LABEL_RE.search(reg_m.group(1)) and "g" not in reg_m.group(2):
            first_match_verdict_res.add(vname)

    # Collect helper function definitions mentioning timeout/signal/abort (for AH007 FP avoidance)
    timeout_helper_fns: set[str] = set()
    for fn_m in re.finditer(
        r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::[^{]+)?\{",
        no_comments,
    ):
        parsed = _scan_balanced_js(no_comments, fn_m.end() - 1, "{", "}")
        if parsed and re.search(r"\b(?:signal|AbortSignal|AbortController|timeout)\b", parsed[0], re.IGNORECASE):
            timeout_helper_fns.add(fn_m.group(1))
    for fn_m in re.finditer(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=]+)?\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^{=]+)?=>\s*\{",
        no_comments,
    ):
        parsed = _scan_balanced_js(no_comments, fn_m.end() - 1, "{", "}")
        if parsed and re.search(r"\b(?:signal|AbortSignal|AbortController|timeout)\b", parsed[0], re.IGNORECASE):
            timeout_helper_fns.add(fn_m.group(1))

    # AH001: Unbounded while loops (while (true), while (running), while (resp.toolCalls), etc.)
    for m in re.finditer(r"\bwhile\s*\(", code_only):
        cond_parsed = _scan_balanced_js(code_only, m.end() - 1, "(", ")")
        if not cond_parsed:
            continue
        cond_str, after_cond = cond_parsed
        brace_pos = after_cond
        while brace_pos < len(code_only) and code_only[brace_pos].isspace():
            brace_pos += 1
        if brace_pos >= len(code_only) or code_only[brace_pos] != "{":
            continue
        body_parsed = _scan_balanced_js(code_only, brace_pos, "{", "}")
        if not body_parsed:
            continue
        body, _ = body_parsed
        line_no = _line_of(code_only, m.start())
        if JS_LLM_TOOL_RE.search(body) and not _js_loop_has_real_budget_guard(cond_str, body):
            _emit(
                "AH001",
                "ERROR",
                line_no,
                "Unbounded agent loop invokes model/tool without a numeric step, turn, or budget guard.",
            )

    # AH002, AH005, AH007 on child_process calls (including named aliases)
    cp_fn_names = sorted({"execSync", "exec", "spawnSync", "spawn", "execFileSync", "execFile", *cp_named_aliases.keys()}, key=len, reverse=True)
    cp_call_re = re.compile(
        r"(?:(?P<obj>[A-Za-z_$][\w$]*)\s*\.\s*)?\b(?P<fn>" + "|".join(re.escape(n) for n in cp_fn_names) + r")\s*\("
    )
    for m in cp_call_re.finditer(no_comments):
        obj = m.group("obj")
        raw_fn = m.group("fn")
        fn = cp_named_aliases.get(raw_fn, raw_fn) if not obj else raw_fn
        if obj and obj not in cp_namespaces:
            continue
        if not obj and raw_fn == "exec" and not imports_cp:
            continue
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "(", ")")
        if not parsed:
            continue
        args_str, _ = parsed
        line_no = _line_of(no_comments, m.start())
        top_args = _split_js_top_level_args(args_str)

        if fn in ("exec", "execSync"):
            first_arg = top_args[0] if top_args else ""
            is_interpolated = (
                "${" in first_arg
                or "+" in strip_js_comments(first_arg, blank_strings=True)
                or (re.fullmatch(r"[A-Za-z_$][\w$]*", first_arg) is not None and first_arg in tainted_cmd_vars)
            )
            if is_interpolated:
                _emit(
                    "AH002",
                    "ERROR",
                    line_no,
                    f"Unsafe shell execution via {fn}() with interpolated/concatenated command; use execFile/spawn with argv array.",
                )
        else:
            if re.search(r"\bshell\s*:\s*(?:true|['\"][^'\"]+['\"])", args_str):
                _emit(
                    "AH002",
                    "ERROR",
                    line_no,
                    f"Unsafe shell execution via {fn}(..., {{ shell: true }}); execute argv directly with shell: false.",
                )

        # AH005: Raw process.env passed to child process
        if re.search(r"\benv\s*:\s*(?:process\.env\b|\{\s*\.\.\.process\.env\b)", args_str):
            _emit(
                "AH005",
                "ERROR",
                line_no,
                "Raw process.env passed to child process; pass an explicit allowlisted env object instead.",
            )
        else:
            env_ref_m = re.search(r"\benv\s*:\s*([A-Za-z_$][\w$]*)\b", args_str)
            if env_ref_m and env_ref_m.group(1) in raw_env_vars_js:
                _emit(
                    "AH005",
                    "ERROR",
                    line_no,
                    f"Raw process.env passed via '{env_ref_m.group(1)}' to child process; pass an explicit allowlisted env object instead.",
                )
            elif re.search(r"\{[^{}]*\benv\b\s*[,}]", args_str) and "env" in raw_env_vars_js:
                _emit(
                    "AH005",
                    "ERROR",
                    line_no,
                    "Raw process.env passed via shorthand 'env' to child process; pass an explicit allowlisted env object instead.",
                )

        # AH007: Missing timeout or AbortSignal on child_process call
        has_cp_timeout = bool(re.search(r"\b(?:timeout|signal|AbortSignal|abort)\b", args_str, re.IGNORECASE))
        if not has_cp_timeout:
            # Check if options arg references a helper/variable whose definition mentions timeout/signal/abort
            opts_arg = top_args[-1] if len(top_args) >= 2 else ""
            if re.fullmatch(r"[A-Za-z_$][\w$]*", opts_arg):
                rhs = local_var_rhs.get(opts_arg, "")
                if re.search(r"\b(?:timeout|signal|AbortSignal|abort)\b", rhs, re.IGNORECASE):
                    has_cp_timeout = True
            else:
                call_m = re.match(r"^([A-Za-z_$][\w$]*)\s*\(", opts_arg)
                if call_m and call_m.group(1) in timeout_helper_fns:
                    has_cp_timeout = True
        if not has_cp_timeout:
            _emit(
                "AH007",
                "WARN",
                line_no,
                f"{fn}() called without timeout or AbortSignal; hung child processes can stall the harness indefinitely.",
            )

    # AH003: Global eval( and (new) Function( — excluding class/object method definitions & obj.eval()
    for m in re.finditer(r"(?<!\.)(?<!\?\.)\b(?:eval|(?:new\s+)?Function)\s*\(", code_only):
        open_paren = m.end() - 1
        if _is_js_method_or_decl(code_only, m.start(), open_paren):
            continue
        line_no = _line_of(code_only, m.start())
        _emit(
            "AH003",
            "ERROR",
            line_no,
            "Dynamic code execution via eval() or Function() in harness/tool code.",
        )

    # AH004: Blacklist sandbox illusion (supports optional TS `: Type` annotation & `new Set<string>(...)`)
    if not has_real_sandbox:
        for m in re.finditer(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=;\n]+)?\s*=\s*(\[[^\]]*\]|new\s+Set\s*(?:<[^>]*>)?\s*\([^)]*\))",
            no_comments,
            re.DOTALL,
        ):
            vname, vval = m.group(1), m.group(2)
            if BLACKLIST_NAME_RE.search(vname) and SHELL_CMD_HINT_RE.search(vval):
                line_no = _line_of(no_comments, m.start())
                _emit(
                    "AH004",
                    "ERROR",
                    line_no,
                    f"Command denylist '{vname}' without OS/container sandbox is a bypassable sandbox illusion.",
                )

    # AH007: fetch() without signal / AbortSignal (aware of helperWithTimeout(...) & local vars)
    for m in re.finditer(r"(?<!\.)\bfetch\s*\(", no_comments):
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "(", ")")
        if not parsed:
            continue
        args_str, _ = parsed
        line_no = _line_of(no_comments, m.start())
        top_args = _split_js_top_level_args(args_str)
        if len(top_args) < 2:
            _emit(
                "AH007",
                "WARN",
                line_no,
                "fetch() called without AbortSignal / timeout; pass signal: AbortSignal.timeout(...).",
            )
            continue

        init_arg = top_args[1].strip()
        if re.search(r"\bsignal\b|AbortSignal", init_arg):
            continue
        if init_arg.startswith("{"):
            # Allow spread of a timeout/signal variable like { ...timeoutInit, method: "POST" }
            spread_safe = False
            for sp_m in re.finditer(r"\.\.\.\s*([A-Za-z_$][\w$]*)", init_arg):
                sp_name = sp_m.group(1)
                if re.search(r"timeout|signal|abort", sp_name, re.IGNORECASE) or re.search(
                    r"timeout|signal|abort", local_var_rhs.get(sp_name, ""), re.IGNORECASE
                ):
                    spread_safe = True
                    break
            if not spread_safe:
                _emit(
                    "AH007",
                    "WARN",
                    line_no,
                    "fetch() called without AbortSignal / timeout; pass signal: AbortSignal.timeout(...).",
                )
        else:
            # 2nd arg is a helper call or identifier: safe if its name or local definition mentions timeout/signal/abort
            if re.search(r"timeout|signal|abort", init_arg, re.IGNORECASE):
                continue
            call_m = re.match(r"^([A-Za-z_$][\w$]*)\s*\(", init_arg)
            if call_m:
                if call_m.group(1) in timeout_helper_fns:
                    continue
                _emit(
                    "AH007",
                    "WARN",
                    line_no,
                    "fetch() called without AbortSignal / timeout; pass signal: AbortSignal.timeout(...).",
                )
            elif re.fullmatch(r"[A-Za-z_$][\w$]*", init_arg):
                rhs = local_var_rhs.get(init_arg)
                if rhs is not None and rhs.startswith("{") and not re.search(
                    r"\b(?:signal|AbortSignal|timeout|abort)\b", rhs, re.IGNORECASE
                ):
                    _emit(
                        "AH007",
                        "WARN",
                        line_no,
                        "fetch() called without AbortSignal / timeout; pass signal: AbortSignal.timeout(...).",
                    )

    # AH008: Empty catch {} or messages.pop() inside catch
    for m in re.finditer(r"\bcatch\s*(?:\([^)]*\))?\s*\{", code_only):
        parsed = _scan_balanced_js(code_only, m.end() - 1, "{", "}")
        if not parsed:
            continue
        body, _ = parsed
        line_no = _line_of(code_only, m.start())
        if not body.strip():
            _emit("AH008", "WARN", line_no, "Silent empty catch block swallows harness/tool errors.")
        elif re.search(r"\b(?:messages|history|turns|conversation|events|transcript)\s*\.\s*pop\s*\(", body):
            _emit(
                "AH008",
                "WARN",
                line_no,
                "Erasing failed turn via .pop() inside catch block destroys error-recovery evidence.",
            )

    # AH009: Naive retry loop without backoff/jitter (also detects constant `await sleep(1000)`)
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
        has_delay = bool(re.search(r"\b(?:setTimeout|sleep|delay|wait)\b", body))
        has_constant_delay = bool(
            re.search(
                r"\b(?:setTimeout\s*\([^,]+,\s*\d+\s*\)|(?:sleep|delay|wait)\s*\(\s*\d+(?:\.\d+)?\s*\))",
                body,
            )
        )
        if not has_backoff and (not has_delay or has_constant_delay):
            _emit(
                "AH009",
                "WARN",
                line_no,
                "Retry loop lacks exponential backoff + jitter (constant or zero delay between attempts).",
            )

    # AH010: Prompt-cache prefix buster in JS/TS (supports `: Type`, multiline template literals, no cross-statement bleed)
    for m in re.finditer(
        r"\b(?:systemPrompt|SYSTEM_PROMPT|system_prompt|systemMessage|promptPrefix)\b(?:\s*:\s*[^=;\n]+)?\s*=\s*",
        no_comments,
    ):
        pos = m.end()
        if pos >= len(no_comments):
            continue
        ch = no_comments[pos]
        if ch in ('"', "'", "`"):
            end_s = _skip_js_string(no_comments, pos)
            rhs = no_comments[pos:end_s]
        elif ch in ("{", "(", "["):
            bal = _scan_balanced_js(no_comments, pos, ch, {"{": "}", "(": ")", "[": "]"}[ch])
            rhs = bal[0] if bal else ""
        else:
            line_end = no_comments.find("\n", pos)
            semi_end = no_comments.find(";", pos)
            ends = [e for e in (line_end, semi_end) if e != -1]
            rhs = no_comments[pos : min(ends)] if ends else no_comments[pos:]
        if JS_VOLATILE_RE.search(rhs):
            line_no = _line_of(no_comments, m.start())
            _emit(
                "AH010",
                "WARN",
                line_no,
                "Volatile timestamp/UUID inside system prompt breaks prompt KV-cache prefix invariance.",
            )

    # Scan object literals for multiline AH010 (role: 'system' + volatile) and key-order-agnostic AH011 (role: 'user' + toolResult)
    all_objs = _iter_js_innermost_objects(no_comments)
    for start_off, obj_body in all_objs:
        # Skip outer container objects that wrap another object literal containing `role:`
        if "{" in obj_body and re.search(r"\{[^{}]*\brole\s*:", obj_body):
            continue
        line_no = _line_of(no_comments, start_off)
        if re.search(r"""\brole\s*:\s*['"]system['"]""", obj_body) and JS_VOLATILE_RE.search(obj_body):
            _emit(
                "AH010",
                "WARN",
                line_no,
                "Volatile timestamp/UUID inside role: 'system' message breaks prompt KV-cache prefix invariance.",
            )
        if re.search(r"""\brole\s*:\s*['"]user['"]""", obj_body):
            content_m = re.search(r"\bcontent\s*:\s*([^,}]+)", obj_body)
            if content_m and re.search(
                r"\b(?:toolResult|tool_result|toolOutput|tool_output|toolResponse|tool_response|toolStdout)\b",
                content_m.group(1),
            ):
                _emit(
                    "AH011",
                    "WARN",
                    line_no,
                    "Tool result cast as role: 'user'; use role: 'tool' to preserve reasoning and trust boundaries.",
                )

    # AH011: delete msg.reasoning_content / delete msg["thinking"] / destructuring strip `{ thinking, ...rest } = msg`
    for m in re.finditer(
        r"""\bdelete\s+[A-Za-z_$][\w$.]*(?:\.(?:reasoning_content|thinking|encrypted_content)\b|\[\s*['"](?:reasoning_content|thinking|encrypted_content)['"]\s*\])""",
        no_comments,
    ):
        line_no = _line_of(no_comments, m.start())
        _emit(
            "AH011",
            "WARN",
            line_no,
            "Deleting reasoning_content/thinking/encrypted_content from history breaks multi-turn reasoning APIs.",
        )

    for m in re.finditer(
        r"\{[^{}]*\b(?:reasoning_content|thinking|encrypted_content)\b[^{}]*\.\.\.[A-Za-z_$][\w$]*\s*\}\s*=",
        code_only,
    ):
        line_no = _line_of(code_only, m.start())
        _emit(
            "AH011",
            "WARN",
            line_no,
            "Destructuring strips reasoning_content/thinking/encrypted_content from message history, breaking multi-turn reasoning APIs.",
        )

    # AH012: Unbounded tool output in JS/TS tool handlers (named functions + arrow functions)
    def _check_js_tool_body(fname: str, body: str, body_start_off: int) -> None:
        if TRUNCATION_HINT_RE.search(body):
            return
        # Track tainted variables in body
        tainted_js: set[str] = set()
        for am in re.finditer(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=;\n]+)?\s*=\s*([^\n;]+)",
            body,
        ):
            vname, vrhs = am.group(1), am.group(2)
            if ".slice(" in vrhs or ".substring(" in vrhs:
                continue
            if re.search(
                r"(?:[A-Za-z_$][\w$.]*\.stdout\b|readFileSync\s*\(|(?:[A-Za-z_$][\w$.]*\.)?readFile\s*\(|[A-Za-z_$][\w$.]*\.text\s*\()",
                vrhs,
            ):
                tainted_js.add(vname)

        for rm in re.finditer(r"\breturn\s+([^\n;]+)", body):
            ret_expr = rm.group(1).strip()
            if ".slice(" in ret_expr or ".substring(" in ret_expr or TRUNCATION_HINT_RE.search(ret_expr):
                continue
            is_direct_raw = bool(
                re.match(
                    r"^(?:await\s+)?(?:[A-Za-z_$][\w$.]*\.stdout\b|readFileSync\s*\(|(?:[A-Za-z_$][\w$.]*\.)?readFile\s*\(|[A-Za-z_$][\w$.]*\.text\s*\()",
                    ret_expr,
                )
            )
            is_tainted_var = bool(re.fullmatch(r"(?:await\s+)?([A-Za-z_$][\w$]*)", ret_expr)) and (
                ret_expr.split()[-1] in tainted_js
            )
            if is_direct_raw or is_tainted_var:
                line_no = _line_of(no_comments, body_start_off + rm.start())
                _emit(
                    "AH012",
                    "WARN",
                    line_no,
                    f"Tool handler '{fname}' returns raw unbounded output without truncation or disk spilling.",
                )

    for m in re.finditer(
        r"\b(?:async\s+)?function\s+((?:tool|handle|execute|runTool)[A-Za-z0-9_$]*)\s*\([^)]*\)\s*(?::[^{]+)?\{",
        no_comments,
    ):
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "{", "}")
        if parsed:
            _check_js_tool_body(m.group(1), parsed[0], m.end())

    for m in re.finditer(
        r"\b(?:const|let|var)\s+((?:tool|handle|execute|runTool)[A-Za-z0-9_$]*)(?:\s*:\s*[^=]+)?\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^{=]+)?=>\s*\{",
        no_comments,
    ):
        parsed = _scan_balanced_js(no_comments, m.end() - 1, "{", "}")
        if parsed:
            _check_js_tool_body(m.group(1), parsed[0], m.end())

    # Expression-bodied arrow function: `const toolRead = async (p: string) => fs.readFile(p, "utf8")`
    for m in re.finditer(
        r"\b(?:const|let|var)\s+((?:tool|handle|execute|runTool)[A-Za-z0-9_$]*)(?:\s*:\s*[^=]+)?\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^=]+)?=>\s*(?!\{)([^\n;]+)",
        no_comments,
    ):
        fname, expr = m.group(1), m.group(2).strip()
        if ".slice(" in expr or ".substring(" in expr or TRUNCATION_HINT_RE.search(expr):
            continue
        if re.match(
            r"^(?:await\s+)?(?:[A-Za-z_$][\w$.]*\.stdout\b|readFileSync\s*\(|(?:[A-Za-z_$][\w$.]*\.)?readFile\s*\(|[A-Za-z_$][\w$.]*\.text\s*\()",
            expr,
        ):
            line_no = _line_of(no_comments, m.start())
            _emit(
                "AH012",
                "WARN",
                line_no,
                f"Tool handler '{fname}' returns raw unbounded output without truncation or disk spilling.",
            )

    # AH013: Static tool bloat (>15 registerTool calls without deferred loading)
    reg_matches = list(re.finditer(r"\b(?:registerTool|register_tool|addTool)\s*\(", code_only))
    if len(reg_matches) > 15 and not file_has_deferred:
        line_no = _line_of(code_only, reg_matches[0].start())
        _emit(
            "AH013",
            "WARN",
            line_no,
            f"File registers {len(reg_matches)} static tools (>15) without deferred/lazy loading.",
        )

    # AH014: Blocking *Sync calls inside async functions / methods / arrows in JS/TS
    async_block_patterns = (
        re.compile(r"\basync\s+function(?:\s+[A-Za-z_$][\w$]*)?\s*\([^)]*\)\s*(?::[^{]+)?\{"),
        re.compile(r"(?<![A-Za-z0-9_$.])\basync\s+(?!function\b)[A-Za-z_$][\w$]*\s*\([^)]*\)\s*(?::[^{]+)?\{"),
        re.compile(r"\basync\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^{=]+)?=>\s*\{"),
    )
    for pat in async_block_patterns:
        for am in pat.finditer(code_only):
            parsed = _scan_balanced_js(code_only, am.end() - 1, "{", "}")
            if not parsed:
                continue
            body, _ = parsed
            for sm in JS_BLOCKING_SYNC_RE.finditer(body):
                line_no = _line_of(code_only, am.end() + sm.start())
                _emit(
                    "AH014",
                    "WARN",
                    line_no,
                    f"Blocking synchronous call '{sm.group(1)}()' inside async function; use async fs/promises or child_process equivalents.",
                )

    for am in re.finditer(
        r"\basync\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=>\s*(?!\{)([^\n;]+)",
        code_only,
    ):
        expr = am.group(1)
        for sm in JS_BLOCKING_SYNC_RE.finditer(expr):
            line_no = _line_of(code_only, am.start(1) + sm.start())
            _emit(
                "AH014",
                "WARN",
                line_no,
                f"Blocking synchronous call '{sm.group(1)}()' inside async function; use async fs/promises or child_process equivalents.",
            )

    # AH015: Unprotected LLM-as-a-judge in JS/TS (file OR any judge function/scope)
    def _audit_js_judge_scope(scope_text: str, base_offset: int) -> None:
        scope_has_nonce = file_has_nonce or bool(NONCE_HINT_RE.search(scope_text))
        if not scope_has_nonce:
            for jm in JS_JUDGE_UNSAFE_INTERP_RE.finditer(scope_text):
                line_no = _line_of(no_comments, base_offset + jm.start())
                _emit(
                    "AH015",
                    "WARN",
                    line_no,
                    "Judge prompt interpolates submission/answer without nonce boundary delimiters.",
                )
        for tm in re.finditer(r"\btemperature\s*:\s*([0-9]*\.?[0-9]+)", scope_text):
            try:
                val = float(tm.group(1))
            except ValueError:
                continue
            if val > 0:
                line_no = _line_of(no_comments, base_offset + tm.start())
                _emit(
                    "AH015",
                    "WARN",
                    line_no,
                    f"LLM judge call sets temperature: {val} (> 0); set temperature: 0.",
                )
        # First-match .match(/GRADE:.../i) without /g or VERDICT_RE.exec(...) / .match(VERDICT_RE)
        for mm in re.finditer(r"\.match\s*\(\s*/([^/\n]+)/([a-z]*)\s*\)", scope_text):
            if VERDICT_LABEL_RE.search(mm.group(1)) and "g" not in mm.group(2):
                line_no = _line_of(no_comments, base_offset + mm.start())
                _emit(
                    "AH015",
                    "WARN",
                    line_no,
                    "Judge verdict parsed with first-match .match() without /g; use matchAll() or global matches and take the last verdict.",
                )
        for mm in re.finditer(r"\.match\s*\(\s*([A-Za-z_$][\w$]*)\s*\)", scope_text):
            rname = mm.group(1)
            if rname in first_match_verdict_res or re.search(r"(?:verdict|grade|score)", rname, re.IGNORECASE):
                line_no = _line_of(no_comments, base_offset + mm.start())
                _emit(
                    "AH015",
                    "WARN",
                    line_no,
                    f"Judge verdict parsed with first-match .match({rname}); use matchAll() and take the last verdict.",
                )
        for em in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\.\s*exec\s*\(", scope_text):
            rname = em.group(1)
            if rname in first_match_verdict_res:
                line_no = _line_of(no_comments, base_offset + em.start())
                _emit(
                    "AH015",
                    "WARN",
                    line_no,
                    f"Judge verdict parsed with first-match {rname}.exec(); use matchAll() and take the last verdict.",
                )

    if file_is_judge:
        _audit_js_judge_scope(no_comments, 0)
    else:
        js_fn_patterns = (
            re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::[^{]+)?\{"),
            re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=]+)?\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::[^{=]+)?=>\s*\{"),
        )
        for pat in js_fn_patterns:
            for fm in pat.finditer(no_comments):
                fname = fm.group(1)
                parsed = _scan_balanced_js(no_comments, fm.end() - 1, "{", "}")
                if not parsed:
                    continue
                body, _ = parsed
                has_judge_signal = bool(JUDGE_NAME_RE.search(fname)) or bool(
                    VERDICT_LABEL_RE.search(body)
                    or re.search(r"\$\{\s*(?:submission|answer|candidate)\b", body)
                )
                if has_judge_signal:
                    _audit_js_judge_scope(body, fm.end())

    # AH016: Hardcoded trials = 1 (typed or untyped, var or default param) in JS/TS eval runner
    if file_is_eval_runner and not file_has_pass_k:
        for m in re.finditer(
            r"\b(?:const|let|var)\s+(?:trials|numTrials|trialsPerTask)\b(?:\s*:\s*[^=;\n]+)?\s*=\s*1\b",
            code_only,
        ):
            line_no = _line_of(code_only, m.start())
            _emit(
                "AH016",
                "WARN",
                line_no,
                "Eval runner hardcodes trials = 1 without pass@k/pass^k; use multi-trial evaluation (k >= 3).",
            )
        for m in re.finditer(
            r"(?:function\s+[A-Za-z_$][\w$]*\s*\(([^)]*)\))|(?:\(([^)]*)\)\s*(?::[^={;\n]+)?=>)|(?:\b(?:async\s+)?[A-Za-z_$][\w$]*\s*\(([^)]*)\)\s*(?::[^{]+)?\{)",
            code_only,
        ):
            params = m.group(1) or m.group(2) or m.group(3) or ""
            pm = re.search(r"\b(?:trials|numTrials|trialsPerTask)\b(?:\s*:\s*number)?\s*=\s*1\b", params)
            if pm:
                line_no = _line_of(code_only, m.start())
                _emit(
                    "AH016",
                    "WARN",
                    line_no,
                    "Eval runner defaults trials = 1 without pass@k/pass^k; use multi-trial evaluation (k >= 3).",
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

    stage_aliases: set[str] = set()
    stage_users: dict[str, tuple[str, int] | None] = {}
    current_stage_alias: str | None = None
    stage_last_user: tuple[str, int] | None = None

    for idx, line in enumerate(raw_text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(
            r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?",
            stripped,
            re.IGNORECASE,
        )
        if m:
            if current_stage_alias is not None:
                stage_users[current_stage_alias] = stage_last_user
            img = m.group(1)
            alias = m.group(2)
            current_stage_alias = alias.lower() if alias else None
            from_stage_alias = img.lower() in stage_aliases
            # Inherit USER if building from a prior named stage
            stage_last_user = stage_users.get(img.lower()) if from_stage_alias else None
            if alias:
                stage_aliases.add(alias.lower())
            if img.lower() == "scratch" or from_stage_alias or img.startswith("$"):
                continue
            if "@sha256:" not in img:
                if not is_suppressed(suppressions, idx, "AH006"):
                    if img.endswith(":latest") or ":" not in img:
                        msg = f"Dockerfile uses mutable/implicit ':latest' tag ('{img}') without @sha256 digest pin."
                    else:
                        msg = f"Dockerfile base image '{img}' is not pinned by @sha256 digest."
                    findings.append(
                        Finding(
                            rule_id="AH006",
                            severity="ERROR",
                            file=rel,
                            line=idx,
                            message=msg,
                        )
                    )
            continue

        um = re.match(r"^USER\s+(\S+)", stripped, re.IGNORECASE)
        if um:
            stage_last_user = (um.group(1), idx)

    if stage_last_user is not None:
        user_spec, user_line = stage_last_user
        user_part = user_spec.split(":", 1)[0].strip().lower()
        if user_part in ("root", "0"):
            if not is_suppressed(suppressions, user_line, "AH006"):
                findings.append(
                    Finding(
                        rule_id="AH006",
                        severity="ERROR",
                        file=rel,
                        line=user_line,
                        message=f"Dockerfile sets 'USER {user_spec}', running container as root; switch to a non-root user/UID.",
                    )
                )
    return findings


@dataclass
class _ComposeService:
    name: str
    line: int
    network_mode: str | None = None
    networks: list[str] = field(default_factory=list)
    flagged_host_net: bool = False


def audit_compose_file(f: Path, root: Path) -> list[Finding]:
    rel = f.relative_to(root).as_posix()
    raw_text = f.read_text(encoding="utf-8", errors="replace")
    suppressions = parse_suppressions(raw_text)
    findings: list[Finding] = []

    findings.extend(scan_hardcoded_secrets(raw_text, rel, suppressions))

    lines = raw_text.splitlines()

    section: str | None = None  # "services" | "networks" | other
    service_indent: int | None = None
    current_service: _ComposeService | None = None
    services: list[_ComposeService] = []

    net_indent: int | None = None
    current_net_name: str | None = None
    internal_networks: set[str] = set()

    in_volumes = False
    volumes_indent = -1
    in_svc_networks = False
    svc_networks_indent = -1

    for idx, raw_line in enumerate(lines, 1):
        line = re.sub(r"\s+#.*$", "", raw_line)
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))

        # Top-level section transition (indent == 0)
        if indent == 0:
            in_volumes = False
            in_svc_networks = False
            current_service = None
            current_net_name = None
            if re.match(r"^services\s*:", stripped):
                section = "services"
            elif re.match(r"^networks\s*:", stripped):
                section = "networks"
            else:
                section = "other"
            continue

        # Parse top-level networks section for `internal: true`
        if section == "networks":
            if net_indent is None or indent <= net_indent:
                net_m = re.match(r"^([A-Za-z0-9_.-]+)\s*:", stripped)
                if net_m:
                    net_indent = indent
                    current_net_name = net_m.group(1)
            elif current_net_name is not None:
                if re.match(r"^internal\s*:\s*true\b", stripped, re.IGNORECASE):
                    internal_networks.add(current_net_name)
            continue

        if section != "services":
            continue

        # Service declaration inside `services:`
        if service_indent is None or indent <= service_indent:
            svc_m = re.match(r"^([A-Za-z0-9_.-]+)\s*:", stripped)
            if svc_m:
                service_indent = indent
                current_service = _ComposeService(name=svc_m.group(1), line=idx)
                services.append(current_service)
                in_volumes = False
                in_svc_networks = False
                continue

        if current_service is None:
            continue

        # Track exit from sub-blocks
        if in_volumes and indent <= volumes_indent and not stripped.startswith("-"):
            in_volumes = False
        if in_svc_networks and indent <= svc_networks_indent and not stripped.startswith("-"):
            in_svc_networks = False

        if in_svc_networks:
            if stripped.startswith("-"):
                net_ref = stripped.lstrip("-").strip().strip("'\"")
                if net_ref:
                    current_service.networks.append(net_ref)
            else:
                net_key_m = re.match(r"^([A-Za-z0-9_.-]+)\s*:", stripped)
                if net_key_m and indent > svc_networks_indent:
                    # Only record immediate child keys under `networks:`
                    if indent <= svc_networks_indent + 4:
                        current_service.networks.append(net_key_m.group(1))
            continue

        # Check per-service attributes
        nm_m = re.match(r"^network_mode\s*:\s*['\"]?([^\s'\"]+)['\"]?", stripped, re.IGNORECASE)
        if nm_m:
            mode_val = nm_m.group(1).lower()
            current_service.network_mode = mode_val
            if mode_val == "host":
                current_service.flagged_host_net = True
                if not is_suppressed(suppressions, idx, "AH006"):
                    findings.append(
                        Finding(
                            rule_id="AH006",
                            severity="ERROR",
                            file=rel,
                            line=idx,
                            message=(
                                f"Compose service '{current_service.name}' sets 'network_mode: host', "
                                "exposing host network stack and local services."
                            ),
                        )
                    )
            continue

        if re.match(r"^networks\s*:\s*\[([^\]]+)\]", stripped):
            arr_m = re.match(r"^networks\s*:\s*\[([^\]]+)\]", stripped)
            if arr_m:
                for tok in arr_m.group(1).split(","):
                    cleaned = tok.strip().strip("'\"")
                    if cleaned:
                        current_service.networks.append(cleaned)
            continue
        if re.match(r"^networks\s*:", stripped):
            in_svc_networks = True
            svc_networks_indent = indent
            continue

        if re.match(r"^privileged\s*:\s*true\b", stripped, re.IGNORECASE):
            if not is_suppressed(suppressions, idx, "AH006"):
                findings.append(
                    Finding(
                        rule_id="AH006",
                        severity="ERROR",
                        file=rel,
                        line=idx,
                        message=f"Compose service '{current_service.name}' sets 'privileged: true', breaking container sandbox isolation.",
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
                        message=f"Compose service '{current_service.name}' mounts docker.sock into container, granting host root equivalence.",
                    )
                )

        usr_m = re.match(r"^user\s*:\s*['\"]?([^\s'\"]+)['\"]?", stripped, re.IGNORECASE)
        if usr_m:
            u_part = usr_m.group(1).split(":", 1)[0].strip().lower()
            if u_part in ("root", "0"):
                if not is_suppressed(suppressions, idx, "AH006"):
                    findings.append(
                        Finding(
                            rule_id="AH006",
                            severity="ERROR",
                            file=rel,
                            line=idx,
                            message=f"Compose service '{current_service.name}' runs as root ('user: {usr_m.group(1)}'); set a non-root UID.",
                        )
                    )

        img_m = re.match(r"^image\s*:\s*['\"]?([^\s'\"]+)['\"]?", stripped)
        if img_m:
            img = img_m.group(1)
            if "@sha256:" not in img and (img.endswith(":latest") or ":" not in img):
                if not is_suppressed(suppressions, idx, "AH006"):
                    findings.append(
                        Finding(
                            rule_id="AH006",
                            severity="ERROR",
                            file=rel,
                            line=idx,
                            message=f"Compose image '{img}' in service '{current_service.name}' uses mutable ':latest' tag without @sha256 digest pin.",
                        )
                    )

        if re.match(r"^volumes\s*:", stripped):
            in_volumes = True
            volumes_indent = indent
            continue

        if in_volumes and stripped.startswith("-"):
            mount = stripped.lstrip("-").strip().strip("'\"")
            if "docker.sock" not in mount:
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
                                    message=f"Writable host bind mount '{mount}' in compose service '{current_service.name}'; mount read-only (:ro).",
                                )
                            )

    # Per-service network isolation check (supports Dual-Boundary egress proxy pattern)
    for svc in services:
        if svc.flagged_host_net:
            continue
        if svc.network_mode == "none":
            continue
        if svc.networks and all(n in internal_networks for n in svc.networks):
            continue
        # Dual-Boundary egress proxy sidecar attached to an internal: true network
        if (
            internal_networks
            and any(n in internal_networks for n in svc.networks)
            and re.search(r"(?:proxy|egress|gateway|firewall)", svc.name, re.IGNORECASE)
        ):
            continue
        if not (is_suppressed(suppressions, svc.line, "AH006") or is_suppressed(suppressions, 1, "AH006")):
            findings.append(
                Finding(
                    rule_id="AH006",
                    severity="ERROR",
                    file=rel,
                    line=svc.line,
                    message=(
                        f"Compose service '{svc.name}' missing network isolation ('network_mode: none' or "
                        "internal-only network); isolate egress or route via an allowlisting proxy."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# MCP JSON config auditor (AH005 + AH013)
# ---------------------------------------------------------------------------

NPX_VALUE_FLAGS = frozenset(
    {"--cache", "--prefix", "--userconfig", "--registry", "--node-options", "-c", "--call"}
)
NPX_PKG_FLAGS = frozenset({"-p", "--package"})
NPX_BOOL_FLAGS = frozenset({"-y", "--yes", "-q", "--quiet", "--no", "--no-install", "--offline", "--prefer-offline"})

UVX_VALUE_FLAGS = frozenset(
    {"--python", "-p", "--index-url", "--extra-index-url", "--cache-dir", "--config-file", "--directory", "--with", "--with-editable"}
)
UVX_PKG_FLAGS = frozenset({"--from"})
UVX_BOOL_FLAGS = frozenset({"-q", "--quiet", "-v", "--verbose", "--offline", "--refresh", "--isolated", "--no-cache"})


def _is_pinned_npm_pkg(arg: str) -> bool:
    if arg.startswith("@"):
        if "/" not in arg:
            return False
        after_slash = arg.split("/", 1)[1]
        return bool(re.search(r"@\d+\.\d+", after_slash))
    return bool(re.search(r"@\d+\.\d+", arg))


def _is_pinned_python_pkg(arg: str) -> bool:
    if re.search(r"==\s*\d", arg):
        return True
    if re.search(r"@\d+\.\d+", arg):
        return True
    if re.search(r"@git\+.*@[0-9a-fA-F]{7,}", arg):
        return True
    return False


def _extract_mcp_package_spec(
    str_args: list[str],
    pkg_flags: frozenset[str],
    value_flags: frozenset[str],
    bool_flags: frozenset[str],
) -> str | None:
    """Skip --flag value pairs cleanly and extract the MCP package spec."""
    i = 0
    n = len(str_args)
    while i < n:
        tok = str_args[i]
        if tok == "--":
            return str_args[i + 1] if i + 1 < n else None
        if tok.startswith("-"):
            if "=" in tok:
                flag_name, flag_val = tok.split("=", 1)
                if flag_name in pkg_flags and flag_val:
                    return flag_val
                i += 1
                continue
            if tok in pkg_flags:
                return str_args[i + 1] if i + 1 < n else None
            if tok in value_flags:
                i += 2
                continue
            if tok in bool_flags:
                i += 1
                continue
            # Unknown --long-flag followed by a value when another positional package follows
            if tok.startswith("--") and i + 2 < n and not str_args[i + 1].startswith("-"):
                i += 2
                continue
            i += 1
            continue
        return tok
    return None


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

        cmd_base = Path(cmd).name.lower()
        if cmd_base in ("npx", "npx.cmd"):
            pkg = _extract_mcp_package_spec(str_args, NPX_PKG_FLAGS, NPX_VALUE_FLAGS, NPX_BOOL_FLAGS)
            if pkg and not _is_pinned_npm_pkg(pkg):
                line_no = _find_line(pkg)
                if not is_suppressed(suppressions, line_no, "AH013"):
                    findings.append(
                        Finding(
                            rule_id="AH013",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message=(
                                f"MCP server '{srv_name}' runs unpinned 'npx {pkg}'; "
                                "pin an explicit version (e.g., pkg@1.2.3) to mitigate rug-pull updates."
                            ),
                        )
                    )
        elif cmd_base in ("uvx", "uvx.exe"):
            pkg = _extract_mcp_package_spec(str_args, UVX_PKG_FLAGS, UVX_VALUE_FLAGS, UVX_BOOL_FLAGS)
            if pkg and not _is_pinned_python_pkg(pkg):
                line_no = _find_line(pkg)
                if not is_suppressed(suppressions, line_no, "AH013"):
                    findings.append(
                        Finding(
                            rule_id="AH013",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message=(
                                f"MCP server '{srv_name}' runs unpinned 'uvx {pkg}'; "
                                "pin an explicit version (e.g., pkg==1.2.3) to mitigate rug-pull updates."
                            ),
                        )
                    )
        elif cmd_base in ("uv", "uv.exe") and len(str_args) >= 3 and str_args[0] == "tool" and str_args[1] == "run":
            pkg = _extract_mcp_package_spec(str_args[2:], UVX_PKG_FLAGS, UVX_VALUE_FLAGS, UVX_BOOL_FLAGS)
            if pkg and not _is_pinned_python_pkg(pkg):
                line_no = _find_line(pkg)
                if not is_suppressed(suppressions, line_no, "AH013"):
                    findings.append(
                        Finding(
                            rule_id="AH013",
                            severity="WARN",
                            file=rel,
                            line=line_no,
                            message=(
                                f"MCP server '{srv_name}' runs unpinned 'uv tool run {pkg}'; "
                                "pin an explicit version (e.g., pkg==1.2.3) to mitigate rug-pull updates."
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
        if EVAL_PATH_BOUNDARY_RE.search(rel_l):
            return True
    return False


# ---------------------------------------------------------------------------
# SARIF 2.1.0 & audit runner
# ---------------------------------------------------------------------------

def _encode_sarif_uri(rel_path: str) -> str:
    rel_posix = rel_path.replace("\\", "/")
    return urllib.parse.quote(rel_posix, safe="/:")


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
    primary_file = result.get("primary_file")
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

        sarif_entry: dict[str, object] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {"text": message_text},
        }

        if isinstance(file_rel, str) and file_rel:
            uri = _encode_sarif_uri(file_rel)
            start_line = int(line_raw) if isinstance(line_raw, int) and line_raw >= 1 else 1
            sarif_entry["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": start_line},
                    }
                }
            ]
        elif isinstance(primary_file, str) and primary_file:
            # Project-level finding (e.g. AH016): anchor to first scanned code file, never directory "."
            uri = _encode_sarif_uri(primary_file)
            sarif_entry["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1},
                    }
                }
            ]

        sarif_results.append(sarif_entry)

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

    code_rels = sorted(
        p.relative_to(root).as_posix() for p in (*buckets["python"], *buckets["js_ts"])
    )
    non_test_code = [r for r in code_rels if not is_test_path(r)]
    primary_file: str | None = non_test_code[0] if non_test_code else (code_rels[0] if code_rels else None)

    if len(code_rels) > 0 and not _project_has_eval_suite(root, buckets["all"]):
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
        "primary_file": primary_file,
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


def _format_text_report(result: dict[str, object], root: Path) -> str:
    sc = result["scanned"]
    counts = result["counts"]
    lines = [
        (
            f"Scanned {sc['python']} Python, {sc['js_ts']} JS/TS, {sc['docker']} Dockerfile, "
            f"{sc['compose']} Compose, {sc['mcp']} MCP files in {root}"
        ),
        (
            f"Total findings: {len(result['findings'])} "
            f"(error={counts['error']}, warn={counts['warn']}, info={counts['info']})"
        ),
    ]
    if result["findings"]:
        lines.append("")
        lines.extend(result["findings"])
    return "\n".join(lines)


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
        "--output",
        metavar="FILE",
        default=None,
        help="Write Text/JSON/SARIF output directly to FILE in UTF-8 without BOM",
    )
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
        rendered = json.dumps(result, indent=2)
    elif args.sarif:
        rendered = json.dumps(build_sarif_report(result), indent=2)
    else:
        rendered = _format_text_report(result, root)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    else:
        print(rendered)

    counts = result["counts"]
    if counts["error"] > 0:
        return 1
    if args.strict and counts["warn"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
