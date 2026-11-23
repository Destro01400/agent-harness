# Tool Contracts, Poka-Yoke ACI & Execution Pipelines

Tools are contracts between deterministic infrastructure and non-deterministic agents—not 1:1 mirrors of REST endpoints or human GUIs. Designing an ergonomic **Agent-Computer Interface (ACI)** delivers some of the largest measured gains in agent engineering (+7 to +61.6 points on identical model weights).

## Table of Contents

1. [Poka-Yoke ACI Design Rules](#1-poka-yoke-aci-design-rules)
2. [Anchored Editing: Hashline vs. Lint-Gated Range Edits](#2-anchored-editing-hashline-vs-lint-gated-range-edits)
3. [Strict JSON Schema Validation at the Model Boundary](#3-strict-json-schema-validation-at-the-model-boundary)
4. [Output Capping and `spill-policy` Disk Offloading](#4-output-capping-and-spill-policy-disk-offloading)
5. [Actionable Recovery Errors and Idempotency Keys](#5-actionable-recovery-errors-and-idempotency-keys)
6. [Ordered Pre / Bounded Concurrent Execute / Ordered Post Pipeline](#6-ordered-pre--bounded-concurrent-execute--ordered-post-pipeline)
7. [Reference Implementation (Python 3.11+ & TypeScript ESM)](#7-reference-implementation-python-311--typescript-esm)
8. [Tool Contract Checklist](#8-tool-contract-checklist)

---

## 1. Poka-Yoke ACI Design Rules

Apply *poka-yoke* (mistake-proofing) so invalid arguments and wasted turns become structurally difficult:

| Principle | Concrete Standard | Verified Evidence |
|---|---|---|
| **Consolidate workflows over CRUD** | Expose `schedule_event`, `search_logs` (with context lines), `get_customer_context` instead of `list_users` + `list_events` + `create_event`. | Vercel `d0` deleted 80% of tools (17 → 2 primitives) and jumped **80% → 100%** at **3.5× speed** and **−37% tokens**. |
| **Strict namespacing** | Prefix consistently by service and resource (`github_issues_search`, `asana_projects_get`, `fs_read`). | Prevents cross-server collisions across multi-MCP topologies and mitigates tool typosquatting (`ASI02`/`ASI04`). |
| **`response_format` enum** | Expose `response_format: "concise" \| "detailed"` (default `"concise"`). | Anthropic measured **~67% token savings** (`72` vs. `206` tokens on Slack threads). |
| **Semantic IDs over raw UUIDs** | Return human-meaningful names or 0-indexed handles instead of raw UUIDs, `256px_image_url`, or internal MIME boilerplate. | Reduces argument transcription hallucinations and saves working context. |
| **1–5 `input_examples`** | Attach 1–5 canonical JSON examples (minimal, partial, full) to complex or nested tool schemas. | JSON Schema encodes types, not conventions (`YYYY-MM-DD`, `USR-001`). Anthropic measured **+18 pp** parameter accuracy (**72% → 90%**). |
| **Absolute paths & explicit empty states** | Require absolute file paths (or explicit workspace-relative canonical paths); never return an empty string `""` when a command succeeds silently. | Anthropic eliminated post-`cd` path failures on SWE-bench; SWE-agent returns `"Command completed with no output"` so models do not assume a hang. |
| **Avoid human-GUI search patterns** | Return summarized search hits capped at ≤50 results with a `"narrow your query"` hint instead of `next`/`prev` pagination buttons. | SWE-agent ablation: IDE-style iterative search scored **12.0%**—**3.7 pts worse than having NO search tool at all (15.7%)**, while summarized search scored **18.0%**. |

---

## 2. Anchored Editing: Hashline vs. Lint-Gated Range Edits

Mechanical edit failures waste huge portions of agent budgets (in SWE-agent, cascading edit failures caused **23.4%** of unresolved trajectories; in Can Bölük's benchmark, raw `apply_patch` had **46%–51% patch failure rates** on Grok 4 and GLM-4.7). Never ask models to count diff lines before writing code or escape whole files inside JSON strings.

Two empirically validated anchored edit contracts dominate production coding harnesses:

### Option A: Hashline (`line:hash|` Content Anchors — Can Bölük / Stencil)
Every line returned by `read_file` or `grep` carries a short **2–3 hex-character** deterministic content hash truncated from `blake2b`/`blake2s` or `sha256` (e.g., 2 hex chars / 256 buckets for compact files as in [coding-agent-patterns.md](coding-agent-patterns.md), or 3 hex chars / 4,096 buckets for larger files—always keep the same hash algorithm and slice width across read and edit tools, e.g., `42:f1|  return total`). Edit operations reference `(start_anchor, end_anchor)` instead of reproducing old text or whitespace:
- **Optimistic concurrency for free:** If the file changed since reading, the hash check rejects the edit deterministically before corrupting the file.
- **Measured impact across 16 LLMs:** **+15 pts average** over `apply_patch` (wins on **14/16** models; Grok Code Fast 1 **6.7% → 68.3% (+61.6 pts / 10×, −49% tokens)**; Grok 4 Fast **−61% output tokens**).
- **Per-model caveat:** DeepSeek V3.2 regressed **−5 pts** on Hashline vs. its post-trained edit format—select the edit variant via `HarnessProfile.edit_tool_variant`.

### Option B: 100-Line Stateful Viewer + Lint-Gated Range Edit (SWE-agent)
- **Window size matters:** SWE-agent's file viewer peaked at **100 lines** (**18.0%** SWE-bench Lite), dropping to **14.3%** at 30 lines (fragmented) and **12.7%** on full files (context dilution).
- **Syntax-check-and-revert:** `edit <start>:<end>` runs a fast syntax linter (`ast.parse` / `flake8` / `tsc --noEmit`) *before* committing. On syntax error, it **atomically reverts** the file and returns the exact lint diagnostic + offending lines. Removing this single guardrail cost **−3.0 percentage points** on SWE-bench Lite.

---

## 3. Strict JSON Schema Validation at the Model Boundary

Treat every tool argument object emitted by an LLM as **untrusted external input**:

1. **Validate every call strictly before execution:** Reject missing required fields, unknown keys (`additionalProperties: false`), wrong primitive types, and out-of-range enums with an actionable recovery error (never let a `KeyError` or `TypeError` crash the loop).
2. **Respect provider strict-mode schema subsets:** When using strict structured tool calling (e.g., DeepSeek `/beta` `strict: true` or OpenAI strict schemas), enforce `additionalProperties: false`, list **all** properties in `required` (use nullable types `["string", "null"]` for optional fields), and avoid unsupported JSON Schema keywords such as `minLength`, `maxLength`, `minItems`, or `maxItems` (validate those bounds in your runtime validator instead).
3. **Never trust static types across the wire:** Validate untrusted JSON, file contents, and MCP responses at the boundary; trust static types only inside already-validated in-process seams (DeepSeek `dsh` defensive pattern).

---

## 4. Output Capping and `spill-policy` Disk Offloading

Unbounded tool outputs (`stdout`, log files, SQL result sets, raw DOM dumps) trigger immediate Context Rot and OOM crashes (`AH012`).

- **Inline hard ceiling:** Enforce a strict token/character cap per tool result (Claude Code defaults to **25,000 tokens**; smaller loops often cap at **8,000–24,000 chars**). Note UK AISI Inspect AI's subtle distinction: `read_file` enforces a 100 MB cap and raises `OutputLimitExceededError`, whereas `exec` caps streams at 10 MB via front-truncation without raising—never assume truncated stdout is valid JSON.
- **Reversible disk offloading (`spill-policy` — DeepSeek `dsh`):** When a plain-text result exceeds `max_inline_chars`:
  1. Persist the complete output to a private session artifact path (e.g., `.harness/spills/<call_id>.txt`).
  2. Return a **head + tail preview**, total byte/line counts, the exact spill file path, and a concrete retrieval hint (`"Use read_file(path=..., start_line=..., end_line=...) or grep_file to inspect sections"`).
  3. **Safe fallback:** If writing the spill file fails (disk full/permissions), return the truncated preview with a clear warning rather than dropping the turn or crashing.

---

## 5. Actionable Recovery Errors and Idempotency Keys

### Actionable Recovery Errors (Never Opaque Tracebacks)
Distinguish **expected recoverable tool errors** (validation failures, `FileNotFoundError`, non-zero exit code, timeout) from **unexpected infrastructure failures** (sandbox daemon dead, corrupt session log). Return expected errors to the model using a structured 3-part template:
1. **What failed** (canonical error code + exact offending parameter/command).
2. **Why** (concise root cause, zero noisy host stack traces).
3. **How to recover** (valid range/format, narrower query, or alternative tool).

### Idempotency Keys for Mutating Tools (AWS Builders' Library)
Whenever a network timeout or dropped connection hits a mutating tool (`create_ticket`, `send_email`, `charge_card`, `provision_vm`), retrying blindly duplicates side effects.

- **Require a caller-supplied `idempotency_key` (`client_token`)** on every side-effecting tool wrapped in retries or Programmatic Tool Calling.
- **Record atomically:** Persist `(idempotency_key, canonical_params_hash, result)` in the same transaction/atomic write as the side effect.
- **Exact replay semantics:**
  - Same key + **same parameters** → return the **semantically equivalent cached result** (never throw `AlreadyExists`, which breaks retry flows).
  - Same key + **different parameters** → fail loudly with `IDEMPOTENCY_PARAMETER_MISMATCH`.
  - Never rely on naive parameter-hash deduplication alone—it breaks legitimate duplicate creations (e.g., provisioning two identical VMs).

---

## 6. Ordered Pre / Bounded Concurrent Execute / Ordered Post Pipeline

When a model emits multiple tool calls in a single assistant turn (e.g., 4 `read_file` calls and 1 `edit_file` call), execute them using DeepSeek `dsh`'s three-phase batch pipeline:

```text
Model tool_calls [c1(ro), c2(ro), c3(write), c4(ro)]
  │
  ├─ Phase 1 — ORDERED pre-execute (in exact model order):
  │    Schema validation, ApprovalPolicy (PEP/PDP), DoomLoopGuard, path containment.
  │    Calls rejected here record immediate errors without running.
  │
  ├─ Phase 2 — BARRIER + BOUNDED CONCURRENT execute:
  │    Read-only/parallel-safe calls run concurrently under Semaphore(max_concurrency=4).
  │    Mutating/serial calls (`executionMode="serial"`) act as execution barriers:
  │    wait for prior in-flight calls to drain, run exclusively, then resume.
  │
  └─ Phase 3 — ORDERED post-execute & commit (in exact model order):
       Apply spill-policy, secret redaction, telemetry spans, and commit `tool/result`
       in exact [c1, c2, c3, c4] order (synthesizing error results for any aborted call).
```

---

## 7. Reference Implementation (Python 3.11+ & TypeScript ESM)

### Python 3.11+ — Hashline Anchors, `SpillPolicy`, Strict Validation & Batch Dispatcher

```python
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Literal


# --- 1. Hashline anchored read & edit (2-3 hex chars from blake2/sha256) ---

def line_hash(text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), digest_size=2).hexdigest()[:3]


def format_hashline_slice(content: str, start_line: int = 1, max_lines: int = 100) -> str:
    lines = content.splitlines()
    end_line = min(len(lines), start_line - 1 + max_lines)
    slice_lines = lines[start_line - 1 : end_line]
    body = "\n".join(
        f"{idx}:{line_hash(line)}|{line}"
        for idx, line in enumerate(slice_lines, start=start_line)
    )
    return f"[Lines {start_line}-{end_line} of {len(lines)}]\n{body}"


def apply_hashline_edit(
    content: str, start_anchor: str, end_anchor: str, replacement: str
) -> str:
    """Replaces inclusive line range verified by `line:hash` anchors; rejects stale edits."""
    lines = content.splitlines()
    s_num_str, s_hash = start_anchor.split(":", 1)
    e_num_str, e_hash = end_anchor.split(":", 1)
    s_idx, e_idx = int(s_num_str) - 1, int(e_num_str) - 1

    if not (0 <= s_idx <= e_idx < len(lines)):
        raise ValueError(f"Line range {start_anchor}..{end_anchor} out of bounds (1..{len(lines)}).")
    if line_hash(lines[s_idx]) != s_hash or line_hash(lines[e_idx]) != e_hash:
        raise ValueError(
            "Stale anchor mismatch: file changed since last read. "
            "Re-read the target region with `read_file` before retrying."
        )
    new_lines = lines[:s_idx] + replacement.splitlines() + lines[e_idx + 1 :]
    return "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")


# --- 2. SpillPolicy (output cap + reversible disk offloading) ---

class SpillPolicy:
    def __init__(self, spill_dir: Path, *, max_inline_chars: int = 24_000, preview_chars: int = 4_000) -> None:
        self._dir = spill_dir
        self._max_inline = max_inline_chars
        self._preview = preview_chars

    def apply(self, call_id: str, output: str) -> str:
        if not output:
            return "[OK: Command completed with no output.]"
        if len(output) <= self._max_inline:
            return output

        head = output[: self._preview]
        tail = output[-self._preview :]
        line_count = output.count("\n") + 1
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", call_id).strip(".") or "spill"
            spill_path = self._dir / f"{safe_id}.txt"
            spill_path.write_text(output, encoding="utf-8")
            locator = (
                f"Full output ({len(output)} chars, {line_count} lines) spilled to `{spill_path.as_posix()}`. "
                "Use targeted `read_file` line ranges or `grep` to inspect."
            )
        except OSError as exc:
            locator = f"Output truncated ({len(output)} chars); spill storage unavailable ({exc})."

        return f"{head}\n\n... [TRUNCATED: {locator}] ...\n\n{tail}"


# --- 3. Strict Tool Contract + Ordered-Pre / Bounded-Concurrent / Ordered-Post Dispatcher ---

@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    required_params: tuple[str, ...]
    param_types: dict[str, type]
    handler: Callable[[dict[str, Any]], Awaitable[str]]
    execution_mode: Literal["parallel", "serial"] = "parallel"
    timeout_s: float = 30.0
    idempotent: bool = False
    input_examples: tuple[dict[str, Any], ...] = ()


class ToolDispatcher:
    def __init__(self, specs: list[ToolSpec], spill: SpillPolicy, *, max_concurrency: int = 4) -> None:
        self._specs = {s.name: s for s in specs}
        self._spill = spill
        self._sem = asyncio.Semaphore(max_concurrency)
        self._idempotency_cache: dict[str, tuple[str, str]] = {}  # key -> (args_hash, result)
        self._inflight: dict[str, tuple[str, asyncio.Task[tuple[bool, str]]]] = {}  # single-flight map

    def _validate(self, spec: ToolSpec, args: dict[str, Any]) -> str | None:
        unknown = set(args) - set(spec.param_types)
        if unknown:
            return f"[SCHEMA ERROR] Unknown parameters {sorted(unknown)} for `{spec.name}`. Allowed: {sorted(spec.param_types)}."
        missing = [p for p in spec.required_params if p not in args]
        if missing:
            return f"[SCHEMA ERROR] Missing required parameters {missing} for `{spec.name}`."
        for k, v in args.items():
            expected = spec.param_types[k]
            if not isinstance(v, expected) or (expected is int and isinstance(v, bool)):
                return f"[SCHEMA ERROR] Parameter `{k}` must be {expected.__name__}, got {type(v).__name__}."
        return None

    async def execute_batch(
        self, calls: list[tuple[str, str, dict[str, Any]]]
    ) -> list[tuple[str, str]]:
        """Ordered pre-execute -> barrier/bounded concurrent execute -> ordered post-execute."""
        results: dict[str, str] = {}
        runnable: list[tuple[str, ToolSpec, dict[str, Any]]] = []

        # Phase 1: Ordered pre-execute
        for call_id, name, args in calls:
            spec = self._specs.get(name)
            if spec is None:
                results[call_id] = f"[UNKNOWN TOOL] `{name}` not found. Available: {sorted(self._specs)}."
                continue
            err = self._validate(spec, args)
            if err:
                results[call_id] = err
                continue
            runnable.append((call_id, spec, args))

        # Phase 2: Barrier + bounded concurrent execute (single-flight idempotency)
        async def _exec_handler(spec: ToolSpec, args: dict[str, Any]) -> tuple[bool, str]:
            async with self._sem:
                try:
                    raw = await asyncio.wait_for(spec.handler(args), timeout=spec.timeout_s)
                    return True, raw
                except TimeoutError:
                    return False, f"[TIMEOUT] `{spec.name}` exceeded {spec.timeout_s}s. Narrow scope or split call."
                except Exception as exc:
                    return False, f"[TOOL ERROR] `{spec.name}` failed: {exc}. Adjust arguments and retry."

        async def _run_one(cid: str, spec: ToolSpec, args: dict[str, Any]) -> tuple[str, str]:
            idem_key = args.get("idempotency_key")
            if not isinstance(idem_key, str):
                _, out = await _exec_handler(spec, args)
                return cid, out

            args_hash = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()
            if idem_key in self._idempotency_cache:
                prev_hash, prev_res = self._idempotency_cache[idem_key]
                if prev_hash != args_hash:
                    return cid, f"[IDEMPOTENCY MISMATCH] Key `{idem_key}` reused with different parameters."
                return cid, prev_res

            # Single-flight guard: collapse concurrent callers sharing the same idempotency_key.
            inflight = self._inflight.get(idem_key)
            if inflight is not None:
                inflight_hash, task = inflight
                if inflight_hash != args_hash:
                    return cid, f"[IDEMPOTENCY MISMATCH] Key `{idem_key}` reused with different parameters."
                _, out = await asyncio.shield(task)
                return cid, out

            task = asyncio.create_task(_exec_handler(spec, args))
            self._inflight[idem_key] = (args_hash, task)
            try:
                ok, out = await task
                if ok:
                    self._idempotency_cache[idem_key] = (args_hash, out)
                return cid, out
            finally:
                self._inflight.pop(idem_key, None)

        parallel_tasks: list[asyncio.Task[tuple[str, str]]] = []
        for cid, spec, args in runnable:
            if spec.execution_mode == "serial":
                if parallel_tasks:
                    for done_id, out in await asyncio.gather(*parallel_tasks):
                        results[done_id] = out
                    parallel_tasks.clear()
                done_id, out = await _run_one(cid, spec, args)
                results[done_id] = out
            else:
                parallel_tasks.append(asyncio.create_task(_run_one(cid, spec, args)))

        if parallel_tasks:
            for done_id, out in await asyncio.gather(*parallel_tasks):
                results[done_id] = out

        # Phase 3: Ordered post-execute (spill + exact model call order)
        return [(cid, self._spill.apply(cid, results[cid])) for cid, _, _ in calls]
```

### TypeScript (Strict ESM) — Hashline Anchors, `SpillPolicy` & Batch Dispatcher

```ts
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

// Keep hash algorithm & width (2-3 hex chars from blake2/sha256) identical across read and edit.
export function lineHash(line: string): string {
  return createHash("sha256").update(line, "utf8").digest("hex").slice(0, 3);
}

export function formatHashlineSlice(content: string, startLine = 1, maxLines = 100): string {
  const lines = content.split(/\r?\n/);
  const endLine = Math.min(lines.length, startLine - 1 + maxLines);
  const body = lines
    .slice(startLine - 1, endLine)
    .map((line, i) => `${startLine + i}:${lineHash(line)}|${line}`)
    .join("\n");
  return `[Lines ${startLine}-${endLine} of ${lines.length}]\n${body}`;
}

export class SpillPolicy {
  private readonly spillDir: string;
  private readonly maxInlineChars: number;
  private readonly previewChars: number;

  constructor(spillDir: string, maxInlineChars = 24_000, previewChars = 4_000) {
    this.spillDir = spillDir;
    this.maxInlineChars = maxInlineChars;
    this.previewChars = previewChars;
  }

  async apply(callId: string, output: string): Promise<string> {
    if (output.length === 0) return "[OK: Command completed with no output.]";
    if (output.length <= this.maxInlineChars) return output;

    const head = output.slice(0, this.previewChars);
    const tail = output.slice(-this.previewChars);
    const lineCount = output.split("\n").length;
    let locator: string;
    try {
      await mkdir(this.spillDir, { recursive: true });
      const safeId = callId.replace(/[^A-Za-z0-9_.-]/g, "_").replace(/^\.+|\.+$/g, "") || "spill";
      const filePath = join(this.spillDir, `${safeId}.txt`);
      await writeFile(filePath, output, "utf8");
      locator = `Full output (${output.length} chars, ${lineCount} lines) spilled to \`${filePath.replaceAll("\\", "/")}\`. Read line ranges or grep.`;
    } catch (err) {
      locator = `Output truncated (${output.length} chars); spill write failed (${String(err)}).`;
    }
    return `${head}\n\n... [TRUNCATED: ${locator}] ...\n\n${tail}`;
  }
}

export interface ToolSpec {
  readonly name: string;
  readonly executionMode: "parallel" | "serial";
  readonly timeoutMs: number;
  readonly requiredParams: readonly string[];
  readonly allowedParams: readonly string[];
  readonly handler: (args: Record<string, unknown>, signal: AbortSignal) => Promise<string>;
}

export class ToolDispatcher {
  private readonly specs = new Map<string, ToolSpec>();
  private readonly spill: SpillPolicy;
  private readonly maxConcurrency: number;

  constructor(specs: readonly ToolSpec[], spill: SpillPolicy, maxConcurrency = 4) {
    this.spill = spill;
    this.maxConcurrency = maxConcurrency;
    for (const s of specs) this.specs.set(s.name, s);
  }

  async executeBatch(
    calls: readonly { id: string; name: string; args: Record<string, unknown> }[],
  ): Promise<Array<{ id: string; content: string }>> {
    const rawResults = new Map<string, string>();
    const runnable: Array<{ id: string; spec: ToolSpec; args: Record<string, unknown> }> = [];

    // Phase 1: Ordered pre-execute validation
    for (const c of calls) {
      const spec = this.specs.get(c.name);
      if (!spec) {
        rawResults.set(c.id, `[UNKNOWN TOOL] \`${c.name}\` does not exist.`);
        continue;
      }
      const allowed = new Set(spec.allowedParams);
      const unknown = Object.keys(c.args).filter((k) => !allowed.has(k));
      const missing = spec.requiredParams.filter((k) => !(k in c.args));
      if (unknown.length > 0 || missing.length > 0) {
        rawResults.set(
          c.id,
          `[SCHEMA ERROR] \`${c.name}\` invalid args (missing=${JSON.stringify(missing)}, unknown=${JSON.stringify(unknown)}).`,
        );
        continue;
      }
      runnable.push({ id: c.id, spec, args: c.args });
    }

    // Phase 2: Barrier + bounded concurrent execute
    const runOne = async (item: { id: string; spec: ToolSpec; args: Record<string, unknown> }) => {
      try {
        const out = await item.spec.handler(item.args, AbortSignal.timeout(item.spec.timeoutMs));
        rawResults.set(item.id, out);
      } catch (err) {
        rawResults.set(item.id, `[TOOL ERROR] \`${item.spec.name}\` failed: ${String(err)}.`);
      }
    };

    const runBounded = async (batch: typeof runnable) => {
      let idx = 0;
      const workers = Array.from({ length: Math.min(this.maxConcurrency, batch.length) }, async () => {
        while (idx < batch.length) {
          const current = batch[idx++];
          if (current) await runOne(current);
        }
      });
      await Promise.all(workers);
    };

    let parallelChunk: typeof runnable = [];
    for (const item of runnable) {
      if (item.spec.executionMode === "serial") {
        if (parallelChunk.length > 0) {
          await runBounded(parallelChunk);
          parallelChunk = [];
        }
        await runOne(item);
      } else {
        parallelChunk.push(item);
      }
    }
    if (parallelChunk.length > 0) await runBounded(parallelChunk);

    // Phase 3: Ordered post-execute (spill + exact model call order)
    const ordered: Array<{ id: string; content: string }> = [];
    for (const c of calls) {
      const content = await this.spill.apply(c.id, rawResults.get(c.id) ?? "[ERROR: Missing result]");
      ordered.push({ id: c.id, content });
    }
    return ordered;
  }
}
```

---

## 8. Tool Contract Checklist

- [ ] **Workflow consolidation:** Are overlapping CRUD endpoints consolidated into fewer high-signal workflow tools (enable lazy loading via Tool Search / Code Mode past `>10` MCP tools per Anthropic guidance; `audit_harness.py` `AH013` warns past `>15` static tools)?
- [ ] **Namespacing & `input_examples`:** Are tools consistently namespaced and complex schemas paired with 1–5 canonical `input_examples`?
- [ ] **Token-efficient returns:** Do read/search tools support `response_format: "concise" | "detailed"`, semantic IDs, and summarized search caps (≤50 hits)?
- [ ] **Anchored edits:** Does file editing avoid fragile whitespace/line-count transcription (Hashline `line:hash|` or 100-line viewer + lint-gated revert selected via `HarnessProfile`)?
- [ ] **Strict boundary validation:** Are unknown keys, missing required fields, and type mismatches rejected with actionable recovery guidance before execution?
- [ ] **Output cap + `spill-policy`:** Are outputs capped inline (e.g., 25k tokens / 24k chars) with full payloads spilled to restorable files and explicit empty-output messages?
- [ ] **Idempotency keys:** Do mutating tools require atomic `idempotency_key` handling with exact replay and parameter-mismatch rejection?
- [ ] **Ordered batch semantics:** Does tool dispatch run ordered `pre-execute`, barrier-respecting bounded concurrent `execute`, and ordered `post-execute` committing every `tool_call_id`?
