# Agent Loop Lifecycle, Orthogonal Budgets & Per-Model Profiles

A reliable agent loop separates **control-plane orchestration** from **model reasoning**: deterministic code owns turn admission, streaming settlement, resource limits, doom-loop breaking, exit verification, and model-specific profile configuration.

## Table of Contents

1. [Canonical Turn and Step Lifecycle](#1-canonical-turn-and-step-lifecycle)
2. [Orthogonal Resource Budgets and Time Limits](#2-orthogonal-resource-budgets-and-time-limits)
3. [Doom-Loop Guards and Exit-Interception Verification](#3-doom-loop-guards-and-exit-interception-verification)
4. [Reasoning-Budget Phase Scheduling](#4-reasoning-budget-phase-scheduling)
5. [Declarative Per-Model `HarnessProfile`s](#5-declarative-per-model-harnessprofiles)
6. [Reference Implementation (Python 3.11+ & TypeScript ESM)](#6-reference-implementation-python-311--typescript-esm)
7. [Loop & Budget Checklist](#7-loop--budget-checklist)

---

## 1. Canonical Turn and Step Lifecycle

Production harnesses (DeepSeek `dsh`, Google ADK, LangChain DeepAgents, OpenAI Codex) separate an outer **turn** (one user request to terminal assistant reply) from inner **steps** (each `LLM inference → tool batch` cycle):

```text
turn/start (claim input + snapshot HarnessProfile)
  │
  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP LOOP (bounded by orthogonal budgets)                               │
│  1. pre_step     : check budgets BEFORE calling LLM; inject soft        │
│                    75% budget warnings or trigger compaction            │
│  2. request      : prepareCall(); commit system/user messages ONLY      │
│                    after admission; derive & freeze immutable messages  │
│  3. stream       : forward transient chunks (`partial=True` /           │
│                    `agent/assistant-stream`) to UI — NEVER mutate state │
│  4. settle       : commit durable `assistant/message` on success OR     │
│                    `assistant/attempt` on stream/network/cancel error   │
│  5. tools        : if tool_calls present -> ordered pre-execute ->      │
│                    bounded concurrent execute -> ordered post-execute;  │
│                    commit `tool/result` in model order (always emit     │
│                    missing results on failure) -> next step             │
│  6. pre_exit     : if natural stop & workspace mutated -> run           │
│                    PreCompletionChecklist verifier; reject & re-enter   │
│                    loop on failure (up to max_verify_retries)           │
└─────────────────────────────────────────────────────────────────────────┘
  │
  ▼
turn/end (emit terminal status: COMPLETED | UNVERIFIED | BUDGET_EXCEEDED | FAILED)
```

### Three Non-Negotiable Lifecycle Invariants

1. **Admission before commit:** If a run is cancelled *before* the request is admitted (`prepareCall`), commit neither `system` nor `user` messages to the durable log so the session remains cleanly resumable (DeepSeek `dsh`).
2. **Transient streams never touch durable state:** Streaming deltas carry `partial=True` (Google ADK) or flow on `agent/assistant-stream` (`dsh`). State updates and durable session writes happen **strictly once** at settlement (`assistant/message` vs. failed `assistant/attempt`).
3. **Every `tool_call` receives a matching `tool_result`:** Even if a tool throws, times out, or the batch aborts mid-way, the harness commits a structured error `tool/result` for every pending `tool_call_id` in model order. Missing IDs corrupt subsequent API requests with HTTP 400.

---

## 2. Orthogonal Resource Budgets and Time Limits

Never rely on a single `max_steps` integer. SWE-agent's trajectory telemetry proves **agents succeed quickly and fail slowly**: resolved runs finished at median **`$1.21` / 12 steps** versus **`$2.52` / 21 steps** for failures, and **93.0%** of resolved runs submitted well before hitting limits. Throwing larger blind budgets at a thrashing loop rarely rescues it.

Enforce **six orthogonal budgets** (grounded in UK AISI Inspect AI *Setting Limits* and DeepSeek `timeout-policy`):

| Budget Dimension | Exact Definition | Enforcement Rule |
|---|---|---|
| **`turn_limit`** | Top-level model inference generations (excludes transport retries, provider fallbacks, and compaction calls). | Check **before** invoking `provider.complete()` so you never pay for an extra doomed turn. |
| **`message_limit`** | Total messages appended (`user` + `assistant` + `tool`). Catches single turns spawning 40 parallel tool calls. | Check before admitting each step. |
| **`token_limit`** | Supports total tokens, **output-only** (e.g., `output:500k` — immune to growing cached input context), or cost-weighted `(input * 0.1) + output`. | Account inclusively (cached input + reasoning output); check pre-step. |
| **`cost_limit`** | Cumulative USD computed from exact served-model rates (`input`, `output`, `cache_write`, `cache_read` in `$/MTok`), respecting fallback model routing. | Fail gracefully with `BUDGET_EXCEEDED` and preserved session log. |
| **`working_limit` + `time_limit`** | **Dual time limits:** `working_limit` excludes rate-limit backoff, concurrency waits, and HITL approval pauses; **`time_limit`** is a hard wall-clock backstop. | Always pair both—background sandbox work or external tools can continue during waits. |
| **`per_tool_timeout`** | Maximum runtime for any single tool invocation (e.g., `30s`–`180s`), strictly lower than `time_limit`. | Prevents one hung shell command from draining the entire run budget. |

### Soft Budget Warnings & Scoped Subagent Limits

- **Soft budget injection (~75% utilization):** LLMs are poor at estimating elapsed wall-clock time or remaining turns (LangChain Terminal-Bench 2.0). At 75% of `turn_limit` or `time_limit`, inject a concise system/user notice (appended at the tail, never mutating the cached prefix!) telling the agent to stop exploring and transition to verification.
- **Scoped & suspendable limits:** Give subagents (`as_tool` / `handoff`) narrow child budget scopes. When a subagent hits its limit, return a structured limit-exceeded summary to the parent rather than crashing the whole run. Suspend `cost`/`token`/`turn`/`working_limit` during auxiliary safety monitors or approval classifiers while keeping the outer wall-clock `time_limit` active.

---

## 3. Doom-Loop Guards and Exit-Interception Verification

### Doom-Loop Detection (Two Complementary Counters)

Agents get stuck in two distinct loops—track both deterministically in middleware:

1. **Identical-Call Repeat Guard (`repeat-tool-reminder` — DeepSeek `dsh`):** Hash `(tool_name, stable_json(arguments))` on every call. At $N \ge 3$ identical calls (or consecutive identical error signatures), intercept or append a direct pivot reminder instructing the model to inspect its assumptions, switch tools, or report the blocker.
2. **Per-File Edit Thrash Counter (`LoopDetectionMiddleware` — LangChain Terminal-Bench 2.0):** Even when arguments vary slightly, editing the same file 5+ times without passing tests indicates local-minimum thrashing. Count edits per canonical filepath; after threshold $K$ (e.g., 5 edits), inject a strategy-reconsideration prompt asking the agent to step back and re-read the error/spec.

### Exit-Interception Verification (`PreCompletionChecklist`)

Frontier models exhibit a strong bias toward stopping on their first plausible edit and praising their own code (Anthropic, LangChain, MAST FM-3.1).

- **Mechanism:** Hook `pre_exit` whenever the model emits a natural stop (zero tool calls) *after* any state-mutating tool ran.
- **Action:** Run a deterministic verification command (test suite, linter, build, schema check, or smoke test) *outside* model self-report.
  - If verification **passes**, allow `turn/end` with `COMPLETED`.
  - If verification **fails**, block exit, append the bounded failure output + original task acceptance criteria as a new turn, and re-enter the loop.
- **Bounded retries:** Cap verification bounce-backs (e.g., `max_verify_retries = 2`). If still failing, terminate cleanly with explicit status `UNVERIFIED` rather than looping forever.

---

## 4. Reasoning-Budget Phase Scheduling

Allocating maximum reasoning effort to every single step often *lowers* benchmark scores due to timeouts and budget exhaustion. LangChain's Terminal-Bench 2.0 ablation (`gpt-5.2-codex`) measured:

| Reasoning Schedule | Terminal-Bench 2.0 Score | Failure / Efficiency Mechanism |
|---|---|---|
| Flat `xhigh` on every turn | **53.9%** | Hit task timeouts during routine file/shell execution turns. |
| Flat `high` on every turn | **63.6%** | Better latency, weaker upfront architecture and final verification. |
| **`xhigh → high → xhigh` ("Reasoning Sandwich")** | **66.5%** | Deep planning on turns 1–2, fast `high` execution in the middle, deep `xhigh` verification before exit. |

**Critical Prompt-Cache Caveat:** On Claude models, mutating top-level `output_config.effort` or legacy `budget_tokens` mid-conversation **invalidates message-level prompt cache breakpoints** (verified by Anthropic's 3-turn reproduction: `cache_read_input_tokens` drops from `3546 → 0`).

- On providers where effort changes invalidate the KV cache (Claude), lock top-level `effort` for the session and steer turn depth via **per-message steering text** (or isolate planning/verification into separate phase sessions with disk handoffs).
- On providers where per-turn reasoning effort is cache-safe (e.g., OpenAI Codex Responses API), switch effort cleanly in `pre_step` via the phase scheduler.

---

## 5. Declarative Per-Model `HarnessProfile`s

Modern models are post-trained tightly with specific harnesses (Codex with `apply_patch` and `shell_command`; Claude with XML reflection tags; DeepSeek V3.2 with its native patch/edit conventions). LangChain's τ²-bench study (Apr 2026) proved that replacing a generic one-size-fits-all harness with declarative per-model `HarnessProfile`s lifted **`GPT-5.3 Codex` by +20 pts (33% → 53%)** and **`Claude Opus 4.7` by +10 pts (43% → 53%)**. Can Bölük's 16-LLM benchmark similarly showed Hashline boosted 14/16 models (+15 pts avg) yet regressed DeepSeek V3.2 (−5 pts).

**Architectural rule:** Never scatter `if "claude" in model:` or `if "codex" in model:` branches across your loop core. Centralize all model-coupled knobs in a declarative `HarnessProfile` (YAML/JSON/dataclass) resolved once at `turn/start` (`resolve(request) -> Spec`, no hidden `?? default` fallbacks deep inside `run()`):

| Profile Field | Purpose | Example Per-Model Difference |
|---|---|---|
| `edit_tool_variant` | Selects anchored edit ACI | `hashline` (most models), `apply_patch` (Codex), `str_replace` (DeepSeek V3.2) |
| `tool_aliases` | Maps canonical tools to post-trained names | `execute → shell_command` for Codex |
| `prompt_suffix_blocks` | Model-tuned behavioral blocks (kept static!) | `<tool_result_reflection>` for Claude; parallel-batch hint for Codex |
| `reasoning_policy` | Reasoning retention & phase schedule | `echo_reasoning_content=True` (DeepSeek); `lock_effort_for_cache=True` (Claude); `xhigh-high-xhigh` (Codex) |
| `enabled_middleware` | Deletable guard toggles (Bitter Lesson) | Toggle `context_resets` or `sprint_gate` off as newer models outgrow them |

---

## 6. Reference Implementation (Python 3.11+ & TypeScript ESM)

### Python 3.11+ — Orthogonal Budgets, Doom-Loop Guard & Declarative `HarnessProfile`

```python
from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Literal


@dataclass(frozen=True, slots=True)
class ModelRates:
    input_per_mtok: float
    output_per_mtok: float
    cache_read_per_mtok: float
    cache_write_per_mtok: float = 0.0


@dataclass(frozen=True, slots=True)
class BudgetConfig:
    turn_limit: int = 30
    message_limit: int = 120
    output_token_limit: int = 100_000
    cost_limit_usd: float = 2.00
    working_limit_s: float = 300.0
    time_limit_s: float = 600.0
    per_tool_timeout_s: float = 45.0
    soft_warn_ratio: float = 0.75


@dataclass(frozen=True, slots=True)
class HarnessProfile:
    name: str
    model: str
    edit_tool_variant: Literal["hashline", "apply_patch", "range_lint", "str_replace"]
    tool_aliases: dict[str, str] = field(default_factory=dict)
    prompt_suffix: str = ""
    lock_effort_for_cache: bool = True
    default_effort: Literal["low", "medium", "high", "xhigh"] = "high"
    phase_efforts: tuple[str, str, str] = ("xhigh", "high", "xhigh")  # plan, exec, verify
    enable_pre_completion_verify: bool = True
    enable_loop_guard: bool = True
    max_verify_retries: int = 2


class BudgetTracker:
    """Enforces orthogonal turn, message, token, cost, working-time, and wall-clock limits."""

    def __init__(self, cfg: BudgetConfig, rates: ModelRates) -> None:
        self.cfg = cfg
        self.rates = rates
        self.turns = 0
        self.messages = 0
        self.output_tokens = 0
        self.cost_usd = 0.0
        self.working_s = 0.0
        self._wall_start = time.monotonic()
        self._warned = False

    def record_usage(
        self,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        cache_write_tokens: int,
        output_tokens: int,
        active_s: float,
    ) -> None:
        self.turns += 1
        self.output_tokens += output_tokens
        self.working_s += active_s
        uncached_in = max(0, input_tokens - cached_input_tokens - cache_write_tokens)
        self.cost_usd += (
            (uncached_in * self.rates.input_per_mtok)
            + (cached_input_tokens * self.rates.cache_read_per_mtok)
            + (cache_write_tokens * self.rates.cache_write_per_mtok)
            + (output_tokens * self.rates.output_per_mtok)
        ) / 1_000_000.0

    def check_pre_step(self, message_count: int) -> str | None:
        """Raises BudgetExceededError on hard cap; returns optional soft warning string."""
        self.messages = message_count
        wall_s = time.monotonic() - self._wall_start
        if self.turns >= self.cfg.turn_limit:
            raise RuntimeError(f"BUDGET_EXCEEDED: turn_limit ({self.cfg.turn_limit})")
        if self.messages >= self.cfg.message_limit:
            raise RuntimeError(f"BUDGET_EXCEEDED: message_limit ({self.cfg.message_limit})")
        if self.output_tokens >= self.cfg.output_token_limit:
            raise RuntimeError(f"BUDGET_EXCEEDED: output_token_limit ({self.cfg.output_token_limit})")
        if self.cost_usd >= self.cfg.cost_limit_usd:
            raise RuntimeError(f"BUDGET_EXCEEDED: cost_limit_usd (${self.cfg.cost_limit_usd:.2f})")
        if self.working_s >= self.cfg.working_limit_s:
            raise RuntimeError(f"BUDGET_EXCEEDED: working_limit_s ({self.cfg.working_limit_s}s)")
        if wall_s >= self.cfg.time_limit_s:
            raise RuntimeError(f"BUDGET_EXCEEDED: time_limit_s ({self.cfg.time_limit_s}s)")

        ratio = max(self.turns / self.cfg.turn_limit, wall_s / self.cfg.time_limit_s)
        if not self._warned and ratio >= self.cfg.soft_warn_ratio:
            self._warned = True
            rem_turns = self.cfg.turn_limit - self.turns
            rem_s = int(self.cfg.time_limit_s - wall_s)
            return (
                f"[BUDGET NOTICE] ~{int(ratio * 100)}% budget used "
                f"({rem_turns} turns / {rem_s}s left). Stop exploring and verify your solution."
            )
        return None


class DoomLoopGuard:
    """Combines DeepSeek `repeat-tool-reminder` with LangChain per-file edit thrash detection."""

    def __init__(self, *, repeat_threshold: int = 3, file_edit_threshold: int = 5) -> None:
        self._call_counts: Counter[str] = Counter()
        self._file_edits: Counter[str] = Counter()
        self._repeat_threshold = repeat_threshold
        self._file_edit_threshold = file_edit_threshold

    def inspect(self, tool_name: str, arguments: dict[str, Any]) -> str | None:
        sig = hashlib.sha256(
            f"{tool_name}:{json.dumps(arguments, sort_keys=True)}".encode("utf-8")
        ).hexdigest()[:16]
        self._call_counts[sig] += 1
        if self._call_counts[sig] >= self._repeat_threshold:
            return (
                f"[LOOP GUARD] Identical `{tool_name}` call repeated {self._call_counts[sig]}x. "
                "Do not repeat the same arguments; diagnose root cause or change approach."
            )

        if tool_name in {"edit_file", "apply_patch", "write_file"} and isinstance(
            arguments.get("path"), str
        ):
            target = arguments["path"]
            self._file_edits[target] += 1
            if self._file_edits[target] >= self._file_edit_threshold:
                return (
                    f"[THRASH GUARD] `{target}` edited {self._file_edits[target]} times. "
                    "Step back, re-read the failing test/spec, and reconsider your design."
                )
        return None


def select_reasoning_effort(
    profile: HarnessProfile, *, turn: int, phase: Literal["plan", "exec", "verify"]
) -> str:
    """Schedules xhigh-high-xhigh only when effort changes do not bust provider KV cache."""
    if profile.lock_effort_for_cache:
        return profile.default_effort
    plan_e, exec_e, verify_e = profile.phase_efforts
    if phase == "verify":
        return verify_e
    return plan_e if turn <= 2 else exec_e
```

### TypeScript (Strict ESM) — Orthogonal Budgets, Doom-Loop Guard & Phase Scheduler

```ts
import { createHash } from "node:crypto";

export type ReasoningEffort = "low" | "medium" | "high" | "xhigh";

export interface BudgetConfig {
  readonly turnLimit: number;
  readonly messageLimit: number;
  readonly outputTokenLimit: number;
  readonly costLimitUsd: number;
  readonly workingLimitMs: number;
  readonly timeLimitMs: number;
  readonly perToolTimeoutMs: number;
  readonly softWarnRatio: number;
}

export interface HarnessProfile {
  readonly name: string;
  readonly model: string;
  readonly editToolVariant: "hashline" | "apply_patch" | "range_lint" | "str_replace";
  readonly toolAliases: Readonly<Record<string, string>>;
  readonly promptSuffix: string;
  readonly lockEffortForCache: boolean;
  readonly defaultEffort: ReasoningEffort;
  readonly phaseEfforts: readonly [ReasoningEffort, ReasoningEffort, ReasoningEffort];
  readonly enablePreCompletionVerify: boolean;
  readonly enableLoopGuard: boolean;
  readonly maxVerifyRetries: number;
}

export class BudgetTracker {
  private turns = 0;
  private outputTokens = 0;
  private costUsd = 0;
  private workingMs = 0;
  private warned = false;
  private readonly wallStartMs = Date.now();

  constructor(
    private readonly cfg: BudgetConfig,
    private readonly rates: {
      inputPerMtok: number;
      outputPerMtok: number;
      cacheReadPerMtok: number;
      cacheWritePerMtok: number;
    },
  ) {}

  recordUsage(u: {
    inputTokens: number;
    cachedInputTokens: number;
    cacheWriteTokens: number;
    outputTokens: number;
    activeMs: number;
  }): void {
    this.turns += 1;
    this.outputTokens += u.outputTokens;
    this.workingMs += u.activeMs;
    const uncachedIn = Math.max(0, u.inputTokens - u.cachedInputTokens - u.cacheWriteTokens);
    this.costUsd +=
      (uncachedIn * this.rates.inputPerMtok +
        u.cachedInputTokens * this.rates.cacheReadPerMtok +
        u.cacheWriteTokens * this.rates.cacheWritePerMtok +
        u.outputTokens * this.rates.outputPerMtok) /
      1_000_000;
  }

  checkPreStep(messageCount: number): string | undefined {
    const wallMs = Date.now() - this.wallStartMs;
    if (this.turns >= this.cfg.turnLimit) throw new Error(`BUDGET_EXCEEDED: turnLimit (${this.cfg.turnLimit})`);
    if (messageCount >= this.cfg.messageLimit) throw new Error(`BUDGET_EXCEEDED: messageLimit (${this.cfg.messageLimit})`);
    if (this.outputTokens >= this.cfg.outputTokenLimit) throw new Error("BUDGET_EXCEEDED: outputTokenLimit");
    if (this.costUsd >= this.cfg.costLimitUsd) throw new Error(`BUDGET_EXCEEDED: costLimitUsd ($${this.cfg.costLimitUsd})`);
    if (this.workingMs >= this.cfg.workingLimitMs) throw new Error("BUDGET_EXCEEDED: workingLimitMs");
    if (wallMs >= this.cfg.timeLimitMs) throw new Error("BUDGET_EXCEEDED: timeLimitMs");

    const ratio = Math.max(this.turns / this.cfg.turnLimit, wallMs / this.cfg.timeLimitMs);
    if (!this.warned && ratio >= this.cfg.softWarnRatio) {
      this.warned = true;
      const remTurns = this.cfg.turnLimit - this.turns;
      const remSec = Math.max(0, Math.floor((this.cfg.timeLimitMs - wallMs) / 1000));
      return `[BUDGET NOTICE] ${Math.round(ratio * 100)}% budget used (${remTurns} turns / ${remSec}s left). Pivot to verification.`;
    }
    return undefined;
  }
}

export class DoomLoopGuard {
  private readonly callCounts = new Map<string, number>();
  private readonly fileEdits = new Map<string, number>();

  constructor(
    private readonly repeatThreshold = 3,
    private readonly fileEditThreshold = 5,
  ) {}

  inspect(toolName: string, args: Record<string, unknown>): string | undefined {
    const sorted = Object.keys(args)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = args[k];
        return acc;
      }, {});
    const key = createHash("sha256")
      .update(`${toolName}:${JSON.stringify(sorted)}`)
      .digest("hex")
      .slice(0, 16);
    const nextCount = (this.callCounts.get(key) ?? 0) + 1;
    this.callCounts.set(key, nextCount);
    if (nextCount >= this.repeatThreshold) {
      return `[LOOP GUARD] Identical \`${toolName}\` call repeated ${nextCount}x. Change strategy or report blocker.`;
    }

    if (
      (toolName === "edit_file" || toolName === "apply_patch" || toolName === "write_file") &&
      typeof args.path === "string"
    ) {
      const edits = (this.fileEdits.get(args.path) ?? 0) + 1;
      this.fileEdits.set(args.path, edits);
      if (edits >= this.fileEditThreshold) {
        return `[THRASH GUARD] \`${args.path}\` edited ${edits}x. Re-read the failing test/spec and step back.`;
      }
    }
    return undefined;
  }
}

export function selectReasoningEffort(
  profile: HarnessProfile,
  turn: number,
  phase: "plan" | "exec" | "verify",
): ReasoningEffort {
  if (profile.lockEffortForCache) return profile.defaultEffort;
  const [planEffort, execEffort, verifyEffort] = profile.phaseEfforts;
  if (phase === "verify") return verifyEffort;
  return turn <= 2 ? planEffort : execEffort;
}
```

---

## 7. Loop & Budget Checklist

- [ ] **Pre-step budget checks:** Are `turn_limit`, `message_limit`, `token_limit`, `cost_limit`, `working_limit`, and hard wall-clock `time_limit` checked *before* calling the LLM?
- [ ] **Per-tool timeout < run `time_limit`:** Is every subprocess/HTTP tool bounded by an explicit timeout or `AbortSignal`?
- [ ] **Atomic settlement:** Are streaming UI deltas isolated from durable commits, with failed/cancelled calls stored as `assistant/attempt`?
- [ ] **Soft budget notice:** Does the harness append a ~75% utilization warning (at the tail, never mutating the cached prefix) so the agent pivots to verification?
- [ ] **Doom-loop + file-thrash guards:** Are both identical repeated calls (`>= 3`) and per-file edit thrashing (`>= 5`) intercepted deterministically?
- [ ] **Pre-completion verification:** Does a deterministic `pre_exit` hook run tests/checks after mutations before accepting `COMPLETED`, capped by `max_verify_retries`?
- [ ] **Declarative `HarnessProfile`:** Are model-specific tool aliases, edit variants, prompt blocks, and reasoning schedules loaded from a declarative profile with zero scattered `if "model" in ...` branches?
