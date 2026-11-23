# Resilience, Retries, Cancellation, and Streaming Protocols

> **Core Principle:** Retries are selfish—done naively across multiple layers, they convert minor latency blips into sustained $3^5 = 243\times$ outage storms. Enforce timeouts everywhere, retry at **one layer** with jitter and a retry budget, keep actionable errors in context, and propagate cancellation cleanly down to every subprocess and container.

## Table of Contents

1. [Connect & Read Timeouts Sized from p99.9](#1-connect--read-timeouts-sized-from-p999)
2. [Capped Exponential Backoff + Full/Decorrelated Jitter](#2-capped-exponential-backoff--fulldecorrelated-jitter)
3. [Single-Layer Retry Rule & Token-Bucket Retry Budgets](#3-single-layer-retry-rule--token-bucket-retry-budgets)
4. [Retryable vs. Non-Retryable Failure Classification](#4-retryable-vs-non-retryable-failure-classification)
5. [Idempotency Keys (`ClientToken`) for Side-Effecting Tools](#5-idempotency-keys-clienttoken-for-side-effecting-tools)
6. [Keep the Wrong Stuff In (Never Swallow or Erase Errors)](#6-keep-the-wrong-stuff-in-never-swallow-or-erase-errors)
7. [Graceful Cancellation & Container Cleanup](#7-graceful-cancellation--container-cleanup)
8. [Thread-Pool Offloading for Blocking Sync I/O on Async Loops](#8-thread-pool-offloading-for-blocking-sync-io-on-async-loops)
9. [Typed Harness Streaming Event Protocol](#9-typed-harness-streaming-event-protocol)
10. [Verification Checklist](#10-verification-checklist)

---

## 1. Connect & Read Timeouts Sized from p99.9

Every HTTP client, LLM SDK call, MCP RPC, and subprocess execution **must** carry explicit timeouts (`AH007`). Following the AWS Builders' Library (*Timeouts, retries, and backoff with jitter*):

- **Separate connect timeout from read/idle timeout:** Fast-fail unreachable hosts (e.g., `connect=5s`), while allowing streaming LLM responses a generous **per-chunk read/idle timeout** (e.g., `read=60s`) plus an outer hard step deadline.
- **Size from downstream p99.9 + TLS/handshake padding:**
  - *Too high / infinite:* Leaks sockets, file descriptors, memory, and worker slots until the harness crashes.
  - *Too low (false-timeout cascades):* Setting a timer below normal tail latency (e.g., an overly aggressive `20ms` timer tripped by a post-deployment TLS handshake) forces healthy requests to time out and retry, manufacturing an outage out of minor jitter.
- **Hierarchy invariant:** `per_tool_timeout < step_timeout < working_limit <= wall_clock_time_limit` so one hung tool never consumes the entire run budget.

---

## 2. Capped Exponential Backoff + Full/Decorrelated Jitter

Exponential backoff without jitter synchronizes retries into periodic **thundering herds** that hammer recovering endpoints at the exact same millisecond (`AH009`). Always cap both the delay (`cap_s`) and max attempts, and randomize sleep intervals:

- **Full Jitter (recommended default for live requests):**
  $$\text{sleep}_a = \text{Uniform}\!\left(0,\; \min(\text{cap},\; \text{base} \cdot 2^{a})\right)$$
- **Decorrelated Jitter (smooth variance around previous sleep):**
  $$\text{sleep}_a = \min\!\left(\text{cap},\; \text{Uniform}(\text{base},\; \text{sleep}_{a-1} \cdot 3)\right)$$
- **Host-Consistent Deterministic Jitter (for scheduled/cron jobs):** Hash `(host_id, job_id)` into a fixed offset so fleet traffic spreads evenly while overload patterns remain reproducible and debuggable.
- **Respect `Retry-After` headers:** When an LLM provider returns HTTP `429` with `Retry-After`, honor the server-specified floor (bounded by your step deadline) and add small positive jitter.

---

## 3. Single-Layer Retry Rule & Token-Bucket Retry Budgets

### The $r^d$ Amplification Trap (`AH009`)

In an agent stack with $d = 5$ layers (orchestrator -> subagent -> agent loop -> tool wrapper -> HTTP/LLM SDK), if each layer retries $r = 3$ times independently, a struggling dependency receives:

$$r^d = 3^5 = 243\times \text{ load amplification}$$

**Single-Layer Retry Rule:** Choose **one** layer to own retries—typically the provider adapter at durable step boundaries (`llm-retry` in DeepSeek `dsh`)—and explicitly disable retries in inner SDKs (`max_retries=0` on `openai`/`anthropic`/`httpx` clients) and outer orchestrators.

### Token-Bucket Retry Budgets Over Modal Circuit Breakers

Binary open/closed circuit breakers introduce abrupt mode flips and recovery oscillations. AWS Builders' Library recommends pairing single-layer retries with a **local token-bucket retry budget**:

- Every **successful** request deposits `+1` token (up to `max_tokens`, e.g., `100`).
- Every **retry** withdraws `retry_cost` tokens (e.g., `10`, capping steady-state retry overhead at $\le 10\%$ of healthy traffic).
- When the bucket is below `retry_cost`, fail fast immediately without retrying—preserving system stability during brownouts without hard modal flaps.

### Python 3.11+ — Single-Layer Jittered Retry with Token-Bucket Budget

```python
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


@dataclass
class RetryBudget:
    """Token-bucket retry budget capping retry overhead (default <= 10% of healthy traffic)."""

    max_tokens: float = 100.0
    tokens: float = 100.0
    success_deposit: float = 1.0
    retry_cost: float = 10.0

    def record_success(self) -> None:
        self.tokens = min(self.max_tokens, self.tokens + self.success_deposit)

    def try_consume_retry(self) -> bool:
        if self.tokens < self.retry_cost:
            return False
        self.tokens -= self.retry_cost
        return True


class RetryableError(Exception):
    def __init__(self, message: str, *, retry_after_s: float | None = None) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


async def call_with_single_layer_retry(
    fn: Callable[[], Awaitable[T]],
    *,
    budget: RetryBudget,
    max_attempts: int = 4,
    base_s: float = 0.5,
    cap_s: float = 16.0,
) -> T:
    """Execute fn with capped exponential backoff + full jitter gated by a retry budget."""
    for attempt in range(max_attempts):
        try:
            result = await fn()
            budget.record_success()
            return result
        except RetryableError as exc:
            is_last = attempt == max_attempts - 1
            if is_last or not budget.try_consume_retry():
                raise
            upper = min(cap_s, base_s * (2 ** attempt))
            delay = random.uniform(0.0, upper)
            if exc.retry_after_s is not None:
                delay = max(delay, min(cap_s, exc.retry_after_s)) + random.uniform(0.0, 0.25)
            await asyncio.sleep(delay)
    raise AssertionError("Unreachable")
```

### TypeScript (strict ESM) — Single-Layer Retry with `AbortSignal` & Budget

```typescript
export class RetryBudget {
  private tokens: number;
  private readonly maxTokens: number;
  private readonly successDeposit: number;
  private readonly retryCost: number;

  constructor(maxTokens = 100, successDeposit = 1, retryCost = 10) {
    this.maxTokens = maxTokens;
    this.successDeposit = successDeposit;
    this.retryCost = retryCost;
    this.tokens = maxTokens;
  }

  recordSuccess(): void {
    this.tokens = Math.min(this.maxTokens, this.tokens + this.successDeposit);
  }

  tryConsumeRetry(): boolean {
    if (this.tokens < this.retryCost) return false;
    this.tokens -= this.retryCost;
    return true;
  }
}

export class RetryableError extends Error {
  public readonly retryAfterMs?: number;

  constructor(message: string, retryAfterMs?: number) {
    super(message);
    this.name = "RetryableError";
    this.retryAfterMs = retryAfterMs;
  }
}

async function sleepWithAbort(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) throw signal.reason ?? new DOMException("Aborted", "AbortError");
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason ?? new DOMException("Aborted", "AbortError"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export async function callWithSingleLayerRetry<T>(
  fn: (signal?: AbortSignal) => Promise<T>,
  opts: {
    budget: RetryBudget;
    signal?: AbortSignal;
    maxAttempts?: number;
    baseMs?: number;
    capMs?: number;
  },
): Promise<T> {
  const maxAttempts = opts.maxAttempts ?? 4;
  const baseMs = opts.baseMs ?? 500;
  const capMs = opts.capMs ?? 16_000;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    opts.signal?.throwIfAborted();
    try {
      const value = await fn(opts.signal);
      opts.budget.recordSuccess();
      return value;
    } catch (err) {
      if (!(err instanceof RetryableError) || attempt === maxAttempts - 1 || !opts.budget.tryConsumeRetry()) {
        throw err;
      }
      const upper = Math.min(capMs, baseMs * 2 ** attempt);
      let delayMs = Math.random() * upper;
      if (err.retryAfterMs !== undefined) {
        delayMs = Math.max(delayMs, Math.min(capMs, err.retryAfterMs)) + Math.random() * 250;
      }
      await sleepWithAbort(delayMs, opts.signal);
    }
  }
  throw new Error("Unreachable");
}
```

---

## 4. Retryable vs. Non-Retryable Failure Classification

Never blindly retry every exception. Classify failures explicitly at the adapter boundary:

| Category | Examples | Retryable? | Required Harness Action |
|---|---|---|---|
| **Transient Infra / Rate Limit** | HTTP `429`, `500`, `502`, `503`, `504`, `529`, TCP reset, DNS transient error, read timeout | **Yes** (idempotent/safe calls only) | Single-layer capped backoff + full jitter gated by `RetryBudget`. |
| **Client / Schema / Auth Error** | HTTP `400`, `401`, `403`, `404`, `422`, invalid JSON schema, missing `reasoning_content` | **No** | Fail fast or return actionable error to model/operator; retrying burns budget and accelerates doom loops. |
| **Context Window Overflow** | Provider canonical `context_length_exceeded` / prompt-too-long error | **No (blind)** | Route to compaction hook (`agent/request-error` -> prune tool results / summarize / reset), then reissue once. |
| **Expected Tool Error** | `FileNotFoundError`, non-zero test exit code, SQL syntax error, policy rejection | **No (harness)** | Return structured corrective `tool/result` (`is_error=True`) to the model so it can self-correct. |
| **Unexpected Infra Error** | Sandbox daemon dead, corrupted disk, unhandled harness bug | **No (model)** | Do **not** hide behind a tool string; abort or fail the run cleanly with `error.type` logged. |

---

## 5. Idempotency Keys (`ClientToken`) for Side-Effecting Tools

When a network timeout occurs after invoking a mutating tool (`create_ticket`, `charge_card`, `provision_vm`, `send_email`, `post_comment`), the harness cannot know whether the remote side effect succeeded. Retrying without an idempotency token duplicates the side effect.

AWS Builders' Library (*Making retries safe with idempotent APIs*) establishes four hard rules:

1. **Caller-generated `ClientToken` / `idempotency_key`:** Generate a deterministic key scoped to `(session_id, tool_call_id)` before the first attempt and send the exact same token on retries.
2. **Never use naive parameter-hash deduplication:** Hashing request parameters breaks whenever a user legitimately creates two identical resources (e.g., two identical worker VMs).
3. **ACID token persistence:** Commit the idempotency token and the created resource in the **same atomic database transaction** to eliminate split-brain states.
4. **Strict replay semantics:**
   - Same `ClientToken` + same parameters -> return a **semantically equivalent success response** (never `ResourceAlreadyExists`, which breaks automated retry clients).
   - Same `ClientToken` + **different** parameters -> reject with `IdempotentParameterMismatch` (`400`/`409`).

```python
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class IdempotencyRecord:
    params_sha256: str
    response: dict[str, Any]


class IdempotencyStore:
    """In-process reference model (back with an ACID DB table in production)."""

    def __init__(self) -> None:
        self._records: dict[str, IdempotencyRecord] = {}

    @staticmethod
    def _fingerprint(params: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()

    def execute_once(
        self,
        client_token: str,
        params: dict[str, Any],
        operation: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        fp = self._fingerprint(params)
        existing = self._records.get(client_token)
        if existing is not None:
            if existing.params_sha256 != fp:
                raise ValueError(f"IdempotentParameterMismatch for ClientToken '{client_token}'.")
            return existing.response
        response = operation()
        self._records[client_token] = IdempotencyRecord(params_sha256=fp, response=response)
        return response
```

---

## 6. Keep the Wrong Stuff In (Never Swallow or Erase Errors)

Two opposite error-handling anti-patterns both cripple agent reliability (`AH008`):

1. **Silent exception swallowing (`except Exception: pass` or returning `""` / `{"ok": true}`):** The agent believes a failed edit or command succeeded and hallucinates downstream steps on corrupted state.
2. **Erasing failed turns from history (`messages.pop()` on tool error):** Manus (*Keep the Wrong Stuff In*) proved that scrubbing failed actions and error observations destroys the Bayesian evidence the model needs to shift its posterior away from the broken strategy—causing it to repeat the exact same mistake.

**Required rule:** Catch expected tool failures, log full diagnostics to telemetry, keep the assistant `tool_call` in history, and append an actionable `role="tool"` error result explaining *what failed* and *how to recover* (only prune very old errors during late-stage compaction).

---

## 7. Graceful Cancellation & Container Cleanup

Cancellation (`SIGINT`, `SIGTERM`, user abort, or `time_limit` / `working_limit` exhaustion) must unwind cleanly without leaking orphan subprocesses, dangling sandbox containers, or truncated traces:

- **Python (`asyncio.CancelledError` / `anyio` cancel scopes):**
  - Never catch `CancelledError` inside a broad `except Exception:` (in Python 3.8+, `CancelledError` inherits from `BaseException`).
  - If you catch `BaseException` to record an `assistant/attempt` or clean up a container, **always re-raise** `CancelledError` immediately after shielded cleanup (`asyncio.shield` / `anyio.CancelScope(shield=True)`).
  - Run Docker containers with `init: true` so `SIGTERM` reaches child trees cleanly, and remove ephemeral containers in a `finally:` block.
- **TypeScript (`AbortSignal` / `AbortController`):**
  - Thread one `AbortSignal` into `fetch(..., { signal })`, `child_process.spawn(..., { signal })`, and retry sleep timers.
  - Combine user cancellation and deadline timeouts cleanly via `AbortSignal.any([userSignal, AbortSignal.timeout(timeoutMs)])`.

### Python 3.11+ — Graceful Subprocess Cancellation with Process-Group Teardown

```python
import asyncio
import contextlib
import os
import signal


def _terminate_process_tree(proc: asyncio.subprocess.Process, *, force: bool = False) -> None:
    """Signal the entire process group on POSIX; fall back to terminate/kill on Windows."""
    if proc.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        if os.name == "posix":
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.killpg(os.getpgid(proc.pid), sig)
        elif force:
            proc.kill()
        else:
            proc.terminate()


async def run_cancellable_command(
    argv: list[str], *, timeout_s: float, grace_s: float = 3.0
) -> tuple[int, str, str]:
    """Run a subprocess with timeout and guaranteed process-group teardown on cancellation."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=(os.name == "posix"),
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        return proc.returncode or 0, stdout_b.decode("utf-8", "replace"), stderr_b.decode("utf-8", "replace")
    except (TimeoutError, asyncio.CancelledError):
        _terminate_process_tree(proc, force=False)
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace_s)
        except TimeoutError:
            _terminate_process_tree(proc, force=True)
            await proc.wait()
        raise
```

### TypeScript (strict ESM) — Composed `AbortSignal` Timeout, Bounded Output & `SIGKILL` Escalation

```typescript
import { spawn } from "node:child_process";

export async function runCancellableCommand(
  cmd: string,
  args: readonly string[],
  opts: { timeoutMs: number; graceMs?: number; maxOutputChars?: number; signal?: AbortSignal },
): Promise<{ exitCode: number; stdout: string; stderr: string; truncated: boolean }> {
  const graceMs = opts.graceMs ?? 3_000;
  const maxOutputChars = opts.maxOutputChars ?? 65_536;
  const combined = opts.signal
    ? AbortSignal.any([opts.signal, AbortSignal.timeout(opts.timeoutMs)])
    : AbortSignal.timeout(opts.timeoutMs);

  combined.throwIfAborted();

  return await new Promise((resolve, reject) => {
    const child = spawn(cmd, [...args], { stdio: ["ignore", "pipe", "pipe"], signal: combined });
    let stdout = "";
    let stderr = "";
    let truncated = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;

    const appendBounded = (buf: string, chunk: string): string => {
      const remaining = maxOutputChars - buf.length;
      if (remaining <= 0) {
        truncated = true;
        return buf;
      }
      if (chunk.length > remaining) {
        truncated = true;
        return buf + chunk.slice(0, remaining);
      }
      return buf + chunk;
    };

    const onAbort = (): void => {
      // Escalate to SIGKILL if child ignores SIGTERM sent by AbortSignal.
      killTimer = setTimeout(() => {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill("SIGKILL");
        }
      }, graceMs);
      killTimer.unref();
    };

    const cleanup = (): void => {
      if (killTimer !== undefined) clearTimeout(killTimer);
      combined.removeEventListener("abort", onAbort);
    };

    combined.addEventListener("abort", onAbort, { once: true });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout = appendBounded(stdout, chunk);
    });
    child.stderr.on("data", (chunk: string) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.on("exit", () => {
      if (killTimer !== undefined) clearTimeout(killTimer);
    });
    child.on("error", (err) => {
      combined.removeEventListener("abort", onAbort);
      reject(err);
    });
    child.on("close", (code) => {
      cleanup();
      resolve({ exitCode: code ?? -1, stdout, stderr, truncated });
    });
  });
}
```

---

## 8. Thread-Pool Offloading for Blocking Sync I/O on Async Loops

Calling blocking synchronous I/O (`time.sleep`, `requests.get`, sync `subprocess.run`, sync SQLite/filesystem scans) inside a Python `async def` agent loop or tool handler freezes the entire event loop (`AH014`)—stalling SSE heartbeats, concurrent read-only tools, cancellation timers, and health probes (explicitly warned against in Google ADK's runtime documentation, which provides `tool_thread_pool_config`).

- **Preferred:** Use native async APIs (`asyncio.create_subprocess_exec`, `httpx.AsyncClient`, `aiofiles`).
- **When wrapping sync libraries:** Offload explicitly via `await asyncio.to_thread(sync_fn, *args)` or a bounded `concurrent.futures.ThreadPoolExecutor(max_workers=...)` so blocking calls cannot starve the event loop or exhaust threads.
- **Node.js / TypeScript:** Never use `fs.readFileSync`, `child_process.execFileSync`, or CPU-heavy synchronous parsing inside async streaming handlers; use `node:fs/promises`, async `spawn`, or `worker_threads`.

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Callable, TypeVar

T = TypeVar("T")

_TOOL_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="harness-sync-tool")


async def run_blocking_tool(fn: Callable[..., T], *args: object, **kwargs: object) -> T:
    """Offload synchronous I/O or library calls off the asyncio event loop safely."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_TOOL_EXECUTOR, partial(fn, *args, **kwargs))
```

---

## 9. Typed Harness Streaming Event Protocol

Expose a strict, discriminated union streaming protocol from your harness to UIs/SDK callers (over SSE or NDJSON) that cleanly distinguishes **transient streaming deltas** from **durable settled events**:

| Event `type` | `settled` | Purpose |
|---|---|---|
| `text_delta` / `thinking_delta` | `false` | Live UI streaming tokens; discardable on disconnect. |
| `tool_call_delta` | `false` | Streaming tool name/argument fragments for progress indicators only. |
| `tool_execution_started` | `false` | Emitted after approval passes, before execution begins. |
| `tool_result` | `true` | Committed tool output/error (`tool_call_id`, `is_error`, truncated preview + spill locator). |
| `turn_committed` | `true` | Atomic settlement of `assistant/message` (`seq`, inclusive token usage, `finish_reason`). |
| `approval_required` | `true` | Run entered `WAITING_APPROVAL` with deterministic risk diff. |
| `run_terminal` | `true` | Final state (`COMPLETED`, `FAILED`, `BUDGET_EXCEEDED`) + summary stats. |

### TypeScript (strict ESM) — Discriminated Streaming Event Union

```typescript
export type HarnessStreamEvent =
  | { readonly type: "text_delta"; readonly settled: false; readonly delta: string }
  | { readonly type: "thinking_delta"; readonly settled: false; readonly delta: string }
  | { readonly type: "tool_call_delta"; readonly settled: false; readonly callId: string; readonly delta: string }
  | { readonly type: "tool_execution_started"; readonly settled: false; readonly callId: string; readonly toolName: string }
  | { readonly type: "tool_result"; readonly settled: true; readonly seq: number; readonly callId: string; readonly isError: boolean; readonly content: string }
  | { readonly type: "turn_committed"; readonly settled: true; readonly seq: number; readonly tokensIn: number; readonly tokensCached: number; readonly tokensOut: number; readonly finishReason: string }
  | { readonly type: "approval_required"; readonly settled: true; readonly callId: string; readonly toolName: string; readonly riskSummary: string }
  | { readonly type: "run_terminal"; readonly settled: true; readonly state: "COMPLETED" | "FAILED" | "BUDGET_EXCEEDED"; readonly reason: string };

export function encodeSseEvent(event: HarnessStreamEvent): string {
  return `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
}
```

---

## 10. Verification Checklist

- [ ] **Timeouts everywhere (`AH007`):** Explicit connect + read timeouts sized from p99.9 on every HTTP/LLM/MCP/subprocess call; `per_tool < step < working_limit <= wall_time`.
- [ ] **Single-layer retries (`AH009`):** Inner SDKs configure `max_retries=0`; outer provider adapter owns capped exponential backoff + full jitter gated by a `RetryBudget`.
- [ ] **Strict error classification:** Only transient `429`/`5xx`/network errors auto-retry; `4xx` fails fast; context overflow routes to compaction.
- [ ] **Idempotent mutations:** Side-effecting tools accept a caller-scoped `ClientToken` persisted atomically with the resource; mismatched params raise `IdempotentParameterMismatch`.
- [ ] **Keep the Wrong Stuff In (`AH008`):** Zero `except Exception: pass` and zero `messages.pop()` on tool errors; expected failures return structured corrective `tool/result` messages.
- [ ] **Cancellation & cleanup:** `asyncio.CancelledError` / `AbortSignal` propagates to streams, subprocesses, and `init: true` containers with guaranteed teardown in `finally`.
- [ ] **Non-blocking async loops (`AH014`):** Zero blocking sync I/O (`time.sleep`, `requests.*`, sync `subprocess.run`) directly inside `async def` functions.
- [ ] **Typed streaming protocol:** UI consumes discriminated events separating transient `settled: false` deltas from durable `settled: true` commits.
