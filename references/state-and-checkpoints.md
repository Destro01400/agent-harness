# State, Checkpoints, and Human-in-the-Loop Control

> **Core Invariant (`Model-visible ⟺ logged`):** The durable append-only session log—not the volatile LLM context window and not an ephemeral sandbox container—is the single source of truth. Every token sent to the model must be deterministically derived from committed session events.

## Table of Contents

1. [Three-Way Decoupling: Brain, Session, and Hands](#1-three-way-decoupling-brain-session-and-hands)
2. [Append-Only Durable Session Log & Versioned Migrations](#2-append-only-durable-session-log--versioned-migrations)
3. [Atomic Streaming vs. Settled Commits](#3-atomic-streaming-vs-settled-commits)
4. [Orphan & Missing Tool-Result Repair](#4-orphan--missing-tool-result-repair)
5. [Explicit Agent Run State Machine](#5-explicit-agent-run-state-machine)
6. [Long-Running Initializer + Worker Pattern](#6-long-running-initializer--worker-pattern)
7. [HITL 5-Decision ApprovalPolicy & Consecutive-Rejection Breaker](#7-hitl-5-decision-approvalpolicy--consecutive-rejection-breaker)
8. [Verification Checklist](#8-verification-checklist)

---

## 1. Three-Way Decoupling: Brain, Session, and Hands

Production harnesses (Anthropic Managed Agents, DeepSeek Harness `dsh`, Google ADK, OpenHands) decouple agent runtime state into three independent failure domains:

| Layer | Responsibility | Durability | Failure & Recovery Behavior |
|---|---|---|---|
| **Session** | Append-only event log (`session.vN.jsonl` or SQLite) | Durable, immutable | Survives process `SIGKILL`, OOM, and container loss; feeds `derive_messages()` projections. |
| **Brain (Harness Loop)** | Turn orchestration, prompt assembly, compaction, retry, approval gating | Stateless / recoverable | Rehydrates from the session log on restart (`wake(session_id)`), never keeps unlogged state. |
| **Hands (Sandbox / Tools)** | Subprocess, filesystem, container, or MCP execution | Ephemeral / replaceable | Lazy-provisioned; replaceable without losing session history or committed workspace artifacts. |

Never treat an in-memory `messages: list[dict]` array as the canonical store. Compaction, tool-result pruning, and context resets transform only the *derived model view* (`derive_messages(events)`), leaving the raw append-only event log intact for audit, crash recovery, and deterministic replay.

---

## 2. Append-Only Durable Session Log & Versioned Migrations

Following DeepSeek Harness (`dsh` `packages/session/`), persist events into immutable versioned generation files (`session.v0.jsonl`, `session.v1.jsonl`, ..., optionally `.zstd`-compressed) or an append-only SQLite WAL table:

- **Monotonic sequence numbers (`seq`):** Every committed event receives a strictly increasing integer `seq` and an ISO-8601 UTC timestamp.
- **Frozen request derivation:** Before calling the model, commit `system/message`, `user/message`, and request metadata, then materialize an immutable `messages` projection strictly via `derive_messages(log)`. Any retry reuses the exact frozen request without duplicating committed entries.
- **Immutable adjacent migrations (`vN -> vN+1`):** Never overwrite, rename, or delete committed generation files during schema upgrades. Compose small, pure, adjacent migrators (`v0_to_v1`, `v1_to_v2`, ...) that read `session.vN.jsonl` and write a new `session.v{N+1}.jsonl` atomically via temp-file + `fsync` + `os.replace`.

### Python 3.11+ — Versioned Append-Only Session Log & Adjacent Migrator

```python
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class SessionEvent:
    seq: int
    event_type: str  # e.g., "user/message", "assistant/message", "assistant/attempt", "tool/result"
    timestamp: str
    payload: dict[str, Any]
    schema_version: int = 2
    metadata: dict[str, Any] = field(default_factory=dict)


class DurableSessionLog:
    """Append-only JSONL session log with fsync durability and pure message derivation."""

    def __init__(self, session_dir: Path, schema_version: int = 2) -> None:
        self.session_dir = session_dir
        self.schema_version = schema_version
        self.path = session_dir / f"session.v{schema_version}.jsonl"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._next_seq = self._scan_next_seq()

    def _scan_next_seq(self) -> int:
        if not self.path.exists():
            return 1
        last_seq = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                last_seq = max(last_seq, int(json.loads(line)["seq"]))
        return last_seq + 1

    def append(self, event_type: str, payload: dict[str, Any], metadata: dict[str, Any] | None = None) -> SessionEvent:
        event = SessionEvent(
            seq=self._next_seq,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            payload=payload,
            schema_version=self.schema_version,
            metadata=metadata or {},
        )
        encoded = json.dumps(asdict(event), sort_keys=True, ensure_ascii=False) + "\n"
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        self._next_seq += 1
        return event

    def read_events(self) -> list[SessionEvent]:
        if not self.path.exists():
            return []
        events: list[SessionEvent] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(SessionEvent(**json.loads(line)))
        return events


Migrator = Callable[[dict[str, Any]], dict[str, Any]]


def migrate_session_chain(
    session_dir: Path,
    from_version: int,
    to_version: int,
    migrators: dict[tuple[int, int], Migrator],
) -> Path:
    """Apply adjacent vN -> vN+1 migrations without mutating committed generation files."""
    current_v = from_version
    while current_v < to_version:
        nxt = current_v + 1
        fn = migrators[(current_v, nxt)]
        src = session_dir / f"session.v{current_v}.jsonl"
        dst = session_dir / f"session.v{nxt}.jsonl"
        if dst.exists():
            current_v = nxt
            continue
        tmp = session_dir / f".session.v{nxt}.jsonl.tmp"
        with src.open("r", encoding="utf-8") as rfh, tmp.open("w", encoding="utf-8") as wfh:
            for line in rfh:
                if not line.strip():
                    continue
                upgraded = fn(json.loads(line))
                upgraded["schema_version"] = nxt
                wfh.write(json.dumps(upgraded, sort_keys=True, ensure_ascii=False) + "\n")
            wfh.flush()
            os.fsync(wfh.fileno())
        os.replace(tmp, dst)  # Atomic rename; src remains untouched.
        current_v = nxt
    return session_dir / f"session.v{to_version}.jsonl"
```

### TypeScript (strict ESM) — Append-Only Session Log & Pure Projection

```typescript
import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

export type SessionEventType =
  | "system/message"
  | "user/message"
  | "assistant/message"
  | "assistant/attempt"
  | "tool/result"
  | "state/transition"
  | "approval/decision";

export interface SessionEvent<T = Record<string, unknown>> {
  readonly seq: number;
  readonly schemaVersion: number;
  readonly eventType: SessionEventType;
  readonly timestamp: string;
  readonly payload: T;
}

export class DurableSessionLog {
  private nextSeq = 1;
  private readonly sessionDir: string;
  private readonly schemaVersion: number;
  private readonly filePath: string;

  constructor(sessionDir: string, schemaVersion = 2) {
    this.sessionDir = sessionDir;
    this.schemaVersion = schemaVersion;
    this.filePath = join(sessionDir, `session.v${schemaVersion}.jsonl`);
  }

  async init(): Promise<void> {
    await mkdir(this.sessionDir, { recursive: true });
    const existing = await this.readEvents();
    this.nextSeq = existing.length === 0 ? 1 : existing[existing.length - 1]!.seq + 1;
  }

  async append<T extends Record<string, unknown>>(
    eventType: SessionEventType,
    payload: T,
  ): Promise<SessionEvent<T>> {
    const event: SessionEvent<T> = {
      seq: this.nextSeq++,
      schemaVersion: this.schemaVersion,
      eventType,
      timestamp: new Date().toISOString(),
      payload,
    };
    const canonical = `${JSON.stringify(sortKeys(event))}\n`;
    await appendFile(this.filePath, canonical, { encoding: "utf8", flush: true });
    return event;
  }

  async readEvents(): Promise<SessionEvent[]> {
    try {
      const raw = await readFile(this.filePath, "utf8");
      return raw
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as SessionEvent);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }
}

export function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

export async function migrateAdjacent(
  sessionDir: string,
  fromVersion: number,
  migrator: (event: Record<string, unknown>) => Record<string, unknown>,
): Promise<string> {
  const src = join(sessionDir, `session.v${fromVersion}.jsonl`);
  const dst = join(sessionDir, `session.v${fromVersion + 1}.jsonl`);
  const tmp = join(sessionDir, `.session.v${fromVersion + 1}.jsonl.tmp`);
  const lines = (await readFile(src, "utf8")).split("\n").filter((l) => l.trim().length > 0);
  const upgraded = lines.map((line) => {
    const row = migrator(JSON.parse(line) as Record<string, unknown>);
    row["schemaVersion"] = fromVersion + 1;
    return JSON.stringify(sortKeys(row));
  });
  await writeFile(tmp, `${upgraded.join("\n")}\n`, { encoding: "utf8", flush: true });
  await rename(tmp, dst);
  return dst;
}
```

---

## 3. Atomic Streaming vs. Settled Commits

A common state-corruption bug in streaming harnesses is committing partial tokens or `state_delta` updates into the durable session log while a response is still streaming. If the stream disconnects, errors, or is cancelled mid-turn, the session log retains corrupted half-messages ("dirty reads").

Production harnesses enforce a strict two-channel boundary:

| Channel | Google ADK Pattern | DeepSeek Harness (`dsh`) Pattern | Persisted to Model History? |
|---|---|---|---|
| **Transient Streaming Frames** | `Event(partial=True)` forwarded to UI/subscribers; `state_delta` ignored. | `agent/assistant-stream` ephemeral chunks on live bus. | **Never.** UI-only, discardable on disconnect. |
| **Durable Settled Commit (Success)** | Final `Event(partial=False)` commits `state_delta` + content atomically. | `assistant/message` (embedding compact timed stream + complete blocks & `tool_calls`). | **Yes.** Projected by `derive_messages()`. |
| **Durable Settled Commit (Failure/Cancel)** | Error event without partial state mutation. | `assistant/attempt` (records partial text, error, cancellation, token spend). | **Audit only.** Excluded from model-visible `messages` so retries start clean. |

**Admission Gate Rule (`prepareCall()`):** If cancellation arrives *before* the LLM request is admitted, commit neither the pending system rebuild nor the queued user turn so the session stays cleanly resumable.

### Python 3.11+ — Settled Commit Separating `assistant/message` and `assistant/attempt`

```python
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any


async def stream_and_settle_turn(
    log: DurableSessionLog,
    stream: AsyncIterator[dict[str, Any]],
    on_ui_frame: Callable[[dict[str, Any]], None],
) -> SessionEvent | None:
    """Forward transient partial frames to UI; commit exactly once on settlement."""
    text_parts: list[str] = []
    thinking_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    usage: dict[str, int] = {}

    try:
        async for chunk in stream:
            kind = chunk["type"]
            if kind == "text_delta":
                text_parts.append(chunk["delta"])
                on_ui_frame({"partial": True, "kind": "text_delta", "delta": chunk["delta"]})
            elif kind == "thinking_delta":
                thinking_parts.append(chunk["delta"])
                on_ui_frame({"partial": True, "kind": "thinking_delta", "delta": chunk["delta"]})
            elif kind == "tool_call":
                tool_calls.append(chunk["tool_call"])
            elif kind == "usage":
                usage = chunk["usage"]
    except BaseException as exc:
        # Record auditable failed/cancelled attempt without polluting model-visible history.
        is_cancelled = isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, GeneratorExit))
        await asyncio.to_thread(
            log.append,
            "assistant/attempt",
            {
                "status": "cancelled" if is_cancelled else "failed",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "partial_text": "".join(text_parts),
                "usage": usage,
            },
        )
        raise

    settled = await asyncio.to_thread(
        log.append,
        "assistant/message",
        {
            "content": "".join(text_parts),
            "reasoning_content": "".join(thinking_parts) or None,
            "tool_calls": tool_calls,
            "usage": usage,
        },
    )
    on_ui_frame({"partial": False, "kind": "turn_settled", "seq": settled.seq})
    return settled
```

---

## 4. Orphan & Missing Tool-Result Repair

LLM APIs (Anthropic Messages, OpenAI Responses/Chat, DeepSeek Thinking) reject requests with HTTP `400` if an `assistant` message contains a `tool_call` (`id = "call_42"`) without a matching `tool` / `tool_result` message before the next `assistant` or `user` turn. Crashes (`SIGKILL`, OOM), per-tool timeouts, approval rejections, or cancellation mid-batch routinely produce **orphan tool calls**.

Two rules keep every resumed session valid:

1. **In-order batch settlement:** Even when read-only tools execute concurrently in a bounded worker pool (`ordered pre-execute -> bounded concurrent execute -> ordered post-execute`), commit `tool/result` events in the exact order emitted by the assistant turn.
2. **Deterministic startup repair (`derive_messages`):** When projecting history from the log on resume or after a failed step, scan every committed `assistant/message` with `tool_calls`. For any `tool_call_id` lacking a subsequent `tool/result`, append a synthetic `tool/result` error event (`"Tool execution did not complete due to process interruption or timeout. Inspect workspace state before retrying."`)—and **never** encode tool results as `role: "user"` (which breaks DeepSeek thinking persistence and triggers static audit rule `AH011`).

### Python 3.11+ — Orphan Tool-Call Detection & Repair

```python
from __future__ import annotations

from typing import Any


def repair_orphan_tool_calls(log: DurableSessionLog) -> list[str]:
    """Ensure every committed tool_call_id has a matching tool/result event."""
    events = log.read_events()
    pending_calls: dict[str, str] = {}  # tool_call_id -> tool_name

    for ev in events:
        if ev.event_type == "assistant/message":
            for tc in ev.payload.get("tool_calls", []):
                pending_calls[tc["id"]] = tc["name"]
        elif ev.event_type == "tool/result":
            pending_calls.pop(ev.payload["tool_call_id"], None)

    repaired_ids: list[str] = []
    for call_id, tool_name in pending_calls.items():
        log.append(
            "tool/result",
            {
                "tool_call_id": call_id,
                "tool_name": tool_name,
                "is_error": True,
                "synthetic_repair": True,
                "content": (
                    f"[HARNESS_RECOVERY] Tool '{tool_name}' (call_id={call_id}) was interrupted "
                    "before returning a result. Verify current state before retrying."
                ),
            },
        )
        repaired_ids.append(call_id)
    return repaired_ids


def derive_messages(events: list[SessionEvent]) -> list[dict[str, Any]]:
    """Pure projection from durable session events to provider-ready messages."""
    messages: list[dict[str, Any]] = []
    for ev in events:
        if ev.event_type == "assistant/attempt":
            continue  # Failed/cancelled attempts stay auditable but never enter model context.
        if ev.event_type == "system/message":
            messages.append({"role": "system", "content": ev.payload["content"]})
        elif ev.event_type == "user/message":
            messages.append({"role": "user", "content": ev.payload["content"]})
        elif ev.event_type == "assistant/message":
            msg: dict[str, Any] = {"role": "assistant", "content": ev.payload.get("content", "")}
            if ev.payload.get("reasoning_content") is not None:
                msg["reasoning_content"] = ev.payload["reasoning_content"]
            if ev.payload.get("tool_calls"):
                msg["tool_calls"] = ev.payload["tool_calls"]
            messages.append(msg)
        elif ev.event_type == "tool/result":
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": ev.payload["tool_call_id"],
                    "name": ev.payload["tool_name"],
                    "content": ev.payload["content"],
                }
            )
    return messages
```

---

## 5. Explicit Agent Run State Machine

Implicit boolean flags (`done`, `waiting`, `errored`) cause illegal transitions (e.g., resuming a `BUDGET_EXCEEDED` run without raising limits, or double-completing after a rejection). Model run lifecycle with an explicit, persisted finite state machine:

```text
                +------------------+
                |     RUNNING      |<-----------------------------------+
                +---+----+----+----+                                    |
                    |    |    |                                         |
     escalate/ask   |    |    | budget exhausted                        | approve / modify /
                    v    |    +------------------>+-----------------+   | reject (< 3)
        +------------------+  wall-time expired   | BUDGET_EXCEEDED |   |
        | WAITING_APPROVAL |--------------------->|   (terminal)    |   |
        +--------+----+----+                      +-----------------+   |
                 |    |                                                 |
                 |    +-------------------------------------------------+
                 | terminate / 3 consecutive rejections
                 +------------------------------->+-----------------+
                                                  |     FAILED      |
                           unrecoverable error    |   (terminal)    |
                        RUNNING ----------------->+-----------------+

                           natural stop + verified
                        RUNNING ----------------->+-----------------+
                                                  |    COMPLETED    |
                                                  |   (terminal)    |
                                                  +-----------------+
```

| State | Terminal? | Permitted Outgoing Transitions | Persistence Action |
|---|---|---|---|
| `RUNNING` | No | `WAITING_APPROVAL`, `COMPLETED`, `FAILED`, `BUDGET_EXCEEDED` | Persist `step/start`, settled commits, and budget counters. |
| `WAITING_APPROVAL` | No | `RUNNING` (on `approve`/`modify`/`reject` < 3), `FAILED` (on `terminate` or 3rd consecutive `reject`), `BUDGET_EXCEEDED` (if hard wall-clock `time_limit` expires while waiting) | Persist pending `tool_call` + deterministic risk diff; pause `working_limit` clock (keep wall-clock `time_limit` active). |
| `COMPLETED` | Yes | None | Persist final verified summary & `turn/end`. |
| `FAILED` | Yes | None | Persist structured `error_type`, `reason`, and any orphan repairs. |
| `BUDGET_EXCEEDED` | Yes | None (requires explicit new run/budget override) | Persist breached dimension (`turn`, `token`, `cost`, `working_time`, `wall_time`). |

### TypeScript (strict ESM) — Explicit State Machine with Guarded Transitions

```typescript
export type RunState =
  | "RUNNING"
  | "WAITING_APPROVAL"
  | "COMPLETED"
  | "FAILED"
  | "BUDGET_EXCEEDED";

const ALLOWED_TRANSITIONS: Readonly<Record<RunState, readonly RunState[]>> = {
  RUNNING: ["WAITING_APPROVAL", "COMPLETED", "FAILED", "BUDGET_EXCEEDED"],
  WAITING_APPROVAL: ["RUNNING", "FAILED", "BUDGET_EXCEEDED"],
  COMPLETED: [],
  FAILED: [],
  BUDGET_EXCEEDED: [],
};

export class RunStateMachine {
  private state: RunState = "RUNNING";

  get current(): RunState {
    return this.state;
  }

  get isTerminal(): boolean {
    return ALLOWED_TRANSITIONS[this.state].length === 0;
  }

  async transition(
    next: RunState,
    reason: string,
    log: DurableSessionLog,
  ): Promise<void> {
    if (!ALLOWED_TRANSITIONS[this.state].includes(next)) {
      throw new Error(`Illegal run state transition: ${this.state} -> ${next} (${reason})`);
    }
    const prev = this.state;
    this.state = next;
    await log.append("state/transition", { from: prev, to: next, reason });
  }
}
```

---

## 6. Long-Running Initializer + Worker Pattern

Multi-hour tasks exceed single context windows and suffer four verified failure modes even on frontier models (Anthropic, *Effective Harnesses for Long-Running Agents*):

1. **One-shotting & mid-feature exhaustion:** Attempting the entire spec in one window and leaving half-broken code behind.
2. **Premature victory declaration:** Seeing partial prior progress and declaring the project complete.
3. **Unverified completion:** Marking features done after unit/curl checks while real end-to-end flows fail.
4. **Checklist tampering:** Silently rewriting Markdown checklists to delete or weaken failing acceptance tests.

Solve all four by separating Session 1 (**Initializer**) from Sessions 2..N (**Incremental Workers**) bridged by four structured on-disk artifacts:

| Artifact | Purpose | Hard Rules |
|---|---|---|
| `feature_list.json` | Canonical machine-checked acceptance backlog (`id`, `category`, `steps`, `passes: false`) | **Use JSON, never Markdown**—models are significantly less likely to delete or rewrite JSON test definitions. Workers may flip `"passes": false -> true` only after E2E verification; harness diff-checks that no feature rows were removed or weakened. |
| `progress.md` | Concise chronological shift handoff (what changed, exact verification commands run, known blockers, next recommended feature) | Append-only per shift; read first on every worker startup. |
| `init.sh` | Idempotent bootstrap script (starts dev servers, runs baseline health/smoke test) | Executed at the start of every worker shift to confirm the repo is green *before* writing new code. |
| **Atomic Git Commits** | Recoverable filesystem checkpoints (`git commit` after each verified feature) | Never leave broken uncommitted edits across sessions; broken experiments revert cleanly via `git checkout` / `git reset`. |

### Worker Shift Startup Protocol (Deterministic Checklist)

Every fresh worker session begins with the exact same 5-step orienting sequence before picking **one** feature:

1. Run `pwd`, `git status`, and `git log -n 10 --oneline` to confirm workspace state.
2. Read `progress.md` and `feature_list.json` (filter `"passes": false`).
3. Execute `./init.sh` and run a fast end-to-end smoke check on already-passing features; if broken, fix the regression before starting new work.
4. Implement **at most one** failing feature cleanly, run end-to-end verification (unit + integration + browser/CLI E2E), and update `"passes": true` only after evidence passes.
5. Commit atomically with a descriptive message, append the shift note to `progress.md`, and leave `git status` clean.

### Python 3.11+ — Tamper-Resistant `feature_list.json` Guard

```python
from __future__ import annotations

from typing import Any


def validate_feature_list_update(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> None:
    """Reject worker edits that delete features or alter acceptance steps."""
    if len(before) != len(after):
        raise ValueError(f"Feature count changed ({len(before)} -> {len(after)}); deletion/addition forbidden.")
    for prev, curr in zip(before, after, strict=True):
        for immutable_key in ("id", "category", "description", "steps"):
            if prev.get(immutable_key) != curr.get(immutable_key):
                raise ValueError(
                    f"Immutable field '{immutable_key}' modified on feature '{prev.get('id')}'. "
                    "Only 'passes' may transition after verification."
                )
```

---

## 7. HITL 5-Decision `ApprovalPolicy` & Consecutive-Rejection Breaker

Safety boundaries must be enforced deterministically outside the LLM. Following Inspect AI's `ApprovalPolicy` and OWASP `ASI09`/`ASI10`:

### The 5 Approval Decisions

| Decision | Effect | Strict Implementation Invariants |
|---|---|---|
| `approve` | Execute tool call as proposed. | Log approver identity, policy rule ID, and argument hash. |
| `modify` | Execute tool call with sanitized/narrowed arguments. | **Must re-validate modified args against tool JSON schema.** Cannot change `tool_name` or `tool_call_id`. **Never mutate the original call object in place** (preserve original proposal in the session log). |
| `reject` | Do not execute; return clear corrective explanation as `tool/result` (`is_error=True`). | Increment `consecutive_rejections`; never silently swallow or erase the turn. |
| `escalate` | Forward to the next policy layer or human reviewer (`RUNNING -> WAITING_APPROVAL`). | Present a **deterministic plain-language risk diff** (target path, host, command, blast radius)—never rely solely on model-fabricated rationales (`ASI09`). Read-only previews must never trigger webhooks or mutations. |
| `terminate` | Immediately abort the agent run (`-> FAILED`). | Record terminal audit event; repair/close open spans. |

### The 3-Consecutive-Rejection Circuit Breaker

A prompt-injected or stuck model will repeatedly propose blocked actions (e.g., probing alternate paths to `~/.ssh` or bypassing an egress rule). Track `consecutive_rejections` across tool proposals:

- Reset `consecutive_rejections = 0` on any `approve` or `modify`.
- Increment `consecutive_rejections += 1` on every `reject`.
- At `consecutive_rejections >= 3` (Inspect AI default), automatically upgrade the decision to **`terminate`** (`ASI10` rogue-loop protection).

### Python 3.11+ — 5-Decision Approval Pipeline with 3-Rejection Breaker

```python
from __future__ import annotations

import asyncio
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal, Protocol

ApprovalDecisionKind = Literal["approve", "modify", "reject", "escalate", "terminate"]


@dataclass(frozen=True)
class ApprovalResult:
    decision: ApprovalDecisionKind
    reason: str
    modified_args: dict[str, Any] | None = None


class Approver(Protocol):
    async def evaluate(self, tool_name: str, call_id: str, args: dict[str, Any]) -> ApprovalResult: ...


class ApprovalPipeline:
    def __init__(
        self,
        approvers: list[Approver],
        schema_validator: Callable[[str, dict[str, Any]], None],
        max_consecutive_rejections: int = 3,
    ) -> None:
        self._approvers = approvers
        self._validate_schema = schema_validator
        self._max_rejections = max_consecutive_rejections
        self._consecutive_rejections = 0

    async def decide(
        self,
        tool_name: str,
        call_id: str,
        args: dict[str, Any],
        log: DurableSessionLog,
    ) -> ApprovalResult:
        # Work on a defensive copy so original model proposal stays immutable in audit logs.
        proposed_args = deepcopy(args)
        final: ApprovalResult = ApprovalResult("reject", "No approver accepted the tool call.")

        for approver in self._approvers:
            result = await approver.evaluate(tool_name, call_id, deepcopy(proposed_args))
            if result.decision == "escalate":
                continue
            if result.decision == "modify":
                if result.modified_args is None:
                    raise ValueError("Decision 'modify' requires 'modified_args'.")
                self._validate_schema(tool_name, result.modified_args)
            final = result
            break

        if final.decision in ("approve", "modify"):
            self._consecutive_rejections = 0
        elif final.decision == "reject":
            self._consecutive_rejections += 1
            if self._consecutive_rejections >= self._max_rejections:
                final = ApprovalResult(
                    decision="terminate",
                    reason=(
                        f"Consecutive rejection circuit breaker tripped "
                        f"({self._consecutive_rejections}/{self._max_rejections}): {final.reason}"
                    ),
                )

        await asyncio.to_thread(
            log.append,
            "approval/decision",
            {
                "tool_name": tool_name,
                "tool_call_id": call_id,
                "decision": final.decision,
                "reason": final.reason,
                "consecutive_rejections": self._consecutive_rejections,
                "modified": final.decision == "modify",
            },
        )
        return final
```

### TypeScript (strict ESM) — 5-Decision Approval Pipeline with 3-Rejection Breaker

```typescript
export type ApprovalDecision = "approve" | "modify" | "reject" | "escalate" | "terminate";

export interface ApprovalOutcome {
  readonly decision: ApprovalDecision;
  readonly reason: string;
  readonly modifiedArgs?: Record<string, unknown>;
}

export interface Approver {
  evaluate(
    toolName: string,
    callId: string,
    args: Readonly<Record<string, unknown>>,
  ): Promise<ApprovalOutcome>;
}

export class ApprovalPipeline {
  private consecutiveRejections = 0;
  private readonly approvers: readonly Approver[];
  private readonly validateArgs: (toolName: string, args: Record<string, unknown>) => void;
  private readonly maxConsecutiveRejections: number;

  constructor(
    approvers: readonly Approver[],
    validateArgs: (toolName: string, args: Record<string, unknown>) => void,
    maxConsecutiveRejections = 3,
  ) {
    this.approvers = approvers;
    this.validateArgs = validateArgs;
    this.maxConsecutiveRejections = maxConsecutiveRejections;
  }

  async decide(
    toolName: string,
    callId: string,
    args: Readonly<Record<string, unknown>>,
    log: DurableSessionLog,
  ): Promise<ApprovalOutcome> {
    let finalOutcome: ApprovalOutcome = {
      decision: "reject",
      reason: "Exhausted approval chain without explicit allow.",
    };

    for (const approver of this.approvers) {
      const snapshot = structuredClone(args);
      const outcome = await approver.evaluate(toolName, callId, snapshot);
      if (outcome.decision === "escalate") continue;
      if (outcome.decision === "modify") {
        if (!outcome.modifiedArgs) {
          throw new Error("Approval outcome 'modify' requires modifiedArgs.");
        }
        this.validateArgs(toolName, outcome.modifiedArgs);
      }
      finalOutcome = outcome;
      break;
    }

    if (finalOutcome.decision === "approve" || finalOutcome.decision === "modify") {
      this.consecutiveRejections = 0;
    } else if (finalOutcome.decision === "reject") {
      this.consecutiveRejections += 1;
      if (this.consecutiveRejections >= this.maxConsecutiveRejections) {
        finalOutcome = {
          decision: "terminate",
          reason: `Tripped ${this.maxConsecutiveRejections}-consecutive-rejection breaker: ${finalOutcome.reason}`,
        };
      }
    }

    await log.append("approval/decision", {
      toolName,
      toolCallId: callId,
      decision: finalOutcome.decision,
      reason: finalOutcome.reason,
      consecutiveRejections: this.consecutiveRejections,
    });
    return finalOutcome;
  }
}
```

---

## 8. Verification Checklist

- [ ] **Append-only durability:** Session log uses versioned `session.vN.jsonl` (or SQLite WAL) with `fsync` writes and pure `derive_messages()` projections.
- [ ] **Immutable migrations:** Schema upgrades run via adjacent `vN -> vN+1` migrators writing via temp-file + atomic rename; older generations are never overwritten.
- [ ] **Atomic stream settlement:** Streaming deltas (`partial=True`) never mutate durable state; failed/cancelled streams commit `assistant/attempt` (audit-only), not `assistant/message`.
- [ ] **Orphan tool repair:** Resuming an interrupted session synthesizes error `tool/result` records (`role="tool"`, never `role="user"`) for any unmatched `tool_call_id` in exact model order.
- [ ] **Explicit run state machine:** Only valid transitions between `RUNNING`, `WAITING_APPROVAL`, `COMPLETED`, `FAILED`, and `BUDGET_EXCEEDED` are accepted and logged.
- [ ] **Long-horizon handoff:** Multi-session tasks use tamper-checked `feature_list.json` (JSON over Markdown), `progress.md`, idempotent `init.sh`, and atomic git commits.
- [ ] **HITL policy & breaker:** All 5 decisions (`approve`/`modify`/`reject`/`escalate`/`terminate`) are enforced outside the LLM, `modify` re-validates schemas without in-place mutation, previews are side-effect-free, and 3 consecutive rejections terminate the run.
