# Harness Architecture: Decoupling Brain, Session, and Hands

A production agent is the joint system $\text{Agent} = \text{Model} + \text{Harness}$. The model provides reasoning; the harness provides the deterministic operating system around it—turn orchestration, durable state, context projection, tool execution boundaries, and verifiable feedback.

## Table of Contents

1. [The OS Metaphor and Inner vs. Outer Harness](#1-the-os-metaphor-and-inner-vs-outer-harness)
2. [Three-Way Decoupling: Brain, Session, and Hands](#2-three-way-decoupling-brain-session-and-hands)
3. [Production Architecture Comparison](#3-production-architecture-comparison)
4. [The `Model-visible ⟺ logged` Invariant and Pure Projections](#4-the-model-visible--logged-invariant-and-pure-projections)
5. [Thin Provider and Execution Seams (Python + TypeScript)](#5-thin-provider-and-execution-seams-python--typescript)
6. [Frameworks vs. Runtimes vs. Harnesses (Avoiding Framework Tax)](#6-frameworks-vs-runtimes-vs-harnesses-avoiding-framework-tax)
7. [Architecture Review Checklist](#7-architecture-review-checklist)

---

## 1. The OS Metaphor and Inner vs. Outer Harness

Mapping the agent runtime onto operating-system primitives clarifies which responsibilities belong to model weights and which belong to deterministic code:

| OS Layer | Agent Equivalent | Engineering Responsibility |
|---|---|---|
| **CPU** | **Model (LLM)** | Token generation, planning, tool selection, synthesis. Stateless across calls. |
| **RAM** | **Context Window** | Finite, volatile working memory subject to $O(n^2)$ attention decay (*Context Rot*). |
| **Operating System** | **Agent Harness** | Boot sequence, prompt assembly, tool drivers, memory/compaction, budgets, sandboxing, crash recovery. |
| **Application** | **Agent (Domain Task)** | User goal, domain prompts, specialized skills, and acceptance criteria. |

Production engineering teams further separate two concentric control layers:

- **Inner Harness (Runtime Loop):** The deterministic execution engine wrapping the model—provider adapter, append-only session store, context compaction, tool dispatch, permission policy, and execution sandbox.
- **Outer Harness (Environment / Codebase Harness):** The cybernetic governor built around the workspace itself—combining **Guides** (*feedforward controls* steering behavior before action: ~100-line `AGENTS.md` map, schemas, architectural specs, skills) and **Sensors** (*feedback controls* verifying after action: compilers, test suites, structural linters, browser/CDP checks, observability queries).

---

## 2. Three-Way Decoupling: Brain, Session, and Hands

Early prototypes coupled the LLM loop, conversation memory, and shell execution inside a single container process. When the container crashed, state vanished; when a task needed no sandbox on turn 1, provisioning still blocked time-to-first-token (TTFT); when secrets lived in environment variables, prompt injection leaked them directly from agent-executed code.

Modern production harnesses (Anthropic Managed Agents, DeepSeek Harness `dsh`, OpenHands SDK, Google ADK) converge on **three independently replaceable, virtualized interfaces**:

```text
┌──────────────────────────────────────────────────────────────────────┐
│                         SESSION (Append-Only Log)                    │
│  Canonical source of truth OUTSIDE context window & sandbox          │
│  emit_event(event) / get_events(range) -> immutable JSONL / SQLite   │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ pure projection: derive_messages(events)
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      BRAIN / HARNESS (Stateless Loop)                │
│  wake(session_id) -> assemble prefix -> call LLM -> settle -> route  │
│  Swappable middleware: budgets, compaction, spill, guards, approvals │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ uniform seam: execute(name, input) -> str
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   HANDS (Isolated Execution Sandbox)                 │
│  Lazy-provisioned OS sandbox (bwrap/Seatbelt/ACL) or Container/VM    │
│  ZERO raw credentials inside sandbox (external vault + host proxy)   │
└──────────────────────────────────────────────────────────────────────┘
```

### Key Decoupling Wins (Verified in Production)

1. **Anthropic Managed Agents (`Session / Harness / Sandbox`):**
   - **Session:** External append-only event log (`getSession`, `emitEvent`, `getEvents` with positional slicing). Because raw events live outside the context window, compaction and trimming remain **reversible** and harness crashes recover via stateless `wake(sessionId)`.
   - **Hands:** Uniform tool seam (`execute(name, input) -> string`) with **lazy sandbox provisioning**—containers spin up only when a sandbox tool is first invoked, cutting **p50 TTFT by ~60%** and **p95 TTFT by >90%**.
   - **Zero-Credential Sandbox:** Git remotes are pre-wired at init, and MCP OAuth tokens reside in an external vault accessed through a session-scoped host proxy so neither generated code nor the harness reads raw secrets.

2. **DeepSeek Harness (`dsh`) — Everything-is-a-Plugin & 3-Role Capability Seams:**
   - Built on the Cordis plugin kernel with **no privileged monolithic core**: `ctx.llm`, `ctx.sessions`, `ctx.systemPrompt`, `ctx.tools`, `ctx.sandbox`, and even `ctx.agentLoop` are reversible plugins whose registrations unwind cleanly on unload.
   - Every swappable subsystem splits cleanly into **three roles**:
     1. **Service Definition** — contract and types only (zero runtime implementation).
     2. **Service Provider** — concrete backend implementation (e.g., local filesystem vs. remote container).
     3. **Consumer** — model-facing tools or policies consuming the contract.
   - Because `ctx.fs` and `ctx.subprocess` share one execution world behind a seam, swapping them to a remote sandbox automatically moves Bash, PTY, and LSP tools together with zero tool forks.
   - Three distinct event domains keep concerns decoupled:
     - **Session events (`session/event`):** Durable, replayable facts (`turn/*`, `step/*`, `system/message`, `user/message`, `assistant/message`, `assistant/attempt`, `tool/call`, `tool/result`).
     - **Agent events (`agent/*`):** In-flight control-plane waterfalls (`agent/pre-step`, `agent/request`, `agent/request-error`, serial `agent/turn-stopping`) plus transient UI frames (`agent/assistant-stream`).
     - **Capability events (`tools/*`, `fs/*`, `telemetry/*`):** Guardrails, spill policies, and timeouts attached to tool/FS seams without ever importing the agent loop.

3. **OpenHands & `mini-swe-agent` — Spectrum of Coupling:**
   - **OpenHands SDK** splits into 4 packages (`sdk`, `tools`, `workspace`, `agent_server`) so identical agent code moves from `LocalWorkspace` to `DockerWorkspace` / `RemoteAPIWorkspace` by swapping one object.
   - **`mini-swe-agent`** represents the opposite minimalist pole: ~100 LOC Python, stateless per-command `subprocess.run` (no fragile persistent shell state), linear 1:1 message history. Useful as a clean baseline and RL/benchmark scaffold, then layered with durable logging and policy seams for production.

---

## 3. Production Architecture Comparison

| System | Orchestration Model | State & History Store | Context / Compaction | Execution Boundary ("Hands") | Primary Tradeoff |
|---|---|---|---|---|---|
| **Anthropic Managed Agents** | Stateless `wake(sessionId)` loop | External append-only `Session` log (`getEvents` slices) | Reversible projection + clearing + summary / resets | Lazy cattle containers + external credential vault/proxy | Maximum crash recovery & multi-tenant safety; higher infra setup. |
| **DeepSeek Harness (`dsh`)** | Cordis all-plugin waterfalls (`ctx.agentLoop`) | Immutable versioned `session.vN.jsonl[.zstd]` / SQLite | `spill-policy` → tool-result pruner → `compaction-basic` | Host-native OS (`bwrap`/Landlock, Seatbelt, Win ACL) or swapped `ctx.fs`+`ctx.subprocess` | Cleanest modular plugin/profile layering (`sdk-minimal` to `web`); requires disciplined seam contracts. |
| **OpenAI Codex** | Stateless HTTP SSE over Responses API | Client-owned `input[]` + ZDR `encrypted_content` | Strict prefix invariance + `/responses/compact` | Host-native OS (`bwrap`+`seccomp`, Seatbelt, Win MXC) + post-allow DNS egress proxy | Preserves local toolchains (Xcode, local SDKs) with ZDR; host-dependent isolation. |
| **Google ADK** | Cooperative yield/pause/resume `Runner` | `SessionService` events + `state_delta` + `ArtifactService` | Context compression + external artifacts + `temp:` scope | Action confirmations, thread-pool sync-I/O offloading, Cloud Run/GKE | Strict atomic streaming commits (`partial=True` never mutates state); framework conventions. |
| **OpenHands SDK** | Typed `Action → Executor → Observation` loop | Typed `Event` stream + `Conversation` + Secret Registry | Pluggable `Condenser` + trigger-activated `Skill`s | `LocalWorkspace` / `DockerWorkspace` / `RemoteAPIWorkspace` | Clean local-to-container portability; tools co-located inside container server. |
| **`mini-swe-agent`** | Linear ReAct loop (~100 LOC Python) | Linear 1:1 trajectory & message array | Pure linear append | Stateless per-command Docker/Podman/Bubblewrap `exec` | Zero framework overhead, ideal baseline/eval scaffold; lacks built-in long-horizon durability. |

---

## 4. The `Model-visible ⟺ logged` Invariant and Pure Projections

A core production invariant from DeepSeek Harness (`dsh`) and Anthropic Managed Agents is:

> **Every token sent to the model must be reconstructable solely by running a pure function `derive_messages(events)` over the append-only session log.**

Why this invariant prevents an entire class of production bugs:

1. **Compaction becomes reversible:** Dropping stale tool outputs or summarizing turns writes a `compaction/checkpoint` event rather than deleting history. Auditing, debugging, and replay always see ground truth.
2. **Crash recovery is trivial:** Restarting a dead worker reads the log tail, runs `derive_messages(events)`, repairs any dangling `tool/call` without a matching `tool/result`, and resumes cleanly.
3. **Transient streaming never corrupts state:** Streaming token deltas (`partial=True` in ADK; `agent/assistant-stream` in `dsh`) go straight to the UI/transport. Only the **settled** turn commits to the durable log—as `assistant/message` on success, or `assistant/attempt` on network/stream failure/cancellation (keeping failures auditable without polluting model context).
4. **Keyless deterministic replay:** Recorded session logs can be replayed through updated prompt assemblers, compaction policies, or profile configs in CI without spending API tokens.

### Python 3.11+ — Append-Only Event Log & Pure `derive_messages()`

```python
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

EventKind = Literal[
    "system_message",
    "user_message",
    "assistant_message",
    "assistant_attempt",  # failed/cancelled stream: logged for audit, excluded from model view
    "tool_result",
    "compaction_checkpoint",
]


@dataclass(frozen=True, slots=True)
class SessionEvent:
    seq: int
    kind: EventKind
    timestamp: str
    payload: dict[str, Any]


class AppendOnlySessionLog:
    """Durable JSONL session log outside the volatile LLM context window."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = self._count_existing()

    def _count_existing(self) -> int:
        if not self._path.exists():
            return 0
        with self._path.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    def append(self, kind: EventKind, payload: dict[str, Any]) -> SessionEvent:
        self._seq += 1
        event = SessionEvent(
            seq=self._seq,
            kind=kind,
            timestamp=datetime.now(timezone.utc).isoformat(),
            payload=payload,
        )
        # Deterministic key order guarantees stable serialization & replay hashes.
        line = json.dumps(asdict(event), sort_keys=True, ensure_ascii=False)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
        return event

    def read_all(self) -> list[SessionEvent]:
        if not self._path.exists():
            return []
        events: list[SessionEvent] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    events.append(SessionEvent(**json.loads(line)))
        return events


def derive_messages(events: list[SessionEvent]) -> list[dict[str, Any]]:
    """Pure projection from durable events to the model-visible message array.

    - Rebuilds from the latest compaction checkpoint if present.
    - Excludes failed/cancelled `assistant_attempt` audit records.
    - Preserves `reasoning_content` / `thinking` verbatim on assistant messages.
    - Emits synthetic error `tool` messages for any orphan tool calls after a crash.
    """
    start_idx = 0
    latest_system: dict[str, Any] | None = None
    for idx, ev in enumerate(events):
        if ev.kind == "system_message":
            latest_system = {"role": "system", "content": ev.payload["content"]}
        elif ev.kind == "compaction_checkpoint":
            start_idx = idx

    messages: list[dict[str, Any]] = []
    if latest_system is not None:
        messages.append(latest_system)

    pending_call_ids: list[str] = []
    for ev in events[start_idx:]:
        if ev.kind == "compaction_checkpoint":
            messages.append({"role": "user", "content": ev.payload["summary_prompt"]})
        elif ev.kind == "user_message":
            messages.append({"role": "user", "content": ev.payload["content"]})
        elif ev.kind == "assistant_message":
            msg: dict[str, Any] = {"role": "assistant", "content": ev.payload.get("content", "")}
            if "reasoning_content" in ev.payload and ev.payload["reasoning_content"] is not None:
                msg["reasoning_content"] = ev.payload["reasoning_content"]
            if ev.payload.get("tool_calls"):
                msg["tool_calls"] = ev.payload["tool_calls"]
                pending_call_ids = [tc["id"] for tc in ev.payload["tool_calls"]]
            messages.append(msg)
        elif ev.kind == "tool_result":
            call_id = ev.payload["tool_call_id"]
            if call_id in pending_call_ids:
                pending_call_ids.remove(call_id)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": ev.payload["content"],
                }
            )
        # `assistant_attempt` is intentionally ignored in the model projection.

    # Crash recovery: repair orphan tool_calls so the next API call never HTTP-400s.
    for orphan_id in pending_call_ids:
        messages.append(
            {
                "role": "tool",
                "tool_call_id": orphan_id,
                "content": "[ERROR: Harness terminated before tool execution settled. Re-verify state.]",
            }
        )
    return messages
```

### TypeScript (Strict ESM) — Append-Only Event Log & Pure `deriveMessages()`

```ts
import { appendFile, readFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export type EventKind =
  | "system_message"
  | "user_message"
  | "assistant_message"
  | "assistant_attempt"
  | "tool_result"
  | "compaction_checkpoint";

export interface SessionEvent<TPayload extends Record<string, unknown> = Record<string, unknown>> {
  readonly seq: number;
  readonly kind: EventKind;
  readonly timestamp: string;
  readonly payload: TPayload;
}

export interface ModelMessage {
  readonly role: "system" | "user" | "assistant" | "tool";
  readonly content: string;
  readonly reasoning_content?: string;
  readonly tool_calls?: ReadonlyArray<{ id: string; name: string; argumentsJson: string }>;
  readonly tool_call_id?: string;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

export class AppendOnlySessionLog {
  private seq = 0;
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  async init(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    try {
      const raw = await readFile(this.path, "utf8");
      this.seq = raw.split("\n").filter((l) => l.trim().length > 0).length;
    } catch {
      this.seq = 0;
    }
  }

  async append<T extends Record<string, unknown>>(kind: EventKind, payload: T): Promise<SessionEvent<T>> {
    this.seq += 1;
    const event: SessionEvent<T> = {
      seq: this.seq,
      kind,
      timestamp: new Date().toISOString(),
      payload,
    };
    await appendFile(this.path, `${stableStringify(event)}\n`, "utf8");
    return event;
  }

  async readAll(): Promise<SessionEvent[]> {
    try {
      const raw = await readFile(this.path, "utf8");
      return raw
        .split("\n")
        .filter((l) => l.trim().length > 0)
        .map((line) => JSON.parse(line) as SessionEvent);
    } catch {
      return [];
    }
  }
}

export function deriveMessages(events: readonly SessionEvent[]): ModelMessage[] {
  let startIdx = 0;
  let latestSystem: ModelMessage | undefined;

  for (let i = 0; i < events.length; i += 1) {
    const ev = events[i];
    if (ev.kind === "system_message") {
      latestSystem = { role: "system", content: String(ev.payload.content ?? "") };
    } else if (ev.kind === "compaction_checkpoint") {
      startIdx = i;
    }
  }

  const messages: ModelMessage[] = latestSystem ? [latestSystem] : [];
  const pendingCallIds = new Set<string>();

  for (let i = startIdx; i < events.length; i += 1) {
    const ev = events[i];
    if (ev.kind === "compaction_checkpoint") {
      messages.push({ role: "user", content: String(ev.payload.summary_prompt ?? "") });
    } else if (ev.kind === "user_message") {
      messages.push({ role: "user", content: String(ev.payload.content ?? "") });
    } else if (ev.kind === "assistant_message") {
      const toolCalls = ev.payload.tool_calls as ModelMessage["tool_calls"];
      if (toolCalls) {
        for (const tc of toolCalls) pendingCallIds.add(tc.id);
      }
      messages.push({
        role: "assistant",
        content: String(ev.payload.content ?? ""),
        ...(typeof ev.payload.reasoning_content === "string"
          ? { reasoning_content: ev.payload.reasoning_content }
          : {}),
        ...(toolCalls && toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
      });
    } else if (ev.kind === "tool_result") {
      const callId = String(ev.payload.tool_call_id ?? "");
      pendingCallIds.delete(callId);
      messages.push({
        role: "tool",
        tool_call_id: callId,
        content: String(ev.payload.content ?? ""),
      });
    }
  }

  for (const orphanId of pendingCallIds) {
    messages.push({
      role: "tool",
      tool_call_id: orphanId,
      content: "[ERROR: Harness terminated before tool execution settled. Re-verify state.]",
    });
  }
  return messages;
}
```

---

## 5. Thin Provider and Execution Seams (Python + TypeScript)

Keep the provider seam **thin, typed, and lossless**:

- **Never hide raw request/response fields** required for caching or reasoning continuity (`reasoning_content`, `thinking` + `signature`, `encrypted_content`, `cache_read_input_tokens`, `cache_creation_input_tokens`).
- **Keep wire-extension telemetry strictly out-of-band** (like DeepSeek `dsh`'s `dsh_plugin_packages`, `dsh_session_log`, and `x-deepseek-harness-*` headers): metadata must never mutate `messages`, system prompts, or tool schemas.
- **Separate `LLMProvider` (Brain I/O) from `ExecutionHands` (Tool/Sandbox I/O)** so tests inject deterministic scripted providers without mocks or API keys.

### Python 3.11+ — `Protocol` Seams

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Literal, Protocol


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0
    thinking_tokens: int = 0


@dataclass(frozen=True, slots=True)
class ModelResponse:
    content: str
    tool_calls: tuple[ToolCall, ...] = ()
    reasoning_content: str | None = None
    opaque_reasoning_blocks: tuple[dict[str, Any], ...] = ()  # Claude signature / OpenAI encrypted_content
    finish_reason: Literal["stop", "tool_calls", "length", "error"] = "stop"
    usage: TokenUsage = field(default_factory=lambda: TokenUsage(0, 0))


@dataclass(frozen=True, slots=True)
class StreamDelta:
    kind: Literal["text", "thinking", "tool_call_delta", "settled"]
    text: str = ""
    response: ModelResponse | None = None


class LLMProvider(Protocol):
    """Thin provider-neutral seam. Implementations preserve provider reasoning & cache tokens."""

    async def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        timeout_s: float,
        reasoning_effort: Literal["low", "medium", "high", "xhigh"] | None = None,
    ) -> ModelResponse: ...

    def stream(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        timeout_s: float,
    ) -> AsyncIterator[StreamDelta]: ...


class ExecutionHands(Protocol):
    """Uniform sandbox/tool seam decoupling the loop from local OS, Docker, or remote microVMs."""

    async def execute(self, name: str, arguments: dict[str, Any], *, timeout_s: float) -> str: ...
    async def close(self) -> None: ...
```

### TypeScript (Strict ESM) — `interface` Seams

```ts
export interface ToolCall {
  readonly id: string;
  readonly name: string;
  readonly arguments: Record<string, unknown>;
}

export interface TokenUsage {
  readonly inputTokens: number;
  readonly outputTokens: number;
  readonly cachedInputTokens: number;
  readonly cacheWriteTokens: number;
  readonly thinkingTokens: number;
}

export interface ModelResponse {
  readonly content: string;
  readonly toolCalls: readonly ToolCall[];
  readonly reasoningContent?: string;
  readonly opaqueReasoningBlocks?: readonly Record<string, unknown>[];
  readonly finishReason: "stop" | "tool_calls" | "length" | "error";
  readonly usage: TokenUsage;
}

export type StreamDelta =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "thinking"; readonly text: string }
  | { readonly kind: "settled"; readonly response: ModelResponse };

export interface CompletionRequest {
  readonly model: string;
  readonly messages: readonly Record<string, unknown>[];
  readonly tools: readonly Record<string, unknown>[];
  readonly maxTokens: number;
  readonly signal: AbortSignal;
  readonly reasoningEffort?: "low" | "medium" | "high" | "xhigh";
}

export interface LLMProvider {
  complete(req: CompletionRequest): Promise<ModelResponse>;
  stream(req: CompletionRequest): AsyncIterable<StreamDelta>;
}

export interface ExecutionHands {
  execute(name: string, args: Record<string, unknown>, signal: AbortSignal): Promise<string>;
  close(): Promise<void>;
}
```

---

## 6. Frameworks vs. Runtimes vs. Harnesses (Avoiding Framework Tax)

Distinguish the three layers of the agent stack before adding a dependency:

1. **Agent Framework** (e.g., LangChain, Vercel AI SDK, CrewAI, Google ADK, OpenAI Agents SDK): Libraries of reusable abstractions—content blocks, provider adapters, tool wrappers, middleware hooks.
2. **Agent Runtime** (e.g., LangGraph, Temporal, Inngest): Durable execution infrastructure providing crash recovery, queues, streaming, persistence, and human-in-the-loop interrupts.
3. **Agent Harness** (e.g., Claude Code, Codex CLI, DeepSeek `dsh`, DeepAgents, or your bespoke ~200-LOC loop): The opinionated operational system combining prompts, ACI tools, context lifecycle, sandbox boundaries, and verification sensors.

### When to Avoid Monolithic Frameworks

Across Anthropic (*Building Effective Agents*), OpenAI (*Harness Engineering*), and Manus (5 full harness rewrites in 6 months), production teams report the same **framework tax** failure modes:

- **Obscured raw payloads:** Engineers cannot inspect the exact serialized `messages` and `tools` JSON sent on turn $N$, making prompt-cache misses, reasoning-block drops, and schema bugs invisible.
- **Hidden error rewriting & retry layers:** Framework defaults silently swallow or reformat tool errors, or stack hidden retries on top of SDK retries (triggering $r^d$ retry storms).
- **Resistance to deletion:** Every model generation renders prior scaffolding obsolete. OpenAI explicitly favored small in-repo implementations over opaque upstream libraries so agents and engineers could reason about and delete layers cleanly.

**Practical rule:** Start directly on the provider SDK + a ~150–300 LOC loop you own. Adopt a **Runtime** (Temporal, LangGraph, SQLite/JSONL queue) when you need distributed durability, or a **Meta-Harness** with open virtualized seams (like Managed Agents or Cordis-style plugins)—never a black-box framework that hides your prompts, tool schemas, or error handling.

---

## 7. Architecture Review Checklist

- [ ] **Session decoupled from context:** Does an append-only durable log hold canonical history outside the context window and sandbox?
- [ ] **`Model-visible ⟺ logged` enforced:** Can you reconstruct any turn's exact model request via a pure `derive_messages()` projection?
- [ ] **Atomic settlement:** Are streaming UI deltas strictly separated from durable state commits, with failed/cancelled calls logged separately (`assistant_attempt`)?
- [ ] **Orphan repair:** Does restart/recovery synthesize explicit error `tool_result`s for any dangling `tool_call`s?
- [ ] **Uniform, lazy Hands:** Are tools and sandboxes hidden behind a uniform seam (`execute(name, args)`) provisioned lazily on first need?
- [ ] **Zero credentials in sandbox:** Do API tokens, Git signing keys, and OAuth secrets stay in a host vault/proxy outside the execution environment?
- [ ] **Thin provider seam:** Can you swap models/providers and inspect raw serialized turn-$N$ payloads in <20 LOC without fighting a framework?
- [ ] **Deletable hooks:** Are middleware guards (loop detection, compaction, verification, profiles) attached via clean seams so any obsolete crutch can be removed in one config toggle?
