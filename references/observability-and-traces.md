# Observability, OpenTelemetry GenAI Conventions, and Trace Replay

> **Core Principle:** You cannot hill-climb a harness you cannot inspect. Adopt the normative **OpenTelemetry GenAI Semantic Conventions** (`open-telemetry/semantic-conventions-genai`) for distributed telemetry, pair them with **append-only structured JSONL traces** for local debugging and keyless replay, and keep raw prompt/tool content **off by default**.

## Table of Contents

1. [Normative OpenTelemetry GenAI Span Hierarchy](#1-normative-opentelemetry-genai-span-hierarchy)
2. [Tool Execution Refinements (Transfers, Skills, Commands)](#2-tool-execution-refinements-transfers-skills-commands)
3. [Token Accounting, Events, and Normative Histogram Metrics](#3-token-accounting-events-and-normative-histogram-metrics)
4. [Privacy-by-Default Content Capture & External Storage Hooks](#4-privacy-by-default-content-capture--external-storage-hooks)
5. [Structured JSONL Traces & `validate_trace.py` Alignment](#5-structured-jsonl-traces--validate_tracepy-alignment)
6. [Keyless Recorded-Session Snapshot Replay](#6-keyless-recorded-session-snapshot-replay)
7. [Verification Checklist](#7-verification-checklist)

---

## 1. Normative OpenTelemetry GenAI Span Hierarchy

> **Spec Source:** GenAI conventions live in `open-telemetry/semantic-conventions-genai` (distinct from core `semantic-conventions`). GenAI-specific attributes are `Development`; `error.*`, `exception.*`, `server.*`, and `process.*` attributes are `Stable`/`RC`.

### Canonical Trace Tree

```text
invoke_agent <low_cardinality_agent_name>   [SpanKind.INTERNAL]
├── plan <agent_name>                       [SpanKind.INTERNAL] (optional, distinct planning phase)
│   └── chat <request_model>                [SpanKind.CLIENT]
├── chat <request_model>                    [SpanKind.CLIENT]   (covers logical call incl. retries)
├── execute_tool <tool_name>                [SpanKind.INTERNAL] (sibling of plan, child of invoke_agent)
│   └── invoke_agent <subagent_name>        [SpanKind.INTERNAL] (if agent-as-a-tool)
├── chat <request_model>                    [SpanKind.CLIENT]
└── event: gen_ai.evaluation.result         (parented to evaluated span)
```

### Normative Span Reference

| Logical Operation | `gen_ai.operation.name` | Normative Span Name | `SpanKind` | Required / Conditionally Required Attributes |
|---|---|---|---|---|
| **Create Agent** | `create_agent` | `create_agent {gen_ai.agent.name}` | `CLIENT` | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.agent.version`, `gen_ai.request.model`, `error.type` |
| **Invoke Agent** (LLM-driven) | `invoke_agent` | `invoke_agent {gen_ai.agent.name}` (or `invoke_agent`) | `INTERNAL` | `gen_ai.operation.name`, `gen_ai.agent.name` (**MUST be low cardinality**), `gen_ai.conversation.id` (only if real—**never fabricate a UUID/trace_id**), `gen_ai.request.model` (if single fixed model), `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.response.finish_reasons`, `error.type` |
| **Invoke Workflow** (code-driven) | `invoke_workflow` | `invoke_workflow {gen_ai.agent.name}` | `INTERNAL` | Same as `invoke_agent`; use when deterministic application code dictates control flow instead of the LLM. |
| **Plan** | `plan` | `plan {gen_ai.agent.name}` (or `plan`) | `INTERNAL` | `gen_ai.operation.name`, `gen_ai.agent.name`, `error.type`. Emit **only** when planning is structurally distinct from generic reasoning; executed tools remain siblings under `invoke_agent`. |
| **Model Inference** | `chat` / `generate_content` | `{op} {gen_ai.request.model}` | `CLIENT` | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.*`, `gen_ai.response.finish_reasons`, `error.type`. Covers logical operation **including automatic retries**. |
| **Execute Tool** | `execute_tool` | `execute_tool {gen_ai.tool.name}` | `INTERNAL` | `gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.tool.call.id` (only if provider-supplied), `gen_ai.tool.type` (`function` \| `extension` \| `datastore`), `gen_ai.agent.name`, `gen_ai.conversation.id`, `error.type`. |
| **Fetch Response** | `fetch_response` | `fetch_response` (no high-card ID) | `CLIENT` | `gen_ai.provider.name`, `gen_ai.response.id`, `gen_ai.response.status` (`queued`\|`in_progress`\|`completed`\|`incomplete`\|`failed`\|`cancelled`), `gen_ai.request.stream_cursor`. **MUST NOT** report token usage. |

### Strict Naming & Cardinality Laws

- **Low-cardinality `gen_ai.agent.name`:** Use stable logical names (`"triage_agent"`, `"coding_worker"`). Never put user IDs, session UUIDs, prompt text, or generic framework class names (`"StateGraph"`, `"AgentExecutor"`) into `gen_ai.agent.name` or span names.
- **Well-known `gen_ai.provider.name` values:** `anthropic`, `aws.bedrock`, `azure.ai.inference`, `azure.ai.openai`, `cohere`, `deepseek`, `gcp.gemini`, `gcp.gen_ai`, `gcp.vertex_ai`, `groq`, `ibm.watsonx.ai`, `mistral`, `moonshot_ai`, `ollama`, `openai`, `perplexity`, `x_ai`.
- **1:1 `gen_ai.response.finish_reasons` alignment:** Keep finish reasons aligned with returned choices; report `"error"` when cancelled, failed, or stream-truncated abnormally, and `"interrupted"` when interrupted without a provider finish reason. Always set `error.type` when span status is `ERROR`.

---

## 2. Tool Execution Refinements (Transfers, Skills, Commands)

The `execute_tool` span supports three normative refinements for modern agent harnesses:

| Refinement | Span Name Format | Additional Normative Attributes | Hygiene Rule |
|---|---|---|---|
| **Agent-as-a-Tool / Transfer** | `execute_tool {gen_ai.tool.name}` | `gen_ai.transfer.mode` (`return_to_caller` \| `pass_control`), `gen_ai.transfer.target.name` | Distinguish bounded subagent calls (`return_to_caller`) from full control handoffs (`pass_control`). |
| **Agent Skill Loading** | `execute_tool {tool} {skill}` or `execute_tool {tool} {skill} {resource}` | `gen_ai.skill.name`, `gen_ai.skill.resource.name`, `gen_ai.skill.description`, `gen_ai.skill.source.uri` | **Scrub query-param tokens/credentials** from `gen_ai.skill.source.uri` before recording. |
| **Command Execution** | `execute_tool {tool} {process.executable.name}` | `process.executable.name`, `process.exit.code`, `process.executable.path` | Record executable basename (e.g., `pytest`, `git`), never raw command lines containing secrets. |

---

## 3. Token Accounting, Events, and Normative Histogram Metrics

### Inclusive Token Accounting Invariants

Providers vary on whether cached input tokens and reasoning/thinking tokens are reported separately or nested. OTel GenAI enforces **inclusive totals** (checked automatically by `scripts/validate_trace.py`):

- **`gen_ai.usage.input_tokens` MUST include cached tokens** (`gen_ai.usage.cache_read.input_tokens`) and all modalities:
  $$\text{input\_tokens} \ge \text{cache\_read.input\_tokens} \ge 0$$
- **`gen_ai.usage.output_tokens` MUST include reasoning/thinking tokens** and all modalities:
  $$\text{output\_tokens} \ge \text{thinking\_tokens} \ge 0$$
- When a provider distinguishes **billed** vs. **consumed** tokens, record **billed** counts.

### Normative Events

| Event Name | Severity / Parenting | Required & Key Attributes |
|---|---|---|
| `gen_ai.evaluation.result` | Parented to evaluated `invoke_agent` or `chat` span | `gen_ai.evaluation.name` (**Required**), `gen_ai.evaluation.score.value`, `gen_ai.evaluation.score.label`, `gen_ai.evaluation.explanation`, `gen_ai.response.id` |
| `gen_ai.invoke_agent.exception` | `WARN` (13), correlated to `invoke_agent` span | `exception.type`, `exception.message` (redacted!), `exception.stacktrace` |
| `gen_ai.execute_tool.exception` | `WARN` (13), correlated to `execute_tool` span | `exception.type`, `exception.message` (redacted!), `exception.stacktrace` |

### Normative Histogram Metrics

| Metric Name | Instrument & Unit | Explicit Bucket Guidance & Counting Semantics |
|---|---|---|
| `gen_ai.invoke_agent.duration` | Histogram (`s`) | `[0.1 .. 86400]` — end-to-end wall time of an `invoke_agent` span. |
| `gen_ai.invoke_agent.inference_calls` | Histogram (`{inference_call}`) | `[1, 2, 4, 8, 16, 32, 64, 128]` — counts each logical inference **once** (excludes retries & nested subagent calls). |
| `gen_ai.invoke_agent.tool_calls` | Histogram (`{tool_call}`) | `[1, 2, 4, 8, 16, 32, 64, 128]` — client-side tools only (excludes provider server-side built-ins). |
| `gen_ai.execute_tool.duration` | Histogram (`s`) | `[0.01, 0.02, ..., 81.92]` — per-tool latency. |
| `gen_ai.server.time_to_first_token` | Histogram (`s`) | Streaming TTFT (detects KV-cache collapse immediately). |
| `gen_ai.server.time_per_output_token` | Histogram (`s`) | Decode throughput per generated token. |
| `gen_ai.server.request.duration` | Histogram (`s`) | Total inference request latency. |

---

## 4. Privacy-by-Default Content Capture & External Storage Hooks

**Never capture raw prompts, messages, or tool arguments/results in spans by default.** Gate all content emission behind the normative environment contract:

| Env Var | Allowed Values / Default | Required Behavior |
|---|---|---|
| `OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT` | `NO_CONTENT` **(default)** \| `SPAN_ONLY` \| `EVENT_ONLY` \| `SPAN_AND_EVENT` | **Unrecognized values MUST fall back to `NO_CONTENT`.** |
| `OTEL_INSTRUMENTATION_GENAI_CONTENT_HOOK` | Hook/uploader identifier | Offloads bulky/sensitive payloads to encrypted blob storage outside the telemetry backend. |
| `OTEL_INSTRUMENTATION_GENAI_UPLOAD_BASE_PATH` | Storage URI prefix (e.g., `s3://bucket/traces`) | Base location for uploaded content blobs. |
| `OTEL_INSTRUMENTATION_GENAI_UPLOAD_FORMAT` | `json` \| `jsonl` | Serialization format for offloaded content. |
| `OTEL_INSTRUMENTATION_GENAI_UPLOAD_MAX_QUEUE_SIZE` | Integer (default `20`) | Bounds background upload memory; drop or backpressure rather than OOMing the agent. |

When offloading content, attach **only credential-free URI references** on the span:

- `gen_ai.input.messages_ref`
- `gen_ai.output.messages_ref`
- `gen_ai.system_instructions_ref`
- `gen_ai.tool.definitions_ref`

**Hard rule:** Never embed pre-signed query tokens (`?X-Amz-Signature=...`, `?token=...`, `?sig=...`) or Basic Auth credentials inside any `*_ref` or `source.uri` attribute.

### Python 3.11+ — Privacy-Safe OTel-Aligned Content Policy & Span Emitter

```python
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

CaptureMode = Literal["NO_CONTENT", "SPAN_ONLY", "EVENT_ONLY", "SPAN_AND_EVENT"]
VALID_CAPTURE_MODES: frozenset[str] = frozenset({"NO_CONTENT", "SPAN_ONLY", "EVENT_ONLY", "SPAN_AND_EVENT"})
_CRED_QUERY_RE = re.compile(r"[?&](?:X-Amz-Signature|token|sig|api_key)=", re.IGNORECASE)


def resolve_capture_mode() -> CaptureMode:
    raw = os.environ.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT", "NO_CONTENT").strip().upper()
    if raw not in VALID_CAPTURE_MODES:
        return "NO_CONTENT"  # Normative fallback on unrecognized values.
    return raw  # type: ignore[return-value]


def assert_credential_free_ref(uri: str) -> str:
    if "@" in uri.split("://", 1)[-1].split("/", 1)[0] or _CRED_QUERY_RE.search(uri):
        raise ValueError("Refusing to record URI containing embedded or query-string credentials.")
    return uri


def assert_inclusive_tokens(tokens_in: int, tokens_cached: int, tokens_out: int, thinking_tokens: int) -> None:
    if not (tokens_in >= tokens_cached >= 0):
        raise ValueError(f"Inclusive input invariant violated: tokens_in={tokens_in} < tokens_cached={tokens_cached}")
    if not (tokens_out >= thinking_tokens >= 0):
        raise ValueError(f"Inclusive output invariant violated: tokens_out={tokens_out} < thinking={thinking_tokens}")


@dataclass
class JsonlTraceWriter:
    """Append-only OTel-aligned JSONL trace writer compatible with scripts/validate_trace.py."""

    path: Path
    trace_id: str
    agent_name: str  # Low-cardinality logical name (never a UUID).
    capture_mode: CaptureMode = field(default_factory=resolve_capture_mode)

    def emit(
        self,
        event_type: str,
        *,
        operation: str,
        attributes: dict[str, Any] | None = None,
        tokens_in: int | None = None,
        tokens_cached: int | None = None,
        tokens_out: int | None = None,
        thinking_tokens: int | None = None,
    ) -> dict[str, Any]:
        attrs = dict(attributes or {})
        attrs["gen_ai.operation.name"] = operation
        attrs["gen_ai.agent.name"] = self.agent_name

        # Strip raw content unless explicitly opted in.
        if self.capture_mode == "NO_CONTENT":
            for sensitive in (
                "gen_ai.input.messages",
                "gen_ai.output.messages",
                "gen_ai.tool.call.arguments",
                "gen_ai.tool.call.result",
            ):
                attrs.pop(sensitive, None)

        for ref_key in (
            "gen_ai.input.messages_ref",
            "gen_ai.output.messages_ref",
            "gen_ai.system_instructions_ref",
            "gen_ai.tool.definitions_ref",
            "gen_ai.skill.source.uri",
        ):
            if ref_key in attrs and isinstance(attrs[ref_key], str):
                assert_credential_free_ref(attrs[ref_key])

        record: dict[str, Any] = {
            "trace_id": self.trace_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "attributes": attrs,
        }
        if tokens_in is not None and tokens_out is not None:
            cached = tokens_cached or 0
            thinking = thinking_tokens or 0
            assert_inclusive_tokens(tokens_in, cached, tokens_out, thinking)
            record["tokens_in"] = tokens_in
            record["tokens_cached"] = cached
            record["tokens_out"] = tokens_out
            record["thinking_tokens"] = thinking

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        return record
```

### TypeScript (strict ESM) — OTel-Aligned JSONL Trace Emitter

```typescript
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export type CaptureMode = "NO_CONTENT" | "SPAN_ONLY" | "EVENT_ONLY" | "SPAN_AND_EVENT";

const VALID_MODES = new Set<CaptureMode>(["NO_CONTENT", "SPAN_ONLY", "EVENT_ONLY", "SPAN_AND_EVENT"]);
const CRED_QUERY_RE = /[?&](?:X-Amz-Signature|token|sig|api_key)=/i;

export function resolveCaptureMode(): CaptureMode {
  const raw = (process.env["OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT"] ?? "NO_CONTENT")
    .trim()
    .toUpperCase() as CaptureMode;
  return VALID_MODES.has(raw) ? raw : "NO_CONTENT";
}

export interface TraceRecord {
  readonly trace_id: string;
  readonly timestamp: string;
  readonly event_type: string;
  readonly attributes: Record<string, unknown>;
  readonly tokens_in?: number;
  readonly tokens_cached?: number;
  readonly tokens_out?: number;
  readonly thinking_tokens?: number;
}

export class JsonlTraceWriter {
  private readonly captureMode: CaptureMode;

  constructor(
    private readonly filePath: string,
    private readonly traceId: string,
    private readonly agentName: string,
  ) {
    this.captureMode = resolveCaptureMode();
  }

  async emit(
    eventType: string,
    operation: string,
    rawAttributes: Record<string, unknown> = {},
    tokens?: { in: number; cached?: number; out: number; thinking?: number },
  ): Promise<TraceRecord> {
    const attributes: Record<string, unknown> = {
      ...rawAttributes,
      "gen_ai.operation.name": operation,
      "gen_ai.agent.name": this.agentName,
    };

    if (this.captureMode === "NO_CONTENT") {
      delete attributes["gen_ai.input.messages"];
      delete attributes["gen_ai.output.messages"];
      delete attributes["gen_ai.tool.call.arguments"];
      delete attributes["gen_ai.tool.call.result"];
    }

    for (const key of [
      "gen_ai.input.messages_ref",
      "gen_ai.output.messages_ref",
      "gen_ai.system_instructions_ref",
      "gen_ai.tool.definitions_ref",
      "gen_ai.skill.source.uri",
    ]) {
      const val = attributes[key];
      if (typeof val === "string" && CRED_QUERY_RE.test(val)) {
        throw new Error(`Attribute ${key} contains forbidden query-string credentials.`);
      }
    }

    if (tokens) {
      const cached = tokens.cached ?? 0;
      const thinking = tokens.thinking ?? 0;
      if (tokens.in < cached || cached < 0 || tokens.out < thinking || thinking < 0) {
        throw new Error("Inclusive OTel token accounting invariant violated.");
      }
    }

    const record: TraceRecord = {
      trace_id: this.traceId,
      timestamp: new Date().toISOString(),
      event_type: eventType,
      attributes,
      ...(tokens
        ? {
            tokens_in: tokens.in,
            tokens_cached: tokens.cached ?? 0,
            tokens_out: tokens.out,
            thinking_tokens: tokens.thinking ?? 0,
          }
        : {}),
    };

    await mkdir(dirname(this.filePath), { recursive: true });
    await appendFile(this.filePath, `${JSON.stringify(record)}\n`, "utf8");
    return record;
  }
}
```

---

## 5. Structured JSONL Traces & `validate_trace.py` Alignment

Every runtime harness should emit an append-only `.jsonl` trace file per run so engineers and CI can inspect failures offline using `scripts/validate_trace.py`:

```bash
python -B scripts/validate_trace.py path/to/trace.jsonl --mode trace --strict --max-tool-chars 50000
```

### Trace Invariants Verified by `validate_trace.py`

| Check | Severity | Exact Condition Verified | Root Harness Defect Diagnosed |
|---|---|---|---|
| **JSONL & Required Fields** | `ERROR` | Valid JSON per line; `trace_id` (or `session_id`), `timestamp`, and `event_type` present; monotonic ISO-8601 timestamps. | Corrupted concurrent writes or unsorted buffering. |
| **Inclusive Token Invariants** | `ERROR` | `tokens_in >= tokens_cached >= 0` and `tokens_out >= thinking_tokens >= 0`. | Double-counting or provider adapter mis-mapping. |
| **KV-Cache Hit Regression** | `WARN` | Multi-turn trace (`>= 4` model turns) reports `tokens_cached == 0` on turns `2..N` while `tokens_in > 0`. | Dynamic timestamp/UUID in system prompt, unsorted tool JSON (`AH010`), or mid-loop `effort`/`budget_tokens` mutation (10x input cost spike). |
| **Orphan Tool Calls** | `ERROR` | Every `tool_call` ID has a matching `tool_result` ID in the trace. | Swallowed tool crash or missing startup repair. |
| **Doom-Loop Repeats** | `WARN`/`ERROR` | `>= 3` consecutive identical `(tool_name, args)` invocations. | Missing repeat-tool guard (`repeat-tool-reminder`) or opaque tool error messages. |
| **Tool Output Flood** | `WARN` | Any single `tool_result` exceeds `--max-tool-chars` (default `50000`). | Missing output truncation / disk spill (`AH012`). |
| **Secret Leak Scan** | `ERROR` | Matches `sk-`, `sk-ant-`, `AIza`, `AKIA[0-9A-Z]{16}`, `ghp_`, PEM private keys, `Bearer ...`, `?X-Amz-Signature=`, `?token=`. | Missing redaction filter or credentials inside sandbox (`AH005`). |
| **Lethal Trifecta Exfil** | `ERROR` | Untrusted external fetch -> sensitive path (`~/.ssh`, `.env`, `mcp.json`) -> outbound send/post in same trace. | Active prompt-injection exfiltration chain. |
| **Unverified Completion** | `WARN` | File/state mutation followed by final completion with zero subsequent verification tool calls. | Missing pre-completion verification gate. |

---

## 6. Keyless Recorded-Session Snapshot Replay

Testing harness changes (compaction rules, approval policies, tool wrappers, message projections) against live LLM APIs is slow, flaky, and expensive. Following **DeepSeek Harness (`dsh`)** and **OWASP `ASI08` digital-twin replay**:

1. **Record sanitized golden sessions** as immutable JSONL fixtures (with `assistant/message` responses, tool calls, tool results, and synthetic timings—zero API keys, zero live secrets).
2. **Swap `ctx.llm` for a deterministic `ReplayProvider`** that asserts the incoming derived prompt/tool payload matches the recorded snapshot (or validates prefix hash invariance!) and returns the recorded assistant turn.
3. **Run in CI with zero network access and zero API keys:** Catches prompt-cache prefix regressions, compaction bugs, orphan tool-result regressions, and approval-policy expansion risks (`ASI08`) in milliseconds.

### Python 3.11+ — Keyless Recorded-Session Replay Provider

```python
import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass
class RecordedTurn:
    expected_prefix_sha256: str
    assistant_response: dict[str, Any]


class KeylessReplayProvider:
    """Deterministic offline LLM provider replaying recorded session fixtures."""

    def __init__(self, turns: list[RecordedTurn]) -> None:
        self._turns = list(turns)
        self._cursor = 0

    @staticmethod
    def hash_prefix(system_prompt: str, tools: list[dict[str, Any]]) -> str:
        canonical = json.dumps({"system": system_prompt, "tools": tools}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def complete(
        self,
        *,
        system_prompt: str,
        tools: list[dict[str, Any]],
        messages: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if self._cursor >= len(self._turns):
            raise AssertionError(f"Replay exhausted: unexpected extra model turn #{self._cursor + 1}.")
        turn = self._turns[self._cursor]
        actual_hash = self.hash_prefix(system_prompt, tools)
        if actual_hash != turn.expected_prefix_sha256:
            raise AssertionError(
                f"KV-cache prefix drift on replay turn {self._cursor + 1}: "
                f"expected {turn.expected_prefix_sha256[:12]}, got {actual_hash[:12]}"
            )
        self._cursor += 1
        return turn.assistant_response
```

---

## 7. Verification Checklist

- [ ] **Normative OTel spans:** `invoke_agent` / `invoke_workflow` (`INTERNAL`), `plan` (`INTERNAL` when distinct), `chat` (`CLIENT`, wrapping retries), `execute_tool` (`INTERNAL`) with transfer/skill/command refinements.
- [ ] **Low-cardinality names:** `gen_ai.agent.name` and span names contain zero UUIDs, prompts, or generic framework class names; `gen_ai.conversation.id` is never fabricated.
- [ ] **Inclusive token accounting:** `input_tokens >= cache_read.input_tokens >= 0` and `output_tokens >= thinking_tokens >= 0` enforced in telemetry writers.
- [ ] **Privacy by default:** `OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT` defaults to `NO_CONTENT` (invalid values fall back to `NO_CONTENT`); all `*_ref` and `source.uri` values are verified credential-free.
- [ ] **Normative metrics & events:** Agent duration, inference calls (excluding retries), client tool calls, tool duration, TTFT, and `gen_ai.evaluation.result` emitted accurately.
- [ ] **JSONL trace hygiene:** Every trace passes `python -B scripts/validate_trace.py <trace.jsonl> --mode trace --strict`.
- [ ] **Keyless CI replay:** Critical compaction, prefix-caching, and policy regressions are covered by offline recorded-session snapshot tests.
