# Context Engineering, KV-Cache Invariance, Reasoning Retention & Memory Hygiene

The context window is a finite **attention budget**, not an infinite append buffer. Because multi-turn agents operate at roughly a **100:1 input-to-output token ratio** across ~50 tool calls per task (Manus), context architecture dominates accuracy, latency, and unit economics.

## Table of Contents

1. [Attention Budget, Context Rot & Breunig's 4 Failure Modes](#1-attention-budget-context-rot--breunigs-4-failure-modes)
2. [KV-Cache Prefix Invariance (10× Cost Engineering)](#2-kv-cache-prefix-invariance-10-cost-engineering)
3. [Reasoning and Thinking Block Retention Across Providers](#3-reasoning-and-thinking-block-retention-across-providers)
4. [The 5-Tier Compaction Ladder & `Discard-all` vs. `Summary`](#4-the-5-tier-compaction-ladder--discard-all-vs-summary)
5. [Progressive Disclosure (`AGENTS.md` Map → `docs/`)](#5-progressive-disclosure-agentsmd-map--docs)
6. [Anti-`ASI06` Memory Hygiene (OWASP Agentic 2026)](#6-anti-asi06-memory-hygiene-owasp-agentic-2026)
7. [Reference Implementation (Python 3.11+ & TypeScript ESM)](#7-reference-implementation-python-311--typescript-esm)
8. [Context & Memory Checklist](#8-context--memory-checklist)

---

## 1. Attention Budget, Context Rot & Breunig's 4 Failure Modes

Transformers compute $O(n^2)$ pairwise token attention across $n$ tokens. Accuracy degrades steadily well before nominal context window ceilings.

### Chroma Research *Context Rot* (18 Frontier & Open LLMs, 194,480 Calls)
- **Lower semantic similarity accelerates decay:** Standard lexical Needle-in-a-Haystack hides degradation; as semantic similarity drops (cosine `0.445–0.829`), recall decays steeply with input length.
- **Distractors compound non-uniformly:** Even 1 topically related distractor degrades accuracy; 4 distractors amplify failures dramatically. Failure styles diverge by family: Claude Opus/Sonnet 4 abstain conservatively, while GPT models hallucinate confident wrong answers.
- **Focused excerpts beat full histories across every model family:** On LongMemEval (~113k full vs. ~300 focused tokens across 306 prompts), **every** tested model—including thinking/reasoning modes—scored substantially worse on full histories because mixing retrieval and reasoning in one long prompt degrades both.
- **Coherent haystacks hurt retrieval *more* than shuffled ones:** Logically structured prose pulls attention away from isolated facts across all 18 models.

### Drew Breunig's 4 Long-Context Failure Modes
1. **Context Poisoning:** An early hallucination enters `goals` or a summary and anchors later turns (Gemini 2.5 Pokémon pursuing impossible objectives).
2. **Context Distraction:** Past ~32k–100k tokens, accumulated history overwhelms training priors (Gemini 2.5 Pro >100k repeats past actions; Databricks Llama 3.1 405B degrades around 32k).
3. **Context Confusion:** Excess tool schemas/docs pull attention into wrong calls (BFCL v3; Llama 3.1 8B failed at 46 tools in 16k window, passed when trimmed to 19).
4. **Context Clash:** Conflicting early guesses or multi-turn shards permanently derail reasoning (Microsoft/Salesforce sharded study: **−39% avg**, OpenAI `o3` **98.1 → 64.1**).

**Prompt altitude & anti-mimicry:** Keep system prompts at the **Goldilocks altitude** (concrete heuristics + canonical examples—neither brittle `if/else` scripts nor vague platitudes). On repetitive batch work (e.g., reviewing 20 items), inject slight structural variation in observation formatting so in-context mimicry does not few-shot the model into a rut (Manus).

---

## 2. KV-Cache Prefix Invariance (10× Cost Engineering)

Because autoregressive KV caches invalidate from the **first mutated byte onward**, a single volatile token at the top of a prompt turns cached input (`$0.30/MTok` on Claude Sonnet) into uncached input (`$3.00/MTok` — a **10× cost blowup** plus severe TTFT latency).

Enforce **six mechanical prefix-invariance rules** (`AH010`):

1. **Strict prefix ordering:** `tools → system → stable examples/docs → append-only messages`.
2. **Zero volatile head fields:** Never inject `datetime.now()`, `Date.now()`, per-request UUIDs, or live counters into the system prompt head. Append mid-session changes (new working directory, updated sandbox mode, soft budget notices) as new trailing messages (OpenAI Codex pattern).
3. **Deterministic JSON serialization:** Serialize all tool schemas, MCP tool lists (sorted by name), and message arguments with deterministic sorted keys (`sort_keys=True` in Python; sorted key serializer in TS).
4. **Lock thinking mode and top-level `effort`/`budget_tokens`:** On Claude, changing top-level `output_config.effort` or `budget_tokens` mid-conversation **invalidates message-level cache breakpoints** (verified by Anthropic: `cache_read_input_tokens: 3546 → 0`). Keep top-level effort constant and steer per-turn depth via trailing user-turn steering text.
5. **Mask tools instead of mutating schemas mid-loop:** Dynamically adding/removing tools mid-turn busts the prefix cache *and* causes schema hallucinations when past turns reference removed tools (Manus). Keep the static tool list fixed and enforce phase restrictions via state-machine logit masking / response prefill over tool prefixes (`browser_*`, `shell_*`)—or use cache-preserving deferred loading (`defer_loading: true` + Tool Search Tool, which only appends discovered references at the tail).
6. **Keep telemetry wire extensions out-of-band:** Follow DeepSeek `dsh` (`dsh_plugin_packages`, `dsh_session_log`, `x-deepseek-harness-*` headers): transport metadata outside `messages`/prompts/schemas so it never adds tokens or perturbs the prefix.

---

## 3. Reasoning and Thinking Block Retention Across Providers

Frontier reasoning models impose strict history contracts across multi-turn tool loops (`AH011`). Violating them causes HTTP 400 errors or silent reasoning collapse:

| Provider / Model Family | Mandatory Multi-Turn Contract | Common Fatal Bug |
|---|---|---|
| **DeepSeek (`V3.2` / `V4` thinking mode)** | When `tools` is present, **must echo `reasoning_content` on every prior assistant turn** (even turns without tool calls) or receive HTTP `400`. V3.2 retains `<think>` across tool turns and discards it only on a **new `role="user"` message**. | Simulating tool results as `role="user"` (e.g., Terminus/Roo Code) wipes historical thinking on every step (Terminal-Bench 2.0: 39.3 non-thinking vs. 46.4 thinking). |
| **Anthropic Claude (`4.5` / `4.6` / `4.7+`)** | Echo the **entire assistant `content` array verbatim** when returning `tool_result`s, including `thinking` blocks and opaque `signature` fields—even when `display: "omitted"` yields empty `thinking: ""`. | Stripping `thinking` blocks silently degrades reasoning; assuming every turn has a `thinking` block crashes under adaptive thinking (`type: "adaptive"`, which skips thinking on trivial turns). Note: thinking tokens bill as `output_tokens` and preserved blocks re-bill as `input_tokens` on keep-all models. |
| **OpenAI (Responses API / Codex)** | Keep requests stateless (avoiding `previous_response_id` for ZDR) and pass returned `type="reasoning"` items with **`encrypted_content`** back unchanged in `input[]`. | Dropping `type="reasoning"` items forces the model to re-derive plans from scratch on every tool turn. |

---

## 4. The 5-Tier Compaction Ladder & `Discard-all` vs. `Summary`

Compaction always transforms only the **derived model view**—never delete the underlying append-only session log. Escalate through five tiers in order of increasing invasiveness:

| Tier | Strategy | Mechanism | When to Use / Verified Evidence |
|---|---|---|---|
| **1. Prevention & Offloading** | `spill-policy` + JIT retrieval | Cap inline tool results (e.g., 25k tokens) and spill full payloads to restorable files; keep file paths/handles instead of raw blobs. | **Always on.** Prevents bloat before compaction is ever needed. |
| **2. Lightweight Clearing** | `CompactionEdit` / `compaction-tool-result-pruner` | Clear old `thinking` blocks and stale raw `tool_result` bodies deep in history while keeping tool call signatures visible (`keep_tool_uses=3`, `keep_thinking_turns=1`). | **First compaction step** (runs *before* summarization in DeepSeek `dsh` and Inspect AI). SWE-agent collapsing observations older than the last 5 gained **+3.0 pts** on SWE-bench Lite. |
| **3. Provider-Native Compaction** | `CompactionNative` (`CompactionAuto`) | Delegate compression to OpenAI `/responses/compact` (opaque `type=compaction` `encrypted_content`) or Claude native compaction, falling back to Tier 4. | Supported frontier endpoints when minimizing custom summarizer drift. |
| **4. Structured Summary Compaction** | `CompactionSummary` | Trigger at token pressure (`pre_step`) or canonical overflow (`request-error`). Summarize into a high-recall checkpoint (**original goal, decisions, edits, unresolved errors, remaining work, verbatim security constraints**) + 5 most recently accessed files (Claude Code). Support incremental re-compaction. | Long coding/conversational sessions needing continuity across >100k tokens. |
| **5. Clean Context Reset (`Discard-all`) + Disk Handoff** | Full reset + durable workspace state | Flush critical state to structured disk artifacts (`feature_list.json` JSON > Markdown, `progress.md`, `git log`, `todo.md` recitation), then discard prior trajectory and start a fresh window. | Models showing "context anxiety" or deep search loops. **DeepSeek-V3.2 BrowseComp 80%-context ablation (§4.4):** `Discard-all` (**67.6%**) decisively beat `Summary` (**60.2%**, 364 avg steps) and no compaction (**51.4%**). |

**Keep recent errors, compact stale bulk:** Never erase recent failed tool calls before retrying (Manus: *Keep the Wrong Stuff In* preserves Bayesian recovery evidence). Clear/collapse *old, resolved* bulk observations once they are more than 3–5 turns behind.

---

## 5. Progressive Disclosure (`AGENTS.md` Map → `docs/`)

OpenAI's *Harness Engineering* (Feb 2026) demonstrated why dumping a 1,000-line manual into the system prompt fails: *"Context is a scarce resource... When everything is 'important,' nothing is. It rots instantly, and it resists mechanical verification."*

Use a **two-level progressive disclosure architecture**:

1. **Compact Entrypoint Map (~80–120 lines):** `AGENTS.md` / `CLAUDE.md` serves strictly as a table of contents—core architecture invariants, build/test commands, and 1-hop pointers into topic docs.
2. **Indexed, Verifiable `docs/` + On-Demand Skills:** Detailed specifications, execution plans (`docs/exec-plans/`), and specialized Skills stay on disk (only skill frontmatter loads at boot; full bodies load on demand via `read_file` / `glob` / `grep`). Enforce doc freshness mechanically via CI link/lint checks and periodic doc-gardening jobs.

---

## 6. Anti-`ASI06` Memory Hygiene (OWASP Agentic 2026)

Persistent cross-session memory (`/memories`, vector stores, `NOTES.md`) introduces **OWASP `ASI06` (Memory & Context Poisoning)**: an indirect prompt injection in turn 12 writes a malicious instruction or false fact into long-term memory, permanently hijacking all future sessions.

Enforce **six structural memory controls**:

1. **Forbid auto-re-ingestion of unverified agent outputs:** Never automatically promote raw model outputs or external web/email tool results into high-trust system memory ("bootstrap poisoning").
2. **Namespace isolation:** Partition memory strictly by `(tenant_id, user_id, session_id)` and trust tier (`trusted_config` vs. `untrusted_observation`).
3. **Mandatory provenance metadata:** Tag every record with `source_type`, `session_id`, `created_at`, `verified_by`, and `trust_level`.
4. **TTL & trust decay:** Expire unverified observations automatically; require deterministic validation (or human approval) before elevating a record to durable project knowledge.
5. **Write validation gate:** Scan candidate memory writes for instruction-like override patterns, secret tokens, and schema compliance before committing.
6. **Pre-compaction flush + snapshot rollback:** Before Tier 4/5 compaction runs, allow the agent to write structured factual notes (`decisions`, `verified_file_paths`, `open_bugs`) into a versioned snapshot that can be quarantined or rolled back on anomaly detection.

---

## 7. Reference Implementation (Python 3.11+ & TypeScript ESM)

### Python 3.11+ — Cache-Safe Prefix, Reasoning Preservation, 2-Stage Compaction & `ASI06` Memory

```python
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Literal


# --- 1. KV-Cache Prefix Integrity Guard ---

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def prefix_fingerprint(system_prompt: str, tools: list[dict[str, Any]]) -> str:
    """Computes a stable digest over sorted tools + system prompt to detect cache-busting drift."""
    sorted_tools = sorted(tools, key=lambda t: str(t.get("name", "")))
    payload = canonical_json({"tools": sorted_tools, "system": system_prompt})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# --- 2. Provider-Safe Assistant Turn Serializer (Preserves Reasoning Blocks) ---

def format_assistant_history_items(
    *,
    provider_family: Literal["deepseek", "anthropic", "openai"],
    content: str,
    tool_calls: list[dict[str, Any]],
    reasoning_content: str | None = None,
    opaque_blocks: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Returns provider-native history items to append; preserves reasoning and never uses role=user for tools."""
    if provider_family == "deepseek":
        entry: dict[str, Any] = {"role": "assistant", "content": content}
        # DeepSeek thinking + tools requires `reasoning_content` on EVERY prior assistant turn.
        entry["reasoning_content"] = reasoning_content or ""
        if tool_calls:
            entry["tool_calls"] = tool_calls
        return [entry]

    if provider_family == "anthropic":
        blocks: list[dict[str, Any]] = []
        if opaque_blocks:
            blocks.extend(opaque_blocks)  # Verbatim {"type": "thinking", "thinking": ..., "signature": ...}
        if content:
            blocks.append({"type": "text", "text": content})
        for tc in tool_calls:
            blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]})
        return [{"role": "assistant", "content": blocks}]

    # OpenAI Responses API: append top-level `input[]` items (never nested inside a Chat-Completions dict).
    items: list[dict[str, Any]] = []
    for block in opaque_blocks or []:
        # Verbatim {"type": "reasoning", "id": ..., "encrypted_content": ...}
        items.append(block)
    if content:
        items.append(
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": content}],
            }
        )
    for tc in tool_calls:
        raw_args = tc["arguments"]
        items.append(
            {
                "type": "function_call",
                "call_id": tc["id"],
                "name": tc["name"],
                "arguments": raw_args if isinstance(raw_args, str) else canonical_json(raw_args),
            }
        )
    return items


# --- 3. Tier-2 Tool-Result Pruner (CompactionEdit before Summarization) ---

def prune_stale_tool_results(
    messages: list[dict[str, Any]],
    *,
    keep_recent_tool_results: int = 3,
    keep_recent_thinking_turns: int = 1,
    exclude_tools: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Pure projection: clears deep tool result bodies & pre-user-turn thinking without mutating the log."""
    excluded = exclude_tools or set()
    tool_indices = [i for i, m in enumerate(messages) if m.get("role") == "tool"]
    protected_tools = set(tool_indices[-keep_recent_tool_results:]) if keep_recent_tool_results > 0 else set()

    asst_indices = [i for i, m in enumerate(messages) if m.get("role") == "assistant"]
    protected_thinking = set(asst_indices[-keep_recent_thinking_turns:]) if keep_recent_thinking_turns > 0 else set()
    last_user_idx = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1)

    projected: list[dict[str, Any]] = []
    for i, msg in enumerate(messages):
        copy = dict(msg)
        if copy.get("role") == "tool" and i not in protected_tools:
            if copy.get("tool_name") not in excluded and len(str(copy.get("content", ""))) > 240:
                copy["content"] = "[PRUNED: Earlier tool output cleared to save context. Re-run tool or read spill file if needed.]"
        elif copy.get("role") == "assistant" and i < last_user_idx and i not in protected_thinking:
            # DeepSeek V3.2 mandates echoing `reasoning_content` across every tool-calling step,
            # but allows dropping prior-turn reasoning strictly after a NEW user message arrives.
            if copy.get("_allow_thinking_prune"):
                copy = {k: v for k, v in copy.items() if k != "reasoning_content"}  # harness-audit: ignore AH011
        projected.append(copy)
    return projected


# --- 4. Anti-ASI06 Scoped Memory Store ---

_INJECTION_PATTERNS = re.compile(
    r"(ignore previous instructions|system prompt|override policy|<IMPORTANT>|exfiltrate)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    key: str
    value: str
    namespace: str
    source_type: Literal["verified_tool", "human_confirmed", "agent_note"]
    created_at: float
    ttl_s: float
    quarantined: bool = False


class SafeMemoryStore:
    """Enforces namespace isolation, provenance, TTL expiry, and write validation against ASI06."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], MemoryRecord] = {}

    def put(
        self,
        *,
        namespace: str,
        key: str,
        value: str,
        source_type: Literal["verified_tool", "human_confirmed", "agent_note"],
        ttl_s: float = 3600.0,
    ) -> MemoryRecord:
        if _INJECTION_PATTERNS.search(value):
            raise ValueError("ASI06_BLOCKED: Candidate memory write matched prompt-injection pattern.")
        if source_type == "agent_note" and ttl_s > 86_400:
            raise ValueError("ASI06_BLOCKED: Unverified agent notes cannot exceed 24h TTL.")
        rec = MemoryRecord(
            key=key,
            value=value,
            namespace=namespace,
            source_type=source_type,
            created_at=time.time(),
            ttl_s=ttl_s,
        )
        self._records[(namespace, key)] = rec
        return rec

    def query(self, namespace: str, *, include_unverified: bool = False) -> list[MemoryRecord]:
        now = time.time()
        out: list[MemoryRecord] = []
        for (ns, _), rec in self._records.items():
            if ns != namespace or rec.quarantined or (now - rec.created_at) > rec.ttl_s:
                continue
            if not include_unverified and rec.source_type == "agent_note":
                continue
            out.append(rec)
        return out
```

### TypeScript (Strict ESM) — Prefix Fingerprint, Tool-Result Pruner & `ASI06` Memory Store

```ts
import { createHash } from "node:crypto";

export function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableJson(v)}`).join(",")}}`;
}

export function prefixFingerprint(
  systemPrompt: string,
  tools: readonly Record<string, unknown>[],
): string {
  const sortedTools = [...tools].sort((a, b) => {
    const na = String(a.name ?? "");
    const nb = String(b.name ?? "");
    return na < nb ? -1 : na > nb ? 1 : 0;
  });
  return createHash("sha256")
    .update(stableJson({ tools: sortedTools, system: systemPrompt }))
    .digest("hex")
    .slice(0, 16);
}

export interface ChatMsg {
  readonly role: "system" | "user" | "assistant" | "tool";
  readonly content: string;
  readonly tool_name?: string;
  readonly tool_call_id?: string;
  readonly reasoning_content?: string;
}

export function pruneStaleToolResults(
  messages: readonly ChatMsg[],
  opts: { keepRecentTools?: number; excludeTools?: ReadonlySet<string> } = {},
): ChatMsg[] {
  const keep = opts.keepRecentTools ?? 3;
  const excluded = opts.excludeTools ?? new Set<string>();
  const toolIndices: number[] = [];
  messages.forEach((m, i) => {
    if (m.role === "tool") toolIndices.push(i);
  });
  const protectedIdx = new Set(keep > 0 ? toolIndices.slice(-keep) : []);

  return messages.map((msg, idx) => {
    if (
      msg.role === "tool" &&
      !protectedIdx.has(idx) &&
      !excluded.has(msg.tool_name ?? "") &&
      msg.content.length > 240
    ) {
      return {
        ...msg,
        content: "[PRUNED: Earlier tool output cleared to preserve attention budget. Re-read spill file if needed.]",
      };
    }
    return msg;
  });
}

const INJECTION_RE = /(ignore previous instructions|system prompt|override policy|<IMPORTANT>|exfiltrate)/i;

export interface MemoryRecord {
  readonly namespace: string;
  readonly key: string;
  readonly value: string;
  readonly sourceType: "verified_tool" | "human_confirmed" | "agent_note";
  readonly createdAtMs: number;
  readonly ttlMs: number;
  readonly quarantined: boolean;
}

export class SafeMemoryStore {
  private readonly records = new Map<string, MemoryRecord>();

  put(input: Omit<MemoryRecord, "createdAtMs" | "quarantined">): MemoryRecord {
    if (INJECTION_RE.test(input.value)) {
      throw new Error("ASI06_BLOCKED: Memory write matched prompt-injection pattern.");
    }
    if (input.sourceType === "agent_note" && input.ttlMs > 86_400_000) {
      throw new Error("ASI06_BLOCKED: Unverified agent notes cannot exceed 24h TTL.");
    }
    const rec: MemoryRecord = { ...input, createdAtMs: Date.now(), quarantined: false };
    this.records.set(`${input.namespace}::${input.key}`, rec);
    return rec;
  }

  query(namespace: string, includeUnverified = false): MemoryRecord[] {
    const now = Date.now();
    const out: MemoryRecord[] = [];
    for (const rec of this.records.values()) {
      if (rec.namespace !== namespace || rec.quarantined || now - rec.createdAtMs > rec.ttlMs) continue;
      if (!includeUnverified && rec.sourceType === "agent_note") continue;
      out.push(rec);
    }
    return out;
  }
}
```

---

## 8. Context & Memory Checklist

- [ ] **Prefix invariance (`AH010`):** Is the prefix locked as `tools → system → append-only messages` with sorted-key JSON, zero head timestamps/UUIDs, and static tool schemas across turns?
- [ ] **Effort & thinking lock:** On Claude, are thinking mode and top-level `effort`/`budget_tokens` held constant across cached turns (using trailing per-message steering instead)?
- [ ] **Reasoning retention (`AH011`):** Does the serializer echo `reasoning_content` (DeepSeek), verbatim `thinking`+`signature` without crashing when adaptive thinking omits a block (Claude), and `encrypted_content` (OpenAI)—and **never** encode tool results as `role="user"`?
- [ ] **Ordered compaction ladder:** Does the harness spill large outputs first, prune stale tool results *before* summarizing, preserve verbatim security constraints in summaries, and support clean `Discard-all` resets + disk handoffs?
- [ ] **Progressive disclosure:** Is `AGENTS.md` / system prompt kept to a concise ~100-line map pointing to indexed `docs/` and on-demand skills?
- [ ] **Anti-`ASI06` memory hygiene:** Are persistent memories namespace-isolated, provenance-tagged, TTL-bounded, validated on write, and blocked from auto-re-ingesting unverified agent outputs?
