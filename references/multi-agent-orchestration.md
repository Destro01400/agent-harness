# Multi-Agent Orchestration & Subagent Topologies

Multi-agent architectures are one of the highest-leverage patterns for parallel exploration and frontier verification—and one of the fastest ways to burn **15× more tokens** while dropping accuracy to **25%** when misapplied. Default to a **single, well-equipped agent loop** and spawn subagents only when a specific structural bottleneck demands context isolation, parallelism, or skeptical separation.

## Table of Contents

1. [When NOT to Use Multi-Agent (Empirical Evidence)](#1-when-not-to-use-multi-agent-empirical-evidence)
2. [Valid High-ROI Multi-Agent Topologies](#2-valid-high-roi-multi-agent-topologies)
3. [Delegation Primitives: `as_tool` vs. `handoff`](#3-delegation-primitives-as_tool-vs-handoff)
4. [Filesystem Artifact Handoff (No "Game of Telephone")](#4-filesystem-artifact-handoff-no-game-of-telephone)
5. [Scoped Subagent Budgets & Failure Containment](#5-scoped-subagent-budgets--failure-containment)
6. [Multi-Agent Security (`ASI03`, `ASI07`, `ASI08`)](#6-multi-agent-security-asi03-asi07-asi08)
7. [Implementation Patterns (Python & TypeScript)](#7-implementation-patterns-python--typescript)

---

## 1. When NOT to Use Multi-Agent (Empirical Evidence)

Do **not** build corporate "org-chart" roleplay hierarchies (CEO, CTO, CPO, Programmer, Reviewer, Tester) or spawn parallel write-capable subagents over shared mutable code/state.

### Cognition's Two Laws (*Don't Build Multi-Agents*, 2025)
1. **Share full context and agent traces, not just isolated messages.** Splitting tightly coupled work across agents fragments the reasoning state needed to keep decisions coherent.
2. **Every action carries implicit decisions, and conflicting implicit decisions produce broken systems.** Parallel subagents writing different parts of the same codebase/app make incompatible API, styling, and architecture choices that a merge agent cannot reliably reconcile.

### UC Berkeley MAST Study (`arXiv:2503.13657`, Mar 2025)
Grounded-theory annotation of **150+ multi-agent traces** (>15,000 lines each) across 5 frameworks (MetaGPT, ChatDev, HyperAgent, AppWorld, AG2; inter-annotator Cohen's $\kappa = 0.88$) identified **14 structural failure modes** across 3 categories:
- **FC1 — Specification & System Design (`FM-1.1`–`FM-1.5`):** Disobeying task specs, role usurpation (CPO acting as CEO), step repetition, lost history, missing termination awareness.
- **FC2 — Inter-Agent Misalignment (`FM-2.1`–`FM-2.6`):** Conversation resets, failing to ask clarification, task derailment, **information withholding** (worker discovers critical constraint, omits it from report), **ignoring peer input**, and reasoning-action mismatch.
- **FC3 — Verification & Termination (`FM-3.1`–`FM-3.3`):** Premature victory claims (claiming a file was patched when untouched), missing verification, superficial compile-only checks.
- **Bottom line:** ChatDev achieved **25.0% baseline accuracy** on ProgramDev and only **40.6%** even after prompt engineering and cyclic topology redesign.

### Cost Economics (Anthropic *Multi-Agent Research System*, Jun 2025)
- Single-agent loops already consume **~4×** the tokens of standard chat.
- Multi-agent orchestration consumes **~15×** chat tokens—justifiable **only** when task value and parallelism/accuracy gains exceed the 15× token multiplier.

---

## 2. Valid High-ROI Multi-Agent Topologies

Use multi-agent orchestration **only** when one of these three proven conditions holds:

### Topology A: Read-Only Parallel Breadth-First Research (Orchestrator-Worker)
- **When it wins:** Open-ended exploration across many independent sources (codebase modules, web sources, log partitions, document sets) where each branch needs 10K–100K tokens of raw search/reading that would trigger Context Rot in a single window.
- **Measured gain (Anthropic, Jun 2025):** Opus 4 lead + parallel Sonnet 4 subagents beat single-agent Opus 4 by **+90.2%** on internal research evals; parallelizing 3–5 subagents × 3+ parallel tool calls cut latency by **up to 90%**. On BrowseComp, token/compute scaling across isolated windows explained **80% of score variance**.
- **Design rules:**
  - Subagents are **read-only** (no conflicting writes).
  - Each subagent starts with a **clean context window** and returns a **1,000–2,000 token distilled synthesis** + structured artifact references.
  - Encode **explicit effort-scaling rules** in the orchestrator prompt/policy:
    - Simple fact lookup → **1 agent**, 3–10 tool calls.
    - Direct comparison → **2–4 agents**, 10–15 calls each.
    - Complex multi-domain research → **5–10+ agents** with disjoint scopes.
  - Every delegation brief MUST specify 4 fields: **(1) objective, (2) output format, (3) tool/source bounds, (4) explicit non-overlapping task boundaries**.

### Topology B: Planner → Generator → Skeptical Evaluator (At Capability Frontier)
- **When it wins:** Long-horizon builds sitting **at or beyond** what a single model handles reliably solo (e.g., multi-hour full-stack app generation where solo models praise their own stubbed code).
- **Measured gain (Anthropic *Harness Design*, Mar 2026):** Turned `Claude Opus 4.5`'s broken `$9` solo build into a working 16-feature application by separating a **Planner** (expands brief into spec), a **Generator** (implements incrementally), and a **Skeptical Evaluator** (equipped with live Playwright/E2E tools, hard pass thresholds, and a pre-negotiated acceptance contract).
- **Build-to-Delete rule:** Re-ablate this topology on every model upgrade. When `Opus 4.6` absorbed multi-hour coherence, Anthropic stripped intermediate sprint loops and collapsed the evaluator to an end-of-run verification gate. Inside the model's solo capability frontier (Naresh Jain, Oct 2026: GPT-6 Sol 10/10 unaided), continuous inner-loop multi-agent/sensor overhead burned **7× cost** and **10.5× tokens** for zero gain—use a lean single loop + **deterministic final verification gate** instead.

### Topology C: Isolated Worktree Parallel Coding (Strict Disjoint Ownership)
- **When it wins:** Multiple completely disjoint files/modules/PRs where each worker runs in its own **`git worktree`** (or isolated container) with zero overlapping file ownership, and a deterministic CI + merge verifier validates the integrated branch.

---

## 3. Delegation Primitives: `as_tool` vs. `handoff`

Choose the right invocation contract (OpenTelemetry `gen_ai.transfer.mode` & UK AISI Inspect AI):

| Primitive | OTel `gen_ai.transfer.mode` | Context Passing | Control Flow | Use For |
|---|---|---|---|---|
| **Agent-as-a-Tool (`as_tool`)** | `return_to_caller` | Clean isolated context window; receives only explicit brief/inputs and returns distilled string/artifact pointer | Synchronous/parallel tool call; parent retains full control and aggregates results | Parallel research workers, code search, focused verification, context compression |
| **Control Transfer (`handoff`)** | `pass_control` | Passes filtered/curated conversation history or durable session pointer | Transfers turn ownership to specialist agent (e.g., Triage → Billing Specialist) | Linear multi-stage pipelines or customer-support domain routing where specialist converses directly with user |

**Default to `as_tool` (`return_to_caller`).** Handoffs transfer entire histories (amplifying Context Rot and `FM-2.1` misalignment) and complicate budget accounting.

---

## 4. Filesystem Artifact Handoff (No "Game of Telephone")

Never relay megabytes of generated code, JSON datasets, or deep research reports *through* the orchestrator's conversation transcript. Summarizing through intermediate LLMs loses exact identifiers, line numbers, and nuance ("game of telephone") while burning input tokens twice.

**Artifact Handoff Contract:**
1. Assign each subagent a dedicated scratch/output path (e.g., `artifacts/subagent-<id>/report.json` or its own `git worktree` branch).
2. Subagent writes full structured output directly to disk/object store and validates its schema before exiting.
3. Subagent returns to the orchestrator **only**:
   - `artifact_uri` + `sha256` checksum
   - Compact **300–1,500 token executive summary**
   - Explicit `status` (`completed` | `partial` | `blocked` | `limit_exceeded`) + `unresolved_gaps`

---

## 5. Scoped Subagent Budgets & Failure Containment

A runaway subagent must **never** exhaust the parent's total budget or crash the entire orchestration run.

- **Stackable per-subagent limits:** Bind explicit `turn_limit`, `token_limit`, `cost_limit`, `time_limit`, and `tool_call_limit` on every child invocation strictly smaller than the parent's remaining headroom.
- **Graceful limit return (Inspect AI rule):** When a tool-based subagent (`as_tool`) hits its scoped limit or throws a recoverable error, catch it at the subagent boundary and return a structured `{"status": "limit_exceeded", "partial_artifact": ..., "summary": ...}` tool result to the parent—never crash the parent loop.
- **Depth & fan-out caps:** Enforce hard code ceilings on **recursion depth** (default `max_depth = 1`; subagents cannot spawn sub-subagents unless explicitly authorized) and **concurrent fan-out** (`asyncio.Semaphore(max_concurrency)` + max total spawned subagents per run) to prevent exponential fork bombs (`ASI08`).
- **Single-layer retries:** Never retry a failed subagent at the orchestrator *and* retry LLM/tool calls inside the subagent independently (causes $r^d$ amplification).

---

## 6. Multi-Agent Security (`ASI03`, `ASI07`, `ASI08`)

Multi-agent setups multiply blast radius if privileges cascade across agents (OWASP Agentic Top 10, 2026):

1. **`ASI03` — Identity & Privilege Abuse (No Unscoped Inheritance):**
   - Never pass the orchestrator's full tool set or credentials to a subagent. Issue **strictly narrowed, task-scoped capabilities** (e.g., read-only tools for research subagents; single-directory write scope for a coder subagent).
   - Re-validate authorization per privileged action at the host PEP/PDP (anti-confused-deputy / anti-TOCTOU).
2. **`ASI07` — Insecure Inter-Agent Communication:**
   - For distributed/networked agents (A2A/HTTP/queues), enforce **mTLS / signed message envelopes** with `sender_id`, `session_id`, `nonce`, `timestamp`, `context_hash`, and typed versioned schemas. Reject unsigned messages, replay nonces, and protocol downgrades.
   - Treat outputs returned by any subagent that read untrusted external content as **tainted untrusted data** in the parent's prompt (wrap in explicit data delimiters; never grant raw subagent prose authority to override parent policy).
3. **`ASI08` — Cascading Failures:**
   - Decouple **planners** from **executors** via an independent deterministic policy engine.
   - Enforce per-run blast-radius quotas (max total writes, max external side effects, max fan-out) and tamper-evident lineage IDs (`trace_id`, `parent_span_id`, `gen_ai.agent.name`) across every hop.

---

## 7. Implementation Patterns (Python & TypeScript)

### Python Pattern: Scoped Parallel `as_tool` Fan-Out with Artifact Handoff

```python
import asyncio
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable


@dataclass(frozen=True)
class SubagentBudget:
    max_turns: int = 8
    max_tokens: int = 40_000
    timeout_s: float = 90.0


@dataclass(frozen=True)
class SubagentBrief:
    task_id: str
    objective: str
    output_format: str
    tool_allowlist: tuple[str, ...]  # Narrower than parent (ASI03)
    boundary: str                    # Disjoint scope / non-overlap rule
    artifact_path: Path


@dataclass(frozen=True)
class SubagentResult:
    task_id: str
    status: str  # "completed" | "limit_exceeded" | "error"
    summary: str
    artifact_path: str | None
    artifact_sha256: str | None


SubagentRunner = Callable[[SubagentBrief, SubagentBudget], Awaitable[str]]


async def run_parallel_subagents(
    briefs: list[SubagentBrief],
    runner: SubagentRunner,
    *,
    budget: SubagentBudget,
    max_concurrency: int = 4,
    current_depth: int = 0,
    max_depth: int = 1,
) -> list[SubagentResult]:
    if current_depth >= max_depth:
        raise PermissionError(f"Subagent recursion depth limit ({max_depth}) reached.")
    if len(briefs) > 12:
        raise ValueError("Fan-out cap exceeded (max 12 subagents per batch).")

    sem = asyncio.Semaphore(max_concurrency)

    async def _run_one(brief: SubagentBrief) -> SubagentResult:
        async with sem:
            try:
                summary = await asyncio.wait_for(
                    runner(brief, budget), timeout=budget.timeout_s
                )
            except TimeoutError:
                return SubagentResult(
                    task_id=brief.task_id,
                    status="limit_exceeded",
                    summary=f"Timed out after {budget.timeout_s}s; partial work if any on disk.",
                    artifact_path=str(brief.artifact_path) if brief.artifact_path.exists() else None,
                    artifact_sha256=None,
                )
            except Exception as exc:  # Contained: never crash parent orchestrator
                return SubagentResult(
                    task_id=brief.task_id,
                    status="error",
                    summary=f"Subagent failed safely: {type(exc).__name__}: {exc}",
                    artifact_path=None,
                    artifact_sha256=None,
                )

            digest = None
            path_str = None
            if brief.artifact_path.exists():
                digest = hashlib.sha256(brief.artifact_path.read_bytes()).hexdigest()
                path_str = str(brief.artifact_path)
            return SubagentResult(
                task_id=brief.task_id,
                status="completed",
                summary=summary[:4000],  # Enforce compact distilled return
                artifact_path=path_str,
                artifact_sha256=digest,
            )

    return list(await asyncio.gather(*(_run_one(b) for b in briefs)))
```

### TypeScript Pattern: Signed Inter-Agent Envelope (`ASI07`)

```ts
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface AgentEnvelope {
  readonly schemaVersion: "1.0";
  readonly senderId: string;
  readonly sessionId: string;
  readonly nonce: string;
  readonly timestampMs: number;
  readonly payload: Record<string, unknown>;
  readonly signatureHex: string;
}

function canonicalPayload(env: Omit<AgentEnvelope, "signatureHex">): string {
  return JSON.stringify([
    env.schemaVersion,
    env.senderId,
    env.sessionId,
    env.nonce,
    env.timestampMs,
    Object.fromEntries(Object.entries(env.payload).sort(([a], [b]) => a.localeCompare(b))),
  ]);
}

export function signEnvelope(
  secret: Buffer,
  fields: Omit<AgentEnvelope, "nonce" | "timestampMs" | "signatureHex">,
): AgentEnvelope {
  const unsigned = { ...fields, nonce: randomBytes(16).toString("hex"), timestampMs: Date.now() };
  const sig = createHmac("sha256", secret).update(canonicalPayload(unsigned)).digest("hex");
  return { ...unsigned, signatureHex: sig };
}

export function verifyEnvelope(
  secret: Buffer,
  env: AgentEnvelope,
  seenNonces: Set<string>,
  maxSkewMs = 60_000,
): boolean {
  if (Math.abs(Date.now() - env.timestampMs) > maxSkewMs) return false;
  if (seenNonces.has(env.nonce)) return false;
  const { signatureHex, ...unsigned } = env;
  const expected = createHmac("sha256", secret).update(canonicalPayload(unsigned)).digest();
  const actual = Buffer.from(signatureHex, "hex");
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return false;
  seenNonces.add(env.nonce);
  return true;
}
```
