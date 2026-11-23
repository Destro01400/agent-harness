# Strong vs. Weak Agent Harnesses: Empirical Evidence, Boundaries & Diagnostics

When an autonomous agent fails in production, teams reflexively swap in a larger model. Empirical benchmarks across Anthropic, LangChain, OpenAI, Vercel, Browser Use, Princeton, Manus, and UC Berkeley prove a sharper truth: **with model weights completely frozen, harness and Agent-Computer Interface (ACI) design swings accuracy by +10 to +61.6 percentage points and unit cost by up to 10×.**

## Table of Contents

1. [Empirical Evidence: Same Model Weights, Dramatic Swings](#1-empirical-evidence-same-model-weights-dramatic-swings)
2. [The Six Necessary & Sufficient Properties of a True Harness](#2-the-six-necessary--sufficient-properties-of-a-true-harness)
3. [6-Species Boundary Diagnostic Matrix](#3-6-species-boundary-diagnostic-matrix)
4. [Capability-Frontier Economics & The Bitter Lesson](#4-capability-frontier-economics--the-bitter-lesson)
5. [Weak-Harness Anti-Patterns vs. Strong Invariants (Before/After)](#5-weak-harness-anti-patterns-vs-strong-invariants-beforeafter)
6. [Context Failure Diagnostic Table (Quick Triage)](#6-context-failure-diagnostic-table-quick-triage)
7. [Pre-Ship Red-Flag Checklist (`AH001`–`AH016` & `validate_trace.py`)](#7-pre-ship-red-flag-checklist-ah001ah016--validate_tracepy)

---

## 1. Empirical Evidence: Same Model Weights, Dramatic Swings

Every result below holds model weights **100% constant** (`$0` training compute):

| Study / Source | Model / Benchmark | Harness / ACI Change | Measured Impact |
|---|---|---|---|
| **LangChain** (Feb 2026) | `gpt-5.2-codex` / Terminal-Bench 2.0 (89 tasks) | Added `LocalContext`, `PreCompletionChecklist` exit verify, `LoopDetection` per-file edit counter, time-budget alerts, `xhigh-high-xhigh` reasoning sandwich via automated trace analysis | **52.8% → 66.5% (+13.7 pts; Top 30 → Top 5)**. `xhigh`-only = 53.9% (timeouts), `high`-only = 63.6%, sandwich = 66.5%. |
| **LangChain** (Apr 2026) | `GPT-5.3 Codex` & `Claude Opus 4.7` / τ²-bench | Replaced one-size-fits-all harness with declarative per-model `HarnessProfile`s (`apply_patch`/`shell_command` for Codex; `<tool_result_reflection>` for Opus 4.7) | **Codex: 33% → 53% (+20 pts)**; **Opus 4.7: 43% → 53% (+10 pts)**. |
| **Can Bölük / Stencil** (Feb 2026) | **16 LLMs** / React mutation editing (180 tasks × 3 runs) | Swapped only the edit tool (`apply_patch`/`str_replace` → **Hashline** `line:hash\|` anchors) | **+15 pts avg** (beats `patch` in **14/16**). **Grok Code Fast 1: 6.7% → 68.3% (+61.6 pts / 10×, −49% tokens)**; **Grok 4 Fast: +17.4 pts (−61% output tokens)**; **DeepSeek V3.2: −5 pts** (proving model-harness coupling). |
| **Princeton SWE-agent** (`arXiv:2405.15793`) | `GPT-4 Turbo` / SWE-bench Lite (300) | Replaced raw Shell-only with custom ACI: 100-line viewer, lint-gated range edit (`flake8` revert), summarized search (≤50 hits), last-5 obs collapse | **11.0% → 18.0% (+7.0 pts)** over Shell-only w/ demo (+10.7 pts w/o demo). Ablations: no linter **−3.0**, full-file viewer **−5.3**, IDE iterative search **−6.0** (worse than no search at 15.7%!). |
| **Vercel `d0`** (Dec 2025) | `Claude Opus 4.5` / Text-to-SQL (Cube DSL) | Deleted ~80% of tools (17 bespoke SQL/schema tools → **2 primitives**: sandboxed bash + `ExecuteSQL` over clean Cube docs) | **80% → 100% (+20 pts)**, **3.5× faster** (`274.8s → 77.4s`), **−37% tokens**, **−42% steps**. Worst case: 724s/100 steps FAIL → 141s/19 steps PASS. |
| **Browser Use 1.0** (Apr 2026) | Frontier LLMs / Browser automation | Replaced 24 click/type/scroll wrappers + 10 crash watchdogs with raw CDP + Python execution | **+14 to +33 pts** on identical models. |
| **Anthropic** (Jan 2026) | `Claude Opus 4.5` / CORE-Bench | Fixed rigid rounding graders, disambiguated specs, and relaxed an over-constrained scaffold | **42% → 95% (+53 pts)**. |
| **Anthropic** (Sep–Nov 2025) | Claude / MCP & Tool evals | Added 1–5 `input_examples`, `defer_loading` Tool Search, Code Execution with MCP, `concise` response format | **+18 pp** param accuracy (72%→90%); **85%–98.7%** tool token reduction; **+8.6–25 pp** MCP eval lift; **~67%** Slack payload reduction. |
| **Factory Droid 1.0** (Nov 2026) | Terminal-Bench 4 | Switched tool catalog to **Code Mode** (`exec(code)` calling typed `tools.*`) | **+3.5 pts accuracy**, **−15% spend**. |
| **Manus** (Jul 2025) | `Claude Sonnet` (~100:1 in:out ratio) | Enforced strict KV-cache prefix invariance + logit masking instead of mid-loop tool mutation | **10× cheaper input tokens** (`$0.30` vs `$3.00/MTok`). |
| **Anthropic Sandboxing** (2025) | Claude Code | OS filesystem isolation (`bwrap`/Seatbelt) + external domain-allowlist network proxy | **−84% permission prompts** while closing exfiltration vectors. |

---

## 2. The Six Necessary & Sufficient Properties of a True Harness

A system **is** an Agent Harness if and only if it satisfies **all six properties simultaneously**:

| # | Property | Mechanical Requirement | What Happens If Missing |
|---|---|---|---|
| **1** | **Model-driven closed-loop control flow** | The LLM dynamically picks tools, inspects ground-truth observations, and decides next steps within runtime bounds. | Collapses into a **Workflow / Rigid Pipeline**. |
| **2** | **Grounded execution environment & ACI** | Real callable tools (filesystem, sandboxed shell, browser, DB, test runner) returning objective feedback. | Collapses into a **Thin API Wrapper**. |
| **3** | **Durable off-context state & pre-rot lifecycle** | Append-only session log outside the volatile window + cache-safe prefixes + spill/pruning/compaction/resets. | Fails past turn 30–50 from Context Rot or crashes with total state loss. |
| **4** | **Code-enforced invariants & security boundaries** | Hard budgets (steps/tokens/cost/time), dual OS/container sandbox, vaulted credentials outside sandbox, deterministic PEP/PDP approvals. | Collapses into **Prompt-Only / Persona** (broken by prompt injection or attention lapse). |
| **5** | **Cybernetic feedback loop (Guides + Sensors)** | Concise feedforward maps/specs paired with deterministic computational sensors (tests, linters, typecheckers, E2E) + optional independent evaluators. | Feedforward-only rules never verify outcomes; model self-praises broken work. |
| **6** | **Inspectable, "build-to-delete" architecture** | Raw turn-$N$ payload visibility, structured traces for hill-climbing, and modular hooks strippable as models improve. | Collapses into an **Opaque Framework** or **Over-Constrained Micro-Manager**. |

---

## 3. 6-Species Boundary Diagnostic Matrix

Dropping *any one* of the six properties—or over-rotating on control until model reasoning is boxed in—crosses cleanly into a different architectural species. Use this matrix to classify what you are actually building (and whether you even *need* a harness):

| Dimension | **True Agent Harness** | **Workflow / Rigid Pipeline** | **Thin API Wrapper / SDK Client** | **Prompt-Only / Persona** | **Monolithic / Opaque Framework** | **Over-Constrained Micro-Manager** |
|---|---|---|---|---|---|---|
| **Who chooses next step?** | **Model** dynamically within code bounds | **Developer code** (fixed DAG / router) | **Caller app** (single turn or chat UX) | **Model** (unbounded, no code governor) | **Hidden framework internals** | **Brittle rule engine** boxing model into micro-steps |
| **Execution & ACI** | Sandboxed composable atomic tools + real ground truth | Code calls APIs at fixed pipeline stages | None (or passive RAG injection only) | None, or raw unguarded tools + prose rules | Generic vendor wrappers | 20–100+ hyper-narrow custom wrapper tools |
| **State & context lifecycle** | Durable off-context log + pre-rot spill/compaction | Explicit state object passed step-to-step | Stateless or unbounded `messages[]` | Giant monolithic prompt / `AGENTS.md` | Opaque memory; cache-hostile | Forced pre-filters / stale mandatory resets |
| **Guardrails & invariants** | **Code-enforced** (sandbox, vaulted creds, budgets, linters) | Deterministic code gates between stages | HTTP retries + JSON schema parse only | **Natural language only** (`"never run rm -rf"`) | Vendor defaults; poorly understood | Micromanages *how* model reasons, not *boundaries* |
| **Feedback / verification** | Cybernetic **Guides + Sensors** (tests/linters/E2E) | Fixed programmatic gate or none | None | Model self-praise ("All tests pass!") | Generic reflection prompt loops | Over-engineered watchdogs hiding raw errors |
| **Single-Question Litmus Test** | Does it satisfy all 6 properties? | Can you enumerate all tool paths from code alone? | Does it only wrap HTTP/retries/RAG in 1 turn? | If the model ignores the system prompt, does code still prevent harm? | Can you print turn-$N$ raw payloads & delete a layer in <20 LOC? | Does deleting tools/watchdogs make it faster *and* more accurate? |
| **When it IS the right choice** | Open-ended, multi-step, verifiable tasks | Known steps, strict SLAs, high-blast-radius writes (billing/migrations) | Extraction, classification, summarization, Q&A | Human-in-the-loop brainstorming with zero side effects | Fast throwaway PoC (only if you inspect internals) | **Never** for reasoning; enforce only hard *boundary invariants* |

---

## 4. Capability-Frontier Economics & The Bitter Lesson

### The Capability-Frontier Economics Law

Empirical studies by Naresh Jain (*Are Harnesses Worth the Cost?*, Oct 2026) and Anthropic (*Harness Design*, Mar 2026) prove that **continuous inner-loop harnessing is not free—its ROI flips sharply across the model's capability frontier**:

| Regime | Measured Benchmark Result | Optimal Harness Topology |
|---|---|---|
| **Inside the frontier** (strong frontier model passes reliably solo) | GPT-6 Sol passed **10/10** unaided (`$0.406`, `1.08M` tokens, `6m51s`). Adding continuous inner-loop behavioral harnessing burned **10.5× tokens** (`11.33M`), **~3× time** (`19m53s`), and **~7× cost** (`$2.679`) for **zero** accuracy lift. | **Lean loop + independent deterministic final verification gate.** Do not pay continuous inner-loop overhead when the model already solves solo. |
| **At or beyond the frontier** (cost-optimized model OR multi-hour frontier build) | GPT-6 Luna scored **3/10** unaided, but continuous inner-loop sensors ("executable attention") lifted it to **10/10 at `$0.273`** (**33% cheaper** than unharnessed GPT-6 Sol!). On Opus 4.5, adding Planner + Generator + Playwright Evaluator turned a broken `$9` solo build into a working full-stack studio. | **Full Inner + Outer Harness** (atomic tools, continuous computational sensors, durable state, and optional independent Evaluator). |

> **Rule of Thumb:** Model capability determines *when and how often* sensors run (continuous inner loop vs. end-of-run gate), never *whether* an independent verification gate is required.

### The Bitter Lesson and The Deletion Test

Every harness component encodes a perishable assumption about what today's model cannot do alone (Rich Sutton's *Bitter Lesson*):

- **Anthropic:** Hard context resets were essential for Sonnet 4.5's "context anxiety", became dead weight on Opus 4.5, and sprint decomposition essential on Opus 4.5 became unnecessary overhead on Opus 4.6.
- **Manus:** Rebuilt their harness **5 times in 6 months** so the product rides frontier model upgrades ("the boat, not the pillar stuck to the seabed").
- **Vercel `d0` & Browser Use 1.0:** Deleting 80% of bespoke tools improved accuracy, speed, and token cost—**with one non-negotiable prerequisite**: *the underlying environment must be legible*. Stripping tools over an undocumented, untestable codebase only produces faster wrong answers.

**The Deletion Test (run on every major model upgrade):**
> *For every custom wrapper tool, pre-filter, forced planning step, or watchdog in your harness: if you delete it in one config toggle and re-run your eval suite on the newest model, does accuracy stay flat or rise while latency and token cost drop? If yes, delete it permanently.*

---

## 5. Weak-Harness Anti-Patterns vs. Strong Invariants (Before/After)

### Runtime Loop: Unbounded & Error-Erasing vs. Bounded & Verifiable

**Weak Pattern (triggers `AH001`, `AH008`, `AH012`):**
```python
# BAD: Unbounded loop, swallows exceptions, erases failed turns, trusts self-report.
while True:
    resp = llm.chat(messages)
    if not resp.tool_calls:
        return resp.content  # No verification after mutations!
    for call in resp.tool_calls:
        try:
            out = run_tool(call.name, call.args)  # Unbounded output, no timeout
            messages.append({"role": "tool", "tool_call_id": call.id, "content": out})
        except Exception:
            messages.pop()  # Erases failure evidence -> model repeats exact same bug!
            continue
```

**Strong Pattern (Python 3.11+ — bounded, preserves errors, detects doom loops, verifies exit):**
```python
from __future__ import annotations

import hashlib
import json
from collections import Counter


async def run_bounded_loop(provider, hands, session_log, profile, *, max_turns: int = 25) -> str:
    repeat_counts: Counter[str] = Counter()
    mutated = False

    for turn in range(1, max_turns + 1):
        messages = derive_messages(session_log.read_all())
        resp = await provider.complete(
            model=profile.model,
            messages=messages,
            tools=profile.static_tools,
            max_tokens=profile.max_tokens,
            timeout_s=60.0,
        )
        session_log.append("assistant_message", {
            "content": resp.content,
            "reasoning_content": resp.reasoning_content,  # Never strip reasoning
            "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments} for c in resp.tool_calls],
        })

        if not resp.tool_calls:
            if mutated and not await verify_workspace(hands):
                session_log.append("user_message", {
                    "content": "Verification failed. Inspect the failing test output and fix before finishing."
                })
                continue
            return resp.content

        for call in resp.tool_calls:
            sig = hashlib.sha256(
                f"{call.name}:{json.dumps(call.arguments, sort_keys=True)}".encode()
            ).hexdigest()[:12]
            repeat_counts[sig] += 1
            if repeat_counts[sig] >= 3:
                result = (
                    f"[LOOP GUARD] Identical call `{call.name}` repeated {repeat_counts[sig]} times. "
                    "Change strategy, inspect error output, or report blocker."
                )
            else:
                try:
                    raw = await hands.execute(call.name, call.arguments, timeout_s=30.0)
                    result = cap_or_spill(raw, max_chars=24_000)
                    mutated = mutated or call.name in profile.mutating_tools
                except TimeoutError:
                    result = f"[TIMEOUT] `{call.name}` exceeded 30s. Narrow scope or split command."
                except Exception as exc:
                    # Keep the wrong stuff in context so the model updates its beliefs.
                    result = f"[TOOL ERROR] `{call.name}` failed: {exc}. Adjust arguments and retry."
            session_log.append("tool_result", {"tool_call_id": call.id, "content": result})

    raise RuntimeError(f"Budget exhausted after {max_turns} turns without verified completion.")
```

**Strong Pattern (TypeScript strict ESM — equivalent loop guards, bounded spill & exit verification):**
```ts
import { createHash } from "node:crypto";

export async function runBoundedLoop(
  provider: LLMProvider,
  hands: ExecutionHands,
  sessionLog: AppendOnlySessionLog,
  opts: {
    model: string;
    staticTools: readonly Record<string, unknown>[];
    mutatingTools: ReadonlySet<string>;
    maxTurns: number;
  },
): Promise<string> {
  const repeats = new Map<string, number>();
  let mutated = false;

  for (let turn = 1; turn <= opts.maxTurns; turn += 1) {
    const messages = deriveMessages(await sessionLog.readAll());
    const resp = await provider.complete({
      model: opts.model,
      messages,
      tools: opts.staticTools,
      maxTokens: 4096,
      signal: AbortSignal.timeout(60_000),
    });

    await sessionLog.append("assistant_message", {
      content: resp.content,
      reasoning_content: resp.reasoningContent,
      tool_calls: resp.toolCalls.map((c) => ({
        id: c.id,
        name: c.name,
        argumentsJson: JSON.stringify(c.arguments),
      })),
    });

    if (resp.toolCalls.length === 0) {
      if (mutated && !(await verifyWorkspace(hands))) {
        await sessionLog.append("user_message", {
          content: "Verification failed. Inspect the failing test output and fix before finishing.",
        });
        continue;
      }
      return resp.content;
    }

    for (const call of resp.toolCalls) {
      const sortedArgs = Object.keys(call.arguments)
        .sort()
        .reduce<Record<string, unknown>>((acc, k) => {
          acc[k] = call.arguments[k];
          return acc;
        }, {});
      const key = createHash("sha256")
        .update(`${call.name}:${JSON.stringify(sortedArgs)}`)
        .digest("hex")
        .slice(0, 12);
      const count = (repeats.get(key) ?? 0) + 1;
      repeats.set(key, count);

      let content: string;
      if (count >= 3) {
        content = `[LOOP GUARD] Identical call \`${call.name}\` repeated ${count}x. Pivot or escalate.`;
      } else {
        try {
          const raw = await hands.execute(call.name, call.arguments, AbortSignal.timeout(30_000));
          content = capOrSpill(raw, 24_000);
          mutated = mutated || opts.mutatingTools.has(call.name);
        } catch (err) {
          if (err instanceof Error && err.name === "TimeoutError") {
            content = `[TIMEOUT] \`${call.name}\` exceeded 30s. Narrow scope or split command.`;
          } else {
            content = `[TOOL ERROR] \`${call.name}\` failed: ${String(err)}. Adjust parameters before retrying.`;
          }
        }
      }
      await sessionLog.append("tool_result", { tool_call_id: call.id, content });
    }
  }
  throw new Error(`Budget exhausted after ${opts.maxTurns} turns without verified completion.`);
}
```

### Multi-Agent "Org-Chart" Anti-Pattern

UC Berkeley's MAST study (`arXiv:2503.13657`, 150+ traces across MetaGPT, ChatDev, HyperAgent, AppWorld, AG2; Cohen's $\kappa = 0.88$) documented **14 systemic multi-agent failure modes** (spec/role violations, information withholding, ignored peer input, premature termination). ChatDev achieved **25.0%** baseline on ProgramDev and only **40.6%** after prompt and topology redesign. Cognition's two laws explain why: *(1) share full traces, not lossy chat summaries; (2) concurrent unisolated writers make conflicting implicit decisions.* Default to a single-threaded linear loop; spawn parallel subagents only for read-only exploration or cleanly isolated verification.

---

## 6. Context Failure Diagnostic Table (Quick Triage)

Use this triage table when reading a failing trace (grounded in Chroma's 18-LLM *Context Rot* study, Drew Breunig's 4 modes, and Manus's KV-cache telemetry):

| Trace Symptom | Diagnosis | Empirical Reference | Concrete Fix |
|---|---|---|---|
| Agent endlessly pursues a hallucinated or impossible goal recorded earlier | **Context Poisoning** | Gemini 2.5 Pokémon poisoned `goals` state | Validate state externally; reset/overwrite poisoned goal artifacts; forbid unverified self-writes to trusted memory (`ASI06`). |
| Past ~32k–100k tokens, agent stops planning and repeats prior actions verbatim | **Context Distraction** | Gemini 2.5 Pro >100k tokens; Databricks Llama 3.1 405B >32k | Prune old tool results (`CompactionEdit`), offload large payloads (`spill-policy`), or trigger clean context reset / `Discard-all`. |
| Agent invokes irrelevant tools or fails schema validation frequently | **Context Confusion** | BFCL v3; GeoEngine Llama 3.1 8B failed at 46 tools, passed at 19 | Consolidate CRUD into workflow tools, namespace clearly, and enable lazy loading (`defer_loading` Tool Search / Code Mode) past `>10` MCP tools (Anthropic guidance; `audit_harness.py` `AH013` warns past `>15` static tools). |
| Early wrong guess anchors later turns; agent never recovers | **Context Clash** | Microsoft/Salesforce sharded prompts: −39% avg; `o3` **98.1 → 64.1** | Isolate speculative exploration in subagents; verify assumptions against ground truth before writing conclusions into main history. |
| Input cost jumps ~10× and TTFT spikes mid-run; `tokens_cached / tokens_in < 0.50` | **KV-Cache Collapse** | Manus: `$3.00` vs `$0.30/MTok` on Claude Sonnet | Freeze static prefix (`tools → system → messages`), remove head timestamps/UUIDs, `sort_keys=True`, lock `effort`/`budget_tokens`, mask instead of mutating tools. |

---

## 7. Pre-Ship Red-Flag Checklist (`AH001`–`AH016` & `validate_trace.py`)

Clear every gate before shipping a harness to production. Each check maps directly to `scripts/audit_harness.py` (static SARIF 2.1.0 rules) and `scripts/validate_trace.py` (runtime trace & eval checks):

| Gate | Red Flag to Eliminate | Static Rule (`audit_harness.py`) | Runtime Trace Signal (`validate_trace.py`) |
|---|---|---|---|
| **1. Hard Loop Caps** | `while True` calling LLM/tools with no step, token, cost, or wall-clock cap | `AH001` (`ERROR`) | Step/token/wall-clock budget breach or ungraceful hang |
| **2. Safe Execution** | `shell=True`, `os.system`, interpolated `exec`/`execSync`, or `eval()`/`new Function()` | `AH002`, `AH003` (`ERROR`) | Command execution anomalies / unexpected exit codes |
| **3. Real Isolation** | Regex/string command blacklists instead of OS/container sandbox; writable host mounts, `privileged: true`, `docker.sock`, missing `network_mode: none` | `AH004`, `AH006` (`ERROR`) | Lethal Trifecta sequence (untrusted read → sensitive local path → outbound egress) |
| **4. Credential Vaulting** | Hardcoded keys or passing raw `os.environ` / `process.env` into subprocess/sandbox | `AH005` (`ERROR`) | Secret leak pattern (`sk-`, `sk-ant-`, `AIza`, `AKIA`, `gh[pousr]_`, PEM PKCS#1/PKCS#8, Bearer, signed URL params incl. `access_token`) |
| **5. Timeouts Everywhere** | Subprocess or HTTP/LLM calls without explicit timeout / `AbortSignal` | `AH007` (`WARN`) | Non-monotonic timestamps / stalled spans |
| **6. Error Integrity** | `except Exception: pass` or `messages.pop()` erasing failed turns from context | `AH008` (`WARN`) | Orphan `tool_call` lacking matching `tool_result`; doom-loop repeats |
| **7. Safe Retries** | Constant/zero-sleep retry loops or nested multi-layer retries ($3^5 = 243\times$ storms) | `AH009` (`WARN`) | Rapid unjittered retry bursts / duplicate mutations |
| **8. KV-Cache Hygiene** | `datetime.now()`/`Date.now()`/`uuid4()` in system prompt prefix or `sort_keys=False` | `AH010` (`WARN`) | KV-cache hit ratio drop across turns $t \ge 2$ (`tokens_cached / tokens_in`) |
| **9. Reasoning Contract** | Stripping `reasoning_content`/`thinking` or encoding tool results as `role="user"` | `AH011` (`WARN`) | OTel accounting violation (`input < cached` or `output < thinking`) / HTTP 400 |
| **10. Bounded Outputs** | Returning raw `stdout`/files/HTTP bodies into context without truncation + disk spill | `AH012` (`WARN`) | Single `tool_result` exceeding token/char ceiling (tool output flood) |
| **11. Tool Supply & Scale** | Unpinned MCP (`npx -y` / `@latest`) or bloated static catalogs (recommend lazy loading past `>10` MCP tools per Anthropic guidance; `audit_harness.py` `AH013` triggers its static bloat warning at `>15` static tools) | `AH013` (`WARN`) | High tool schema validation failure rate |
| **12. Async Hygiene** | Blocking `time.sleep`, `requests.*`, or sync `subprocess.run` inside `async def` | `AH014` (`WARN`) | Event-loop stalls / timeout cascades |
| **13. Hardened Evals** | Unprotected LLM judge (no `{grader_nonce}`, no `temperature=0`, first-match regex) or `k=1` eval without `pass@k` / `pass^k` | `AH015` (`WARN`), `AH016` (`INFO`/`WARN`) | Unverified completion after mutation; invalid `pass@k` vs `pass^k` math or duplicate task IDs |
