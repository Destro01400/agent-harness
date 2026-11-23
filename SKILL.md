---
name: agent-harness
license: MIT
description: Design, scaffold, build, harden, evaluate, and audit production AI agent harnesses in Python and TypeScript. Use when building autonomous agent runtime loops, Agent-Computer Interfaces (ACI) and tool contracts, MCP lazy loading or Code Mode, prompt-cache-safe context compaction and reasoning-block retention, durable append-only sessions and checkpoints, OS/container sandboxing and OWASP Agentic Top 10 (ASI01-ASI10) controls, OpenTelemetry GenAI tracing, resilient retries and streaming, or multi-trial agent eval harnesses with outcome graders, nonce-hardened LLM judges, pass@k, pass^k, and Wilson CI. Also use to diagnose weak vs. strong harnesses, decide whether a thin API wrapper or deterministic workflow fits better than a harness, or apply DeepSeek Harness (dsh), Claude Managed Agents, OpenAI Codex, and SWE-agent patterns. Ships 15 reference guides, 3 zero-dependency starter templates, a SARIF 2.1.0 static auditor (AH001-AH016), and a JSONL trace/eval validator.
---

# Agent Harness Engineering (`agent-harness`)

End-to-end engineering guide for **AI agent runtime and evaluation harnesses** (`Agent = Model + Harness`) in **Python 3.11+** and **TypeScript (Node 24+ ESM)**. Covers Brain/Session/Hands decoupling, ACI and tool contracts, KV-cache-safe context compaction, OS/container sandboxing, OWASP Agentic Top 10 (`ASI01`–`ASI10`), OpenTelemetry GenAI tracing, multi-trial eval harnesses (`pass@k`, `pass^k`, Wilson CI), static auditing (`AH001`–`AH016`, SARIF 2.1.0), and trace validation.

> Load **only** the reference file(s) the active task needs. Paths below are relative to this folder.

---

## Zero-Step Gate (Do You Even Need a Harness?)

Stop before writing loop code—using a harness where a simpler pattern fits wastes latency, tokens, and reliability:
- **Single-turn task** (classification, extraction, summarization, grounded RAG Q&A) → **Do NOT build a harness.** Use a thin API wrapper with structured outputs.
- **Known, fixed step sequence or high-blast-radius writes** (billing, migrations, compliance ETL) → **Do NOT build an open-ended agent loop.** Use a deterministic workflow (chaining, routing, fixed gates).
- **Open-ended, multi-step, verifiable task** where the model must explore and adapt to ground-truth feedback → **Build a harness** using the 1-Hop Decision Tree below (and verify boundaries in [strong-vs-weak-harnesses.md](references/strong-vs-weak-harnesses.md)).

---

## 1-Hop Decision Tree

| If the task is... | Template (`scripts/scaffold_harness.py --template`) | Read first | Then |
|---|---|---|---|
| New Python agent runtime + eval loop | `python-runtime-eval` | [harness-architecture.md](references/harness-architecture.md) | [agent-loop-and-budgets.md](references/agent-loop-and-budgets.md), [tool-contracts-and-execution.md](references/tool-contracts-and-execution.md), [context-and-memory.md](references/context-and-memory.md) |
| New TypeScript/Node agent runtime + eval loop | `typescript-runtime-eval` | [harness-architecture.md](references/harness-architecture.md) | [agent-loop-and-budgets.md](references/agent-loop-and-budgets.md), [resilience-and-streaming.md](references/resilience-and-streaming.md), [state-and-checkpoints.md](references/state-and-checkpoints.md) |
| Standalone eval suite, graders & CI regression gate | `eval-suite-standalone` | [eval-harness-design.md](references/eval-harness-design.md) | [graders-and-regression.md](references/graders-and-regression.md), [observability-and-traces.md](references/observability-and-traces.md) |
| Diagnose weak harness, bloat, or workflow boundary | n/a | [strong-vs-weak-harnesses.md](references/strong-vs-weak-harnesses.md) | Run `scripts/audit_harness.py` & `scripts/validate_trace.py` |
| Harden sandbox, permissions, or MCP supply chain | n/a | [sandboxing-and-security.md](references/sandboxing-and-security.md) | [mcp-and-dynamic-tools.md](references/mcp-and-dynamic-tools.md), [production-deployment.md](references/production-deployment.md) |
| Build coding agent or multi-agent topology | `python-runtime-eval` or `typescript-runtime-eval` | [coding-agent-patterns.md](references/coding-agent-patterns.md) | [multi-agent-orchestration.md](references/multi-agent-orchestration.md), [state-and-checkpoints.md](references/state-and-checkpoints.md) |

Scaffold example: `python scripts/scaffold_harness.py --template python-runtime-eval --name AcmeAgent --out ./AcmeAgent` (`--list`, `--description`, `--force` also supported).

---

## Quick Reference Routing

| Area | File |
|---|---|
| Brain/Session/Hands 3-way decoupling, `Model-visible ⟺ logged`, thin provider seam, DeepSeek `dsh` Cordis 3-role seams, Codex/Managed Agents/ADK/mini-SWE-agent tradeoffs | [harness-architecture.md](references/harness-architecture.md) |
| Empirical strong vs. weak evidence, 6 defining harness properties, 6-species Boundary Matrix, Capability-Frontier Economics, Bitter Lesson ablation, Pre-Ship Red Flags | [strong-vs-weak-harnesses.md](references/strong-vs-weak-harnesses.md) |
| Turn/step lifecycle, orthogonal budgets (`turn`, `token`, `cost`, `working_limit` + `time_limit`, per-tool timeout), doom-loop guards, exit-interception verification, `HarnessProfile`s | [agent-loop-and-budgets.md](references/agent-loop-and-budgets.md) |
| Poka-yoke ACI, workflow consolidation over CRUD, namespacing, `input_examples` (+18 pp), `response_format`, output truncation + disk spill, actionable errors, idempotency | [tool-contracts-and-execution.md](references/tool-contracts-and-execution.md) |
| Context Rot (4 failure modes), KV-cache prefix invariance, reasoning preservation (DeepSeek `reasoning_content`, Claude `thinking`+`signature`, OpenAI `encrypted_content`), 5-tier compaction, `ASI06` memory hygiene | [context-and-memory.md](references/context-and-memory.md) |
| Append-only durable session log (`session.vN.jsonl`), transient stream vs. settled commits, missing tool-result repair, Initializer+Worker (`feature_list.json`, `init.sh`), HITL 5-decision `ApprovalPolicy` | [state-and-checkpoints.md](references/state-and-checkpoints.md) |
| OWASP Agentic Top 10 2026 (`ASI01`–`ASI10`), Least Agency, Lethal Trifecta, Dual-Boundary Rule (FS + egress proxy), OS confinement (`bwrap`/Seatbelt/Windows ACL), Docker hardening, zero-credential sandboxes | [sandboxing-and-security.md](references/sandboxing-and-security.md) |
| OpenTelemetry GenAI Semantic Conventions (`invoke_agent`, `plan`, `chat`, `execute_tool`), inclusive token accounting, `NO_CONTENT` default, `*_ref` hooks, JSONL traces, keyless replay | [observability-and-traces.md](references/observability-and-traces.md) |
| Connect+read timeouts, capped exponential backoff + full jitter, single-layer retry rule (anti-243× amplification), retry budgets, keeping recent errors in context, cancellation, sync-I/O offloading | [resilience-and-streaming.md](references/resilience-and-streaming.md) |
| Task/Trial/Transcript/Outcome model, Capability vs. Regression suites, `--gold` solvability checks, per-trial isolation, unbiased `pass@k` & `pass^k`, Wilson 95% CI, clustered stderr, `sdk-minimal` | [eval-harness-design.md](references/eval-harness-design.md) |
| Outcome-over-trajectory grading, deterministic code graders, `{grader_nonce}` LLM judge hardening, order-swapping, cross-family strict-majority panels, Krippendorff's α, τ-bench attribution, Swiss Cheese | [graders-and-regression.md](references/graders-and-regression.md) |
| MCP token-bloat math, cache-preserving `defer_loading` + Tool Search Tool (>10 tools / >10K tokens), Programmatic Tool Calling / Code Mode (98.7% savings, PII tokenization), Tool Poisoning / Rug Pull / Shadowing defense | [mcp-and-dynamic-tools.md](references/mcp-and-dynamic-tools.md) |
| When NOT to use multi-agent (Cognition's 2 laws, UC Berkeley MAST 14 failure modes, 15× cost), valid topologies, `as_tool` vs. `handoff`, filesystem artifact handoff, scoped limits, `ASI03`/`ASI07`/`ASI08` | [multi-agent-orchestration.md](references/multi-agent-orchestration.md) |
| Coding ACI (Hashline `line:hash\|`, 100-line viewer, lint-gated edit, ≤50-hit search, stateless bash), ~100-line `AGENTS.md` map, git worktrees, bootable CDP/LogQL/PromQL sensors, remediation linters, GC agents | [coding-agent-patterns.md](references/coding-agent-patterns.md) |
| Decoupled Brain/Session/Hands scaling (lazy sandbox provisioning), queues & tenant quotas, declarative layered profiles (`dsh` bundle+patch), immutable `v0→vN` migrations, canary/digital-twin replay, kill switches | [production-deployment.md](references/production-deployment.md) |

### Scripts and Assets

| Tool | Usage |
|---|---|
| [scripts/scaffold_harness.py](scripts/scaffold_harness.py) | `--list`, `--template {python-runtime-eval,typescript-runtime-eval,eval-suite-standalone}`, `--name`, `--out`, `--description`, `--force`. Zero-dependency templates live in `assets/templates/`. |
| [scripts/audit_harness.py](scripts/audit_harness.py) | `python scripts/audit_harness.py PROJECT_DIR [--strict] [--json \| --sarif] [--ignore-dir DIR]`. Scans Python, JS/TS, Docker, and MCP configs across 16 rules (`AH001`–`AH016`); emits Text, JSON, or SARIF 2.1.0. |
| [scripts/validate_trace.py](scripts/validate_trace.py) | `python scripts/validate_trace.py PATH [--mode {auto,trace,dataset,eval_summary}] [--strict] [--json] [--max-tool-chars 50000]`. Validates JSONL traces, token/cache invariants, secrets, Lethal Trifecta, and eval summaries. |
| `scripts/test_scaffold.py`, `test_audit_harness.py`, `test_validate_trace.py` | Zero-dependency test suites: `python -B -m unittest discover -s scripts -p "test_*.py" -v`. |

---

## Core Workflow

1. **Pass the Zero-Step Gate:** Confirm a single augmented call or deterministic workflow is insufficient before adding an autonomous loop.
2. **Audit existing code & traces first:** Run `audit_harness.py --strict` and `validate_trace.py --strict` to surface unbounded loops, shell injection, secret leaks, cache busters, reasoning loss, and single-trial evals.
3. **Scaffold cleanly:** Start from `scaffold_harness.py` so append-only `Model-visible ⟺ logged` JSONL sessions, declarative `HarnessProfile`s, deletable middleware hooks, orthogonal budgets, and multi-trial evals are wired from Turn 1.
4. **Engineer ACI & context:** Keep tools consolidated, sorted, and bounded (truncation + disk spill + actionable errors); protect the KV-cache prefix; echo reasoning/thinking blocks verbatim; never cast tool results as `role="user"`.
5. **Enforce boundaries in code:** Dual OS/container filesystem + network sandboxing, zero credentials inside the sandbox, deterministic `ApprovalPolicy` with 3-rejection breaker, and SHA-256 MCP schema pinning.
6. **Verify & hill-climb:** Add deterministic `PreCompletion` verification, run multi-trial isolated evals (`k >= 3`) measuring `pass@k` and `pass^k` with Wilson CI, read raw transcripts weekly, and ablate stale scaffolding on model upgrades.

---

## Pre-Delivery Checklist

1. **Static audit:** `python scripts/audit_harness.py PROJECT_DIR --strict` exits `0` (use `--sarif` in CI for GitHub Code Scanning).
2. **Trace & eval validation:** `python scripts/validate_trace.py TRACE_OR_EVAL_DIR --strict` exits `0` (zero secret leaks, valid token/cache accounting, no orphan tool calls, `trials >= 3`).
3. **Runtime invariants:** Hard step/token/cost/wall-clock/per-tool limits in code, single-layer jittered backoff, immutable cache prefix, reasoning preserved, failed turns kept with actionable errors.
4. **Security boundary:** No `shell=True`/`eval()`/`exec()`, zero secrets in sandbox env, dual FS + network isolation, pinned MCP servers/schemas, consecutive-rejection circuit breaker active.
5. **Eval rigor:** Outcome graders verified with `--gold` reference solutions, isolated per-trial environments, hardened judges (`{grader_nonce}`, `temperature=0`, last-match regex), and both `pass@k` and `pass^k` reported.
