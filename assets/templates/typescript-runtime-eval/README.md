# {{PROJECT_NAME}}

{{DESCRIPTION}}

Zero-dependency TypeScript (Node.js 24+ native type stripping, strict ESM) agent harness starter template encoding production runtime and evaluation invariants:

- **Append-only `Model-visible <=> logged` JSONL traces** with strictly monotonic UTC timestamps, OpenTelemetry GenAI operation attributes, and automatic secret redaction.
- **KV-cache prefix stability** via immutable system prompts, sorted static tool definitions, and canonical key-sorted JSON serialization.
- **Reasoning preservation** (`reasoning_content` and `thinking_blocks` echoed verbatim across tool turns; tool outputs strictly emitted with `role: "tool"`).
- **Declarative `HarnessProfile`** with deletable middleware hooks (`LoopDetectionHook`, `PreCompletionVerifyHook`).
- **Hard runtime boundaries**: bounded step/token/cost/time budgets, `AbortSignal` per-tool timeouts, output truncation + atomic disk spill, `realpathSync` workspace containment, zero-credential env allowlist, atomic `CheckpointStore`, and 5-decision `ApprovalPolicy` with a 3-consecutive-rejection circuit breaker.
- **Multi-trial eval runner** (`trials >= 3`) computing exact unbiased `pass@k`, `pass^k`, Wilson 95% CI, and `--gold` grader soundness checks in isolated per-trial temp workspaces.

## Quickstart

Requires **Node.js 24+** (uses built-in TypeScript type stripping, zero `npm install` needed):

```bash
# Run the full test suite
node --test tests/harness.test.ts

# Run the offline multi-trial eval suite (default: 3 trials per task)
node src/eval_runner.ts --tasks evals/tasks.jsonl --trials 3

# Verify task/grader soundness with deterministic gold solutions
node src/eval_runner.ts --tasks evals/tasks.jsonl --trials 3 --gold
```

## Layout

- `src/provider.ts` — Provider interface, message/usage types, canonical JSON serializer, declarative `HarnessProfile`, deterministic `MockProvider`.
- `src/tools.ts` — Strict argument schema validation, `AbortSignal` timeouts, output truncation + disk spill, workspace containment, env allowlist, `ApprovalPolicy`.
- `src/harness.ts` — Bounded `AgentHarness` loop, `BudgetConfig`, `TraceWriter` (with secret redaction), atomic `CheckpointStore`, deletable hooks.
- `src/eval_runner.ts` — Isolated multi-trial eval runner with exact `pass@k`, `pass^k`, Wilson 95% CI, and `--gold` verification.
- `evals/tasks.jsonl` — Sample evaluation tasks.
- `tests/harness.test.ts` — Comprehensive `node:test` invariant suite.
