# {{PROJECT_NAME}}

{{DESCRIPTION}}

Zero-dependency TypeScript (Node.js 24+ native type stripping, strict ESM) agent harness starter template encoding production runtime and evaluation invariants:

- **Append-only `Model-visible <=> logged` JSONL traces** emitting canonical events (`assistant/message`, `tool/call`, `tool/result`, `user/message`, `agent_end`) with monotonic UTC timestamps, OpenTelemetry GenAI operation attributes, automatic secret redaction (including PKCS#8 PEM keys, GitHub tokens, and signed URL params), and pure `deriveMessagesFromTrace()` projection.
- **KV-cache prefix stability** via immutable system prompts, sorted static tool definitions, and canonical key-sorted JSON serialization.
- **Reasoning preservation** (`reasoning_content` and `thinking_blocks` echoed verbatim across tool turns and persisted redacted in traces; tool outputs strictly emitted with `role: "tool"`).
- **Declarative `HarnessProfile`** with deletable middleware hooks (`LoopDetectionHook`, `PreCompletionVerifyHook` that refuses premature exit on `VERIFY_FAIL`).
- **Hard runtime boundaries**: bounded step/token/cost/wall-time/working-time/message budgets with 75% soft budget warning, `AbortSignal.timeout()` LLM & tool timeouts, strict `<= maxChars` output truncation + atomic `fs/promises` disk spill, ancestor-walking `realpath` workspace containment with NFC protected-path deny list, zero-credential env allowlist, crash-safe `handle.sync()` atomic `CheckpointStore`, and Inspect AI 5-decision `ApprovalPolicy` (`approve`, `modify`, `reject`, `escalate`, `terminate`) with schema-before-approval ordering and 3-rejection circuit breaker.
- **Multi-trial eval runner** (`trials >= 3`) computing overflow-safe exact unbiased `pass@k`, `pass^k`, Wilson 95% CI, strict CLI validation, and `--gold` grader soundness checks in isolated per-trial temp workspaces.

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

- `src/provider.ts` — Provider interface (with `AbortSignal` support), message/usage types, canonical JSON serializer, declarative `HarnessProfile`, deterministic `MockProvider`.
- `src/tools.ts` — Schema-first argument validation, `AbortSignal` timeouts, strict `<= maxChars` truncation + async atomic disk spill, ancestor-walking workspace containment + NFC protected-path deny list, env allowlist, Inspect AI 5-decision `ApprovalPolicy`.
- `src/harness.ts` — Bounded `AgentHarness` loop, `BudgetConfig` (with `maxMessages`, `maxWorkingMs`, soft warnings), async `TraceWriter` + `deriveMessagesFromTrace()`, crash-safe atomic `CheckpointStore`, deletable hooks.
- `src/eval_runner.ts` — Isolated multi-trial eval runner with overflow-safe exact `pass@k`, `pass^k`, Wilson 95% CI, strict CLI validation, and `--gold` verification.
- `evals/tasks.jsonl` — Sample evaluation tasks.
- `tests/harness.test.ts` — Comprehensive `node:test` invariant & security regression suite.
