# {{PROJECT_NAME}}

{{DESCRIPTION}}

Zero-dependency Python 3.11+ agent harness starter template encoding production runtime and evaluation invariants:

- **Append-only `Model-visible <=> logged` JSONL traces** with monotonic UTC timestamps, OpenTelemetry GenAI operation fields, and automatic secret redaction.
- **KV-cache prefix stability** via immutable system prompts, sorted static tool definitions, and canonical `sort_keys=True` JSON serialization.
- **Reasoning preservation** (`reasoning_content` and `thinking_blocks` echoed verbatim across tool turns; tool outputs strictly emitted with `role="tool"`).
- **Declarative `HarnessProfile`** configuration with deletable middleware hooks (`LoopDetectionHook`, `PreCompletionVerifyHook`).
- **Hard runtime boundaries**: bounded step/token/cost/time budgets, per-tool `asyncio.wait_for` timeouts, output truncation + disk spill, workspace `realpath` containment, zero-credential subprocess env allowlist, atomic `CheckpointStore`, and 5-decision `ApprovalPolicy` with a 3-consecutive-rejection circuit breaker.
- **Multi-trial eval runner** (`trials >= 3`) computing exact unbiased `pass@k`, `pass^k`, Wilson 95% CI, and `--gold` grader soundness checks in isolated per-trial workspaces.

## Quickstart

```bash
# Run the full unit test suite (zero external packages)
python -B -m unittest discover -s tests -p "test_*.py" -v

# Run the offline multi-trial eval suite (default: 3 trials per task)
PYTHONPATH=src python -B -m {{PACKAGE_NAME}}.eval_runner --tasks evals/tasks.jsonl --trials 3

# Verify task/grader soundness with deterministic gold solutions
PYTHONPATH=src python -B -m {{PACKAGE_NAME}}.eval_runner --tasks evals/tasks.jsonl --trials 3 --gold
```

## Layout

- `src/{{PACKAGE_NAME}}/provider.py` — Provider protocol, message/usage dataclasses, declarative `HarnessProfile`, deterministic `MockProvider`.
- `src/{{PACKAGE_NAME}}/tools.py` — Strict schema validation, timeouts, output truncation + disk spill, workspace containment, env allowlist, `ApprovalPolicy`.
- `src/{{PACKAGE_NAME}}/harness.py` — Bounded `AgentHarness` loop, `BudgetConfig`, `TraceWriter` (with secret redaction), atomic `CheckpointStore`, deletable hooks.
- `src/{{PACKAGE_NAME}}/eval_runner.py` — Isolated multi-trial eval runner with exact `pass@k`, `pass^k`, Wilson 95% CI, and `--gold` verification.
- `evals/tasks.jsonl` — Sample evaluation tasks.
- `tests/test_harness.py` — End-to-end invariant tests.
