# {{PROJECT_NAME}}

{{DESCRIPTION}}

Zero-dependency Python 3.11+ agent harness starter template encoding production runtime and evaluation invariants:

- **Append-only `Model-visible <=> logged` JSONL traces** emitting canonical events (`assistant/message`, `tool/call`, `tool/result`, `user/message`, `agent_end`) with monotonic UTC timestamps, OpenTelemetry GenAI operation fields, automatic secret redaction (including PKCS#8 PEM keys, GitHub tokens, and signed URL params), and pure `derive_messages_from_trace()` projection.
- **KV-cache prefix stability** via immutable system prompts, sorted static tool definitions, and canonical `sort_keys=True` JSON serialization.
- **Reasoning preservation** (`reasoning_content` and `thinking_blocks` echoed verbatim across tool turns and persisted redacted in traces; tool outputs strictly emitted with `role="tool"`).
- **Declarative `HarnessProfile`** configuration with deletable middleware hooks (`LoopDetectionHook`, `PreCompletionVerifyHook` refusing premature exit on `VERIFY_FAIL`).
- **Hard runtime boundaries**: bounded step/token/cost/wall-time/working-time/message budgets with 75% soft budget warning, `asyncio.wait_for` LLM & tool timeouts, non-blocking `asyncio.to_thread` disk I/O, strict `<= max_chars` output truncation + atomic disk spill, workspace `realpath` containment + NFC protected-path deny list, zero-credential subprocess env allowlist, atomic `CheckpointStore`, and Inspect AI 5-decision `ApprovalPolicy` (`approve`, `modify`, `reject`, `escalate`, `terminate`) with schema-before-approval ordering and 3-rejection circuit breaker.
- **Multi-trial eval runner** (`trials >= 3`) computing exact unbiased `pass@k`, `pass^k`, Wilson 95% CI, and `--gold` grader soundness checks in isolated per-trial workspaces.

## Quickstart

### Windows (PowerShell)

```powershell
# Run the full unit test suite (zero external packages)
python -B -m unittest discover -s tests -p "test_*.py" -v

# Run the offline multi-trial eval suite (default: 3 trials per task)
$env:PYTHONPATH="src"; python -B -m {{PACKAGE_NAME}}.eval_runner --tasks evals/tasks.jsonl --trials 3

# Verify task/grader soundness with deterministic gold solutions
$env:PYTHONPATH="src"; python -B -m {{PACKAGE_NAME}}.eval_runner --tasks evals/tasks.jsonl --trials 3 --gold
```

### Linux / macOS (Bash)

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
- `src/{{PACKAGE_NAME}}/tools.py` — Schema-first validation, timeouts, strict `<= max_chars` output truncation + atomic disk spill, workspace containment + NFC protected-path deny list, env allowlist, Inspect AI 5-decision `ApprovalPolicy`.
- `src/{{PACKAGE_NAME}}/harness.py` — Bounded `AgentHarness` loop, `BudgetConfig` (with `max_messages`, `max_working_seconds`, soft warnings), non-blocking `TraceWriter` + `derive_messages_from_trace()`, atomic `CheckpointStore`, deletable hooks.
- `src/{{PACKAGE_NAME}}/eval_runner.py` — Isolated multi-trial eval runner with exact `pass@k`, `pass^k`, Wilson 95% CI, and `--gold` verification.
- `evals/tasks.jsonl` — Sample evaluation tasks.
- `tests/test_harness.py` — End-to-end invariant & security regression tests.
