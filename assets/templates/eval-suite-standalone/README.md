# {{PROJECT_NAME}}

{{DESCRIPTION}}

Zero-dependency Python 3.11+ standalone evaluation harness for AI agents and agent harnesses:

- **Adapter boundary (`AgentAdapter`)**: plug any agent runtime (local Python, CLI, HTTP service, or scripted mock) behind one async contract (`run_trial(task, workspace, trial_index) -> TrialResult`).
- **Outcome-first deterministic graders**: `contains`, `regex`, `exact_json`, `numeric_tolerance`, `tool_used`, `max_steps`, `state_equals`.
- **Hardened LLM-as-a-judge contract (`NonceJudgePromptBuilder`)**: random 8-hex `{grader_nonce}` delimiters to resist prompt injection, `temperature=0.0`, **last-match** `GRADE:` parser, `"Unknown"` escape hatch, and strict-majority panel aggregation.
- **Statistical rigor**: bounded `asyncio.Semaphore` concurrency, isolated per-trial temporary workspaces, `trials >= 3` default, exact unbiased `pass@k`, `pass^k`, and Wilson 95% confidence intervals.
- **CI readiness**: `--gold` reference verification (catches broken tasks/graders), baseline diff / regression gate against `datasets/baseline.json`, and JSON + Markdown report generation.

## Quickstart

```bash
# Run unit tests (zero external dependencies)
python -B -m unittest discover -s tests -p "test_*.py" -v

# Run multi-trial eval suite with baseline regression gate
PYTHONPATH=src python -B -m {{PACKAGE_NAME}}.runner \
  --tasks datasets/tasks.jsonl \
  --trials 3 \
  --baseline datasets/baseline.json

# Verify task/grader soundness using deterministic gold solutions
PYTHONPATH=src python -B -m {{PACKAGE_NAME}}.runner \
  --tasks datasets/tasks.jsonl \
  --trials 3 \
  --gold
```

## Layout

- `src/{{PACKAGE_NAME}}/adapter.py` — `AgentAdapter` protocol, `EvalTask`, `TrialResult`, `DemoAdapter`, `GoldReferenceAdapter`.
- `src/{{PACKAGE_NAME}}/graders.py` — Deterministic outcome graders + hardened `NonceJudgePromptBuilder` and strict-majority panel aggregator.
- `src/{{PACKAGE_NAME}}/runner.py` — Bounded concurrent runner, exact `pass@k` / `pass^k` / Wilson CI, `--gold` verification, baseline CI regression gate, JSON + Markdown reports.
- `datasets/tasks.jsonl` — 4 sample tasks including positive and negative trigger checks.
- `datasets/baseline.json` — Committed baseline metrics for CI regression gating.
- `tests/test_eval_suite.py` — Comprehensive unit test suite.
