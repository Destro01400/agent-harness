"""Isolated multi-trial evaluation runner with exact pass@k, pass^k, Wilson CI, and --gold mode."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from {{PACKAGE_NAME}}.harness import AgentHarness, BudgetConfig, CheckpointStore, RunResult, TraceWriter
from {{PACKAGE_NAME}}.provider import HarnessProfile, MockProvider, ModelResponse, ToolCall, Usage
from {{PACKAGE_NAME}}.tools import create_default_tools


def pass_at_k(n: int, c: int, k: int) -> float:
    """Exact unbiased estimator for pass@k: 1 - C(n-c, k) / C(n, k)."""
    if n < 1 or k < 1 or k > n or c < 0 or c > n:
        raise ValueError(f"Invalid parameters: n={n}, c={c}, k={k}")
    if n - c < k:
        return 1.0
    return 1.0 - (math.comb(n - c, k) / math.comb(n, k))


def pass_pow_k(n: int, c: int, k: int) -> float:
    """Exact unbiased estimator for pass^k: C(c, k) / C(n, k)."""
    if n < 1 or k < 1 or k > n or c < 0 or c > n:
        raise ValueError(f"Invalid parameters: n={n}, c={c}, k={k}")
    if c < k:
        return 0.0
    return math.comb(c, k) / math.comb(n, k)


def wilson_ci(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score 95% confidence interval for a binomial proportion."""
    if total < 1 or successes < 0 or successes > total:
        raise ValueError(f"Invalid Wilson CI inputs: successes={successes}, total={total}")
    phat = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (phat + z2 / (2.0 * total)) / denom
    half = (z * math.sqrt((phat * (1.0 - phat) + z2 / (4.0 * total)) / total)) / denom
    return max(0.0, center - half), min(1.0, center + half)


@dataclass(frozen=True)
class EvalTask:
    id: str
    input: str
    expected: dict[str, Any]
    graders: tuple[dict[str, Any], ...]
    setup_files: dict[str, str]
    gold_plan: tuple[dict[str, Any], ...]


def load_tasks(path: Path) -> list[EvalTask]:
    tasks: list[EvalTask] = []
    seen_ids: set[str] = set()
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        item = json.loads(stripped)
        task_id = str(item["id"]).strip()
        if not task_id or task_id in seen_ids:
            raise ValueError(f"Invalid or duplicate task id at line {line_no}: {task_id!r}")
        seen_ids.add(task_id)
        tasks.append(
            EvalTask(
                id=task_id,
                input=str(item["input"]),
                expected=dict(item.get("expected", {})),
                graders=tuple(item.get("graders", ())),
                setup_files=dict(item.get("setup_files", {})),
                gold_plan=tuple(item.get("gold_plan", ())),
            )
        )
    return tasks


def grade_outcome(task: EvalTask, result: RunResult, workspace: Path) -> tuple[bool, list[str]]:
    """Evaluate final outcome (text, workspace artifacts, and invariants) deterministically."""
    failures: list[str] = []
    ws_real = Path(os.path.realpath(workspace))
    for grader in task.graders:
        gtype = grader.get("type")
        if gtype == "contains":
            needle = str(grader["value"])
            if needle not in result.final_output:
                failures.append(f"contains failed: missing {needle!r}")
        elif gtype == "regex":
            pattern = str(grader["pattern"])
            if not re.search(pattern, result.final_output):
                failures.append(f"regex failed: pattern {pattern!r} not matched")
        elif gtype == "file_contains":
            rel_path = str(grader["path"])
            needle = str(grader["value"])
            target = Path(os.path.realpath(ws_real / rel_path))
            try:
                contained = os.path.commonpath([str(ws_real), str(target)]) == str(ws_real)
            except ValueError:
                contained = False
            if not contained:
                failures.append(f"file_contains failed: path {rel_path!r} escapes workspace")
            elif not target.exists():
                failures.append(f"file_contains failed: missing file {rel_path}")
            elif needle not in target.read_text(encoding="utf-8"):
                failures.append(f"file_contains failed: {rel_path} missing {needle!r}")
        elif gtype == "tool_used":
            expected_tool = str(grader["name"])
            if expected_tool not in result.tool_calls_made:
                failures.append(f"tool_used failed: {expected_tool} was never invoked")
        elif gtype == "max_steps":
            limit = int(grader["limit"])
            if result.steps > limit:
                failures.append(f"max_steps failed: {result.steps} > {limit}")
        else:
            failures.append(f"unknown grader type: {gtype!r}")
    return len(failures) == 0, failures


def _build_scripted_provider(task: EvalTask, *, gold: bool) -> MockProvider:
    responses: list[ModelResponse] = []
    for turn_idx, step_spec in enumerate(task.gold_plan):
        tool_calls = tuple(
            ToolCall(
                id=f"tc_{task.id}_{turn_idx}_{idx}",
                name=str(tc["name"]),
                arguments=dict(tc.get("arguments", {})),
            )
            for idx, tc in enumerate(step_spec.get("tool_calls", ()))
        )
        tokens_in = 120 + turn_idx * 40
        tokens_cached = 80 if turn_idx > 0 else 0
        responses.append(
            ModelResponse(
                content=str(step_spec.get("content", "")),
                tool_calls=tool_calls,
                reasoning_content=f"Step {turn_idx + 1} deterministic {'gold' if gold else 'demo'} plan.",
                usage=Usage(
                    tokens_in=tokens_in,
                    tokens_cached=tokens_cached,
                    tokens_out=32,
                    thinking_tokens=8,
                    cost_usd=0.0002,
                ),
            )
        )
    if not responses:
        responses.append(
            ModelResponse(
                content=str(task.expected.get("answer", "DONE")),
                usage=Usage(tokens_in=100, tokens_cached=0, tokens_out=16, cost_usd=0.0001),
            )
        )
    return MockProvider(responses=responses)


def _prepare_workspace(workspace: Path, setup_files: dict[str, str]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    for rel_path, content in setup_files.items():
        dest = workspace / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


async def run_single_trial(task: EvalTask, trial_index: int, *, gold: bool) -> dict[str, Any]:
    """Run one task trial in an isolated temporary workspace with its own trace and checkpoints."""
    with tempfile.TemporaryDirectory(prefix=f"eval_{task.id}_t{trial_index}_") as tmp:
        root = Path(tmp)
        workspace = root / "workspace"
        await asyncio.to_thread(_prepare_workspace, workspace, task.setup_files)

        provider = _build_scripted_provider(task, gold=gold)
        tools = create_default_tools(workspace)
        trace = TraceWriter(
            root / "traces" / f"{task.id}_trial_{trial_index}.jsonl",
            session_id=f"{task.id}_trial_{trial_index}",
        )
        checkpoints = CheckpointStore(root / "checkpoints")
        harness = AgentHarness(
            provider=provider,
            tools=tools,
            profile=HarnessProfile(name="eval-profile"),
            budget=BudgetConfig(max_steps=8),
            trace_writer=trace,
            checkpoint_store=checkpoints,
            spill_dir=root / "spills",
        )
        result = await harness.run(task.input)
        passed, failures = await asyncio.to_thread(grade_outcome, task, result, workspace)
        return {
            "failures": failures,
            "passed": passed,
            "steps": result.steps,
            "stop_reason": result.stop_reason,
            "trial": trial_index,
        }


async def run_eval_suite(
    tasks_path: Path,
    *,
    trials: int = 3,
    gold: bool = False,
) -> dict[str, Any]:
    if isinstance(trials, bool) or not isinstance(trials, int) or trials < 1:
        raise ValueError("trials must be an integer >= 1")
    tasks = await asyncio.to_thread(load_tasks, tasks_path)
    task_reports: list[dict[str, Any]] = []
    total_passes = 0
    total_trials = 0

    for task in tasks:
        trial_results = [
            await run_single_trial(task, idx, gold=gold)
            for idx in range(1, trials + 1)
        ]
        passed_count = sum(1 for r in trial_results if r["passed"])
        total_passes += passed_count
        total_trials += trials
        k = trials
        ci_low, ci_high = wilson_ci(passed_count, trials)
        task_reports.append(
            {
                "gold_verified": gold and passed_count == trials,
                "id": task.id,
                "pass_at_1": round(pass_at_k(trials, passed_count, 1), 6),
                "pass_at_k": round(pass_at_k(trials, passed_count, k), 6),
                "pass_pow_k": round(pass_pow_k(trials, passed_count, k), 6),
                "passed_trials": passed_count,
                "total_trials": trials,
                "trials": trial_results,
                "wilson_ci_95": [round(ci_low, 6), round(ci_high, 6)],
            }
        )

    agg_low, agg_high = wilson_ci(total_passes, total_trials) if total_trials else (0.0, 0.0)
    mean_pass_at_1 = sum(t["pass_at_1"] for t in task_reports) / len(task_reports) if task_reports else 0.0
    mean_pass_at_k = sum(t["pass_at_k"] for t in task_reports) / len(task_reports) if task_reports else 0.0
    mean_pass_pow_k = sum(t["pass_pow_k"] for t in task_reports) / len(task_reports) if task_reports else 0.0

    return {
        "gold_mode": gold,
        "gold_verified": gold and all(t["gold_verified"] for t in task_reports),
        "pass_at_1": round(mean_pass_at_1, 6),
        "pass_at_k": round(mean_pass_at_k, 6),
        "pass_pow_k": round(mean_pass_pow_k, 6),
        "task_count": len(task_reports),
        "tasks": task_reports,
        "trials_per_task": trials,
        "wilson_ci_95": [round(agg_low, 6), round(agg_high, 6)],
    }


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected integer >= 1, got {raw!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError(f"Expected integer >= 1, got {value}")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run isolated multi-trial evaluations for {{PROJECT_NAME}}.")
    parser.add_argument("--tasks", type=Path, default=Path("evals/tasks.jsonl"))
    parser.add_argument("--trials", type=_positive_int, default=3)
    parser.add_argument("--gold", action="store_true", help="Verify tasks/graders with gold plans")
    parser.add_argument("--output", type=Path, default=None, help="Optional path to write JSON summary")
    args = parser.parse_args(argv)

    summary = asyncio.run(run_eval_suite(args.tasks, trials=args.trials, gold=args.gold))
    rendered = json.dumps(summary, sort_keys=True, indent=2, ensure_ascii=False)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if args.gold and not summary["gold_verified"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
