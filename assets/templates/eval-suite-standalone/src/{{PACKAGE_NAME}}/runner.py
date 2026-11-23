"""Concurrency-bounded multi-trial eval runner with pass@k, pass^k, Wilson CI, clustered SE, and baseline gate."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import tempfile
from pathlib import Path
from typing import Any, Sequence

from {{PACKAGE_NAME}}.adapter import (
    AgentAdapter,
    DemoAdapter,
    EvalTask,
    GoldReferenceAdapter,
    TrialResult,
    load_tasks,
)
from {{PACKAGE_NAME}}.graders import grade_trial


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


def clustered_stderr(task_rates: Sequence[float]) -> float:
    """Task-clustered standard error across per-task pass rates (accounts for repeated-trial correlation)."""
    g = len(task_rates)
    if g < 2:
        return 0.0
    values: list[float] = []
    for rate in task_rates:
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate):
            raise ValueError(f"Invalid task rate: {rate!r}")
        values.append(float(rate))
    mean = sum(values) / g
    sum_sq = sum((r - mean) ** 2 for r in values)
    return math.sqrt(sum_sq / (g * (g - 1)))


def _setup_workspace(workspace: Path, setup_files: dict[str, str]) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    for rel_path, content in setup_files.items():
        dest = workspace / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


async def _execute_isolated_trial(
    adapter: AgentAdapter,
    task: EvalTask,
    trial_index: int,
    semaphore: asyncio.Semaphore,
    trial_timeout_s: float,
) -> dict[str, Any]:
    async with semaphore:
        with tempfile.TemporaryDirectory(prefix=f"suite_{task.id}_t{trial_index}_") as tmp:
            workspace = Path(tmp) / "workspace"
            await asyncio.to_thread(_setup_workspace, workspace, task.setup_files)

            try:
                trial_result = await asyncio.wait_for(
                    adapter.run_trial(task, workspace, trial_index),
                    timeout=trial_timeout_s,
                )
            except asyncio.TimeoutError:
                trial_result = TrialResult(
                    task_id=task.id,
                    trial_index=trial_index,
                    output="",
                    steps=0,
                    error=f"Trial timed out after {trial_timeout_s:.2f}s",
                )
            except Exception as exc:
                trial_result = TrialResult(
                    task_id=task.id,
                    trial_index=trial_index,
                    output="",
                    steps=0,
                    error=f"Adapter error ({type(exc).__name__}): {exc}",
                )

            passed, outcomes = await asyncio.to_thread(grade_trial, task, trial_result, workspace)
            return {
                "duration_ms": round(trial_result.duration_ms, 2),
                "error": trial_result.error,
                "graders": [
                    {"detail": o.detail, "passed": o.passed, "type": o.grader_type}
                    for o in outcomes
                ],
                "passed": passed,
                "steps": trial_result.steps,
                "trial": trial_index,
            }


async def run_eval_suite(
    tasks_path: Path,
    *,
    adapter: AgentAdapter | None = None,
    trials: int = 3,
    max_concurrency: int = 4,
    trial_timeout_s: float = 30.0,
    gold: bool = False,
) -> dict[str, Any]:
    """Run all tasks across k trials with bounded concurrency and isolated temp workspaces."""
    if isinstance(trials, bool) or not isinstance(trials, int) or trials < 1:
        raise ValueError("trials must be an integer >= 1")
    if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or max_concurrency < 1:
        raise ValueError("max_concurrency must be an integer >= 1")
    if trial_timeout_s <= 0:
        raise ValueError("trial_timeout_s must be > 0")

    tasks = await asyncio.to_thread(load_tasks, tasks_path)
    active_adapter: AgentAdapter = (
        GoldReferenceAdapter() if gold else (adapter if adapter is not None else DemoAdapter())
    )
    semaphore = asyncio.Semaphore(max_concurrency)

    scheduled: list[tuple[EvalTask, list[asyncio.Task[dict[str, Any]]]]] = []
    for task in tasks:
        task_coros = [
            asyncio.create_task(
                _execute_isolated_trial(active_adapter, task, idx, semaphore, trial_timeout_s)
            )
            for idx in range(1, trials + 1)
        ]
        scheduled.append((task, task_coros))

    task_reports: list[dict[str, Any]] = []
    total_passes = 0
    total_trials = 0

    for task, futures in scheduled:
        trial_results = await asyncio.gather(*futures)
        passed_count = sum(1 for r in trial_results if r["passed"])
        total_passes += passed_count
        total_trials += trials
        ci_low, ci_high = wilson_ci(passed_count, trials)
        task_reports.append(
            {
                "gold_verified": gold and passed_count == trials,
                "id": task.id,
                "pass_at_1": round(pass_at_k(trials, passed_count, 1), 6),
                "pass_at_k": round(pass_at_k(trials, passed_count, trials), 6),
                "pass_pow_k": round(pass_pow_k(trials, passed_count, trials), 6),
                "passed_trials": passed_count,
                "tags": list(task.tags),
                "total_trials": trials,
                "trials": trial_results,
                "wilson_ci_95": [round(ci_low, 6), round(ci_high, 6)],
            }
        )

    agg_low, agg_high = wilson_ci(total_passes, total_trials) if total_trials else (0.0, 0.0)
    task_rates = [t["passed_trials"] / t["total_trials"] for t in task_reports]
    se_cluster = clustered_stderr(task_rates)
    mean_at_1 = sum(t["pass_at_1"] for t in task_reports) / len(task_reports) if task_reports else 0.0
    mean_at_k = sum(t["pass_at_k"] for t in task_reports) / len(task_reports) if task_reports else 0.0
    mean_pow_k = sum(t["pass_pow_k"] for t in task_reports) / len(task_reports) if task_reports else 0.0

    return {
        "clustered_stderr": round(se_cluster, 6),
        "gold_mode": gold,
        "gold_verified": gold and all(t["gold_verified"] for t in task_reports),
        "pass_at_1": round(mean_at_1, 6),
        "pass_at_k": round(mean_at_k, 6),
        "pass_pow_k": round(mean_pow_k, 6),
        "task_count": len(task_reports),
        "tasks": task_reports,
        "trials_per_task": trials,
        "wilson_ci_95": [round(agg_low, 6), round(agg_high, 6)],
    }


def compare_baseline(
    summary: dict[str, Any],
    baseline: dict[str, Any],
    *,
    max_drop: float = 0.05,
) -> dict[str, Any]:
    """Compare current eval summary against a committed baseline for CI regression gating."""
    regressions: list[dict[str, Any]] = []
    for metric in ("pass_at_1", "pass_pow_k"):
        if metric in baseline:
            base_val = float(baseline[metric])
            curr_val = float(summary.get(metric, 0.0))
            if base_val - curr_val > max_drop + 1e-9:
                regressions.append(
                    {
                        "baseline": base_val,
                        "current": curr_val,
                        "delta": round(curr_val - base_val, 6),
                        "metric": metric,
                        "scope": "suite",
                    }
                )

    base_tasks: dict[str, dict[str, Any]] = {
        str(t["id"]): t for t in baseline.get("tasks", ())
    }
    curr_tasks: dict[str, dict[str, Any]] = {
        str(t["id"]): t for t in summary.get("tasks", ())
    }

    for task_id, base_task in sorted(base_tasks.items()):
        curr_task = curr_tasks.get(task_id)
        if curr_task is None:
            regressions.append(
                {
                    "baseline": base_task.get("pass_pow_k", 1.0),
                    "current": 0.0,
                    "delta": -float(base_task.get("pass_pow_k", 1.0)),
                    "metric": "missing_task",
                    "scope": task_id,
                }
            )
            continue
        for metric in ("pass_at_1", "pass_pow_k"):
            if metric not in base_task:
                continue
            base_rate = float(base_task.get(metric, 0.0))
            curr_rate = float(curr_task.get(metric, 0.0))
            if base_rate - curr_rate > max_drop + 1e-9:
                regressions.append(
                    {
                        "baseline": base_rate,
                        "current": curr_rate,
                        "delta": round(curr_rate - base_rate, 6),
                        "metric": metric,
                        "scope": task_id,
                    }
                )

    return {
        "max_allowed_drop": max_drop,
        "passed": len(regressions) == 0,
        "regressions": regressions,
    }


def render_markdown_report(
    summary: dict[str, Any],
    gate: dict[str, Any] | None = None,
) -> str:
    """Render a compact Markdown report suitable for PR comments and CI artifacts."""
    se_val = float(summary.get("clustered_stderr", 0.0))
    lines = [
        "# Evaluation Summary",
        "",
        f"- **Tasks:** {summary['task_count']} | **Trials/task:** {summary['trials_per_task']} | **Gold mode:** `{summary['gold_mode']}`",
        f"- **pass@1:** `{summary['pass_at_1']:.3f}` | **pass@k:** `{summary['pass_at_k']:.3f}` | **pass^k:** `{summary['pass_pow_k']:.3f}`",
        f"- **Aggregate Wilson 95% CI:** `[{summary['wilson_ci_95'][0]:.3f}, {summary['wilson_ci_95'][1]:.3f}]` | **Clustered SE:** `{se_val:.4f}`",
    ]
    if gate is not None:
        status = "PASS" if gate["passed"] else "FAIL"
        lines.append(f"- **Baseline Regression Gate:** `{status}` (max drop `{gate['max_allowed_drop']}`)")
    lines.extend(
        [
            "",
            "| Task | Passed | pass@1 | pass@k | pass^k | Wilson 95% CI |",
            "|---|---:|---:|---:|---:|---|",
        ]
    )
    for task in summary["tasks"]:
        ci = task["wilson_ci_95"]
        lines.append(
            f"| `{task['id']}` | {task['passed_trials']}/{task['total_trials']} "
            f"| {task['pass_at_1']:.3f} | {task['pass_at_k']:.3f} | {task['pass_pow_k']:.3f} "
            f"| [{ci[0]:.3f}, {ci[1]:.3f}] |"
        )
    if gate is not None and gate["regressions"]:
        lines.extend(["", "## Regressions", ""])
        for reg in gate["regressions"]:
            lines.append(
                f"- `{reg['scope']}` `{reg['metric']}`: {reg['baseline']:.3f} -> {reg['current']:.3f} ({reg['delta']:+.3f})"
            )
    return "\n".join(lines) + "\n"


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected integer >= 1, got {raw!r}") from exc
    if value < 1:
        raise argparse.ArgumentTypeError(f"Expected integer >= 1, got {value}")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run standalone agent evaluation suite.")
    parser.add_argument("--tasks", type=Path, default=Path("datasets/tasks.jsonl"))
    parser.add_argument("--trials", type=_positive_int, default=3)
    parser.add_argument("--concurrency", type=_positive_int, default=4)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--gold", action="store_true", help="Verify graders using gold reference adapter")
    parser.add_argument("--baseline", type=Path, default=None, help="Path to baseline.json for regression gate")
    parser.add_argument("--max-drop", type=float, default=0.05)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--md-out", type=Path, default=None)
    args = parser.parse_args(argv)

    summary = asyncio.run(
        run_eval_suite(
            args.tasks,
            trials=args.trials,
            max_concurrency=args.concurrency,
            trial_timeout_s=args.timeout,
            gold=args.gold,
        )
    )

    gate: dict[str, Any] | None = None
    if args.baseline is not None:
        baseline_data = json.loads(args.baseline.read_text(encoding="utf-8-sig"))
        gate = compare_baseline(summary, baseline_data, max_drop=args.max_drop)
        summary["baseline_gate"] = gate

    json_text = json.dumps(summary, sort_keys=True, indent=2, ensure_ascii=False)
    md_text = render_markdown_report(summary, gate)

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json_text + "\n", encoding="utf-8")
    if args.md_out is not None:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(md_text, encoding="utf-8")

    print(json_text)

    if args.gold and not summary["gold_verified"]:
        return 1
    if gate is not None and not gate["passed"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
