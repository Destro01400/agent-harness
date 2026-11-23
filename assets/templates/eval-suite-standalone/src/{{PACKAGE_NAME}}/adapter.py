"""Agent adapter protocol, evaluation task model, and offline demo / --gold adapters."""

from __future__ import annotations

import asyncio
import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class EvalTask:
    """Single benchmark task with deterministic graders and optional gold outcome."""

    id: str
    input: str
    expected: dict[str, Any]
    graders: tuple[dict[str, Any], ...]
    tags: tuple[str, ...] = ()
    setup_files: dict[str, str] = field(default_factory=dict)
    gold_result: dict[str, Any] = field(default_factory=dict)
    demo_result: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrialResult:
    """Normalized outcome returned by any AgentAdapter for one isolated trial."""

    task_id: str
    trial_index: int
    output: str
    steps: int
    tools_used: tuple[str, ...] = ()
    final_state: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: float = 0.0


class AgentAdapter(Protocol):
    """Thin boundary decoupling the eval harness from any specific agent runtime."""

    async def run_trial(
        self,
        task: EvalTask,
        workspace: Path,
        trial_index: int,
    ) -> TrialResult:
        ...


def load_tasks(path: Path) -> list[EvalTask]:
    """Load and validate a JSONL evaluation dataset (unique non-empty task IDs)."""
    tasks: list[EvalTask] = []
    seen_ids: set[str] = set()
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        item = json.loads(stripped)
        task_id = str(item.get("id", "")).strip()
        if not task_id:
            raise ValueError(f"Missing task id at line {line_no}")
        if task_id in seen_ids:
            raise ValueError(f"Duplicate task id at line {line_no}: {task_id}")
        seen_ids.add(task_id)
        if not isinstance(item.get("input"), str) or not item["input"].strip():
            raise ValueError(f"Task '{task_id}' must have a non-empty string 'input'")
        graders = tuple(item.get("graders", ()))
        if not graders:
            raise ValueError(f"Task '{task_id}' must define at least one grader")
        tasks.append(
            EvalTask(
                id=task_id,
                input=item["input"],
                expected=dict(item.get("expected", {})),
                graders=graders,
                tags=tuple(str(t) for t in item.get("tags", ())),
                setup_files=dict(item.get("setup_files", {})),
                gold_result=dict(item.get("gold_result", {})),
                demo_result=dict(item.get("demo_result", {})),
            )
        )
    return tasks


def _write_workspace_files(workspace: Path, files: dict[str, Any]) -> None:
    ws_real = Path(os.path.realpath(workspace))
    for rel_path, content in files.items():
        dest = Path(os.path.realpath(ws_real / str(rel_path)))
        if os.path.commonpath([str(ws_real), str(dest)]) != str(ws_real):
            raise ValueError(f"Refusing to write outside workspace: {rel_path!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(str(content), encoding="utf-8")


class GoldReferenceAdapter:
    """Deterministic gold reference adapter used by --gold to verify task/grader soundness."""

    async def run_trial(
        self,
        task: EvalTask,
        workspace: Path,
        trial_index: int,
    ) -> TrialResult:
        spec = task.gold_result
        write_files = spec.get("write_files", {})
        if write_files:
            await asyncio.to_thread(_write_workspace_files, workspace, dict(write_files))
        return TrialResult(
            task_id=task.id,
            trial_index=trial_index,
            output=str(spec.get("output", "")),
            steps=int(spec.get("steps", 1)),
            tools_used=tuple(str(t) for t in spec.get("tools_used", ())),
            final_state=copy.deepcopy(dict(spec.get("final_state", {}))),
            duration_ms=1.0,
        )


class DemoAdapter:
    """Offline demo adapter simulating candidate agent runs without external API calls."""

    async def run_trial(
        self,
        task: EvalTask,
        workspace: Path,
        trial_index: int,
    ) -> TrialResult:
        spec = task.demo_result or task.gold_result
        write_files = spec.get("write_files", {})
        if write_files:
            await asyncio.to_thread(_write_workspace_files, workspace, dict(write_files))
        return TrialResult(
            task_id=task.id,
            trial_index=trial_index,
            output=str(spec.get("output", "")),
            steps=int(spec.get("steps", 1)),
            tools_used=tuple(str(t) for t in spec.get("tools_used", ())),
            final_state=copy.deepcopy(dict(spec.get("final_state", {}))),
            duration_ms=2.0,
        )
