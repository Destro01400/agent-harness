"""End-to-end invariant tests for {{PROJECT_NAME}}."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from {{PACKAGE_NAME}}.eval_runner import pass_at_k, pass_pow_k, run_eval_suite, wilson_ci
from {{PACKAGE_NAME}}.harness import (
    AgentHarness,
    BudgetConfig,
    CheckpointStore,
    LoopDetectionHook,
    PreCompletionVerifyHook,
    TraceWriter,
)
from {{PACKAGE_NAME}}.provider import HarnessProfile, MockProvider, ModelResponse, ToolCall, Usage
from {{PACKAGE_NAME}}.tools import (
    ApprovalPolicy,
    ToolRegistry,
    ToolSpec,
    build_safe_env,
    create_default_tools,
    resolve_in_workspace,
)


class HarnessInvariantsTest(unittest.IsolatedAsyncioTestCase):
    async def test_normal_run_and_reasoning_echo_and_role_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            (ws / "hello.txt").write_text("alpha-42", encoding="utf-8")

            provider = MockProvider(
                responses=[
                    ModelResponse(
                        content="",
                        reasoning_content="Inspect hello.txt first.",
                        tool_calls=(ToolCall(id="call_1", name="read_file", arguments={"path": "hello.txt"}),),
                        usage=Usage(tokens_in=100, tokens_cached=0, tokens_out=25, thinking_tokens=10, cost_usd=0.001),
                    ),
                    ModelResponse(
                        content="File contains alpha-42.",
                        reasoning_content="Verified content from tool output.",
                        usage=Usage(tokens_in=140, tokens_cached=90, tokens_out=18, thinking_tokens=6, cost_usd=0.001),
                    ),
                ]
            )
            trace = TraceWriter(root / "trace.jsonl", session_id="s_normal")
            harness = AgentHarness(
                provider=provider,
                tools=create_default_tools(ws),
                trace_writer=trace,
                checkpoint_store=CheckpointStore(root / "ckpts"),
                spill_dir=root / "spills",
            )

            result = await harness.run("Read hello.txt")
            self.assertEqual(result.stop_reason, "completed")
            self.assertIn("alpha-42", result.final_output)
            self.assertEqual(len(provider.recorded_calls), 2)

            second_call_messages = provider.recorded_calls[1]["messages"]
            # System prompt prefix stays immutable across turns.
            self.assertEqual(
                provider.recorded_calls[0]["messages"][0],
                second_call_messages[0],
            )
            # Reasoning content from turn 1 is echoed verbatim on the assistant turn.
            self.assertEqual(second_call_messages[2]["reasoning_content"], "Inspect hello.txt first.")
            # Tool result is strictly emitted with role="tool".
            self.assertEqual(second_call_messages[3]["role"], "tool")
            self.assertEqual(second_call_messages[3]["tool_call_id"], "call_1")

    async def test_tool_timeout_keeps_error_in_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            async def slow_tool(_args: dict[str, object]) -> str:
                await asyncio.sleep(0.5)
                return "too late"

            registry = ToolRegistry(
                [
                    ToolSpec(
                        name="slow_op",
                        description="Simulated slow operation.",
                        parameters={"additionalProperties": False, "properties": {}, "required": [], "type": "object"},
                        handler=slow_tool,
                        timeout_s=0.05,
                    )
                ]
            )
            provider = MockProvider(
                responses=[
                    ModelResponse(
                        content="",
                        tool_calls=(ToolCall(id="t_slow", name="slow_op", arguments={}),),
                        usage=Usage(tokens_in=50, tokens_out=10),
                    ),
                    ModelResponse(
                        content="Handled timeout gracefully.",
                        usage=Usage(tokens_in=80, tokens_cached=40, tokens_out=12),
                    ),
                ]
            )
            harness = AgentHarness(
                provider=provider,
                tools=registry,
                trace_writer=TraceWriter(root / "trace.jsonl", session_id="s_timeout"),
                checkpoint_store=CheckpointStore(root / "ckpts"),
                spill_dir=root / "spills",
            )
            result = await harness.run("Run slow op")
            self.assertEqual(result.stop_reason, "completed")
            tool_messages = [m for m in result.messages if m.role == "tool"]
            self.assertEqual(len(tool_messages), 1)
            self.assertIn("ERROR [timeout]", tool_messages[0].content)

    async def test_output_truncation_and_disk_spill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            (ws / "big.txt").write_text("X" * 2000, encoding="utf-8")

            provider = MockProvider(
                responses=[
                    ModelResponse(
                        content="",
                        tool_calls=(ToolCall(id="t_big", name="read_file", arguments={"path": "big.txt"}),),
                        usage=Usage(tokens_in=60, tokens_out=10),
                    ),
                    ModelResponse(
                        content="Read spilled summary.",
                        usage=Usage(tokens_in=90, tokens_cached=50, tokens_out=10),
                    ),
                ]
            )
            spill_dir = root / "spills"
            harness = AgentHarness(
                provider=provider,
                tools=create_default_tools(ws),
                profile=HarnessProfile(max_output_chars=240),
                trace_writer=TraceWriter(root / "trace.jsonl", session_id="s_spill"),
                checkpoint_store=CheckpointStore(root / "ckpts"),
                spill_dir=spill_dir,
            )
            result = await harness.run("Read big.txt")
            self.assertEqual(result.stop_reason, "completed")
            tool_msg = next(m for m in result.messages if m.role == "tool")
            self.assertIn("truncated", tool_msg.content)
            spilled_files = list(spill_dir.glob("*.txt"))
            self.assertEqual(len(spilled_files), 1)
            self.assertEqual(len(spilled_files[0].read_text(encoding="utf-8")), 2000)

    async def test_doom_loop_detection_hook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            (ws / "a.txt").write_text("same", encoding="utf-8")

            repeated_call = ToolCall(id="tc_rep", name="read_file", arguments={"path": "a.txt"})
            provider = MockProvider(
                responses=[
                    ModelResponse(content="", tool_calls=(repeated_call,), usage=Usage(tokens_in=50, tokens_out=10)),
                    ModelResponse(content="", tool_calls=(ToolCall(id="tc_rep2", name="read_file", arguments={"path": "a.txt"}),), usage=Usage(tokens_in=70, tokens_cached=40, tokens_out=10)),
                    ModelResponse(content="", tool_calls=(ToolCall(id="tc_rep3", name="read_file", arguments={"path": "a.txt"}),), usage=Usage(tokens_in=90, tokens_cached=60, tokens_out=10)),
                    ModelResponse(content="Stopped repeating.", usage=Usage(tokens_in=110, tokens_cached=80, tokens_out=10)),
                ]
            )
            harness = AgentHarness(
                provider=provider,
                tools=create_default_tools(ws),
                trace_writer=TraceWriter(root / "trace.jsonl", session_id="s_loop"),
                checkpoint_store=CheckpointStore(root / "ckpts"),
                spill_dir=root / "spills",
                hooks=[LoopDetectionHook(max_identical_repeats=2)],
            )
            result = await harness.run("Loop test")
            self.assertEqual(result.stop_reason, "completed")
            tool_outputs = [m.content for m in result.messages if m.role == "tool"]
            self.assertTrue(any("doom_loop_detected" in text for text in tool_outputs))

    async def test_approval_three_rejection_circuit_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()

            policy = ApprovalPolicy(
                default_decision="ask",
                decider=lambda _name, _args: "deny_once",
                max_consecutive_rejections=3,
            )
            provider = MockProvider(
                responses=[
                    ModelResponse(content="", tool_calls=(ToolCall(id="d1", name="write_file", arguments={"path": "a.txt", "content": "1"}),), usage=Usage(tokens_in=50, tokens_out=10)),
                    ModelResponse(content="", tool_calls=(ToolCall(id="d2", name="write_file", arguments={"path": "b.txt", "content": "2"}),), usage=Usage(tokens_in=70, tokens_cached=40, tokens_out=10)),
                    ModelResponse(content="", tool_calls=(ToolCall(id="d3", name="write_file", arguments={"path": "c.txt", "content": "3"}),), usage=Usage(tokens_in=90, tokens_cached=60, tokens_out=10)),
                    ModelResponse(content="Should not reach turn 4.", usage=Usage(tokens_in=100, tokens_cached=70, tokens_out=10)),
                ]
            )
            harness = AgentHarness(
                provider=provider,
                tools=create_default_tools(ws),
                trace_writer=TraceWriter(root / "trace.jsonl", session_id="s_deny"),
                checkpoint_store=CheckpointStore(root / "ckpts"),
                approval_policy=policy,
                spill_dir=root / "spills",
            )
            result = await harness.run("Try writing")
            self.assertEqual(result.stop_reason, "approval_circuit_breaker")
            self.assertTrue(policy.circuit_open)
            self.assertEqual(result.steps, 3)

    async def test_budget_cap_and_atomic_checkpoint_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            (ws / "x.txt").write_text("checkpoint-ok", encoding="utf-8")

            checkpoints = CheckpointStore(root / "ckpts")
            trace_path = root / "trace.jsonl"

            provider_part1 = MockProvider(
                responses=[
                    ModelResponse(
                        content="",
                        tool_calls=(ToolCall(id="c1", name="read_file", arguments={"path": "x.txt"}),),
                        usage=Usage(tokens_in=60, tokens_out=10),
                    ),
                ]
            )
            harness1 = AgentHarness(
                provider=provider_part1,
                tools=create_default_tools(ws),
                budget=BudgetConfig(max_steps=1),
                trace_writer=TraceWriter(trace_path, session_id="s_resume"),
                checkpoint_store=checkpoints,
                spill_dir=root / "spills",
            )
            part1 = await harness1.run("Read x.txt")
            self.assertEqual(part1.stop_reason, "max_steps")
            self.assertEqual(part1.steps, 1)

            provider_part2 = MockProvider(
                responses=[
                    ModelResponse(
                        content="Resumed and saw checkpoint-ok.",
                        usage=Usage(tokens_in=90, tokens_cached=50, tokens_out=15),
                    ),
                ]
            )
            harness2 = AgentHarness(
                provider=provider_part2,
                tools=create_default_tools(ws),
                budget=BudgetConfig(max_steps=3),
                trace_writer=TraceWriter(trace_path, session_id="s_resume"),
                checkpoint_store=checkpoints,
                spill_dir=root / "spills",
            )
            part2 = await harness2.run("Read x.txt", resume=True)
            self.assertEqual(part2.stop_reason, "completed")
            self.assertEqual(part2.steps, 2)
            self.assertIn("checkpoint-ok", part2.final_output)

    async def test_pre_completion_verify_hook_and_trace_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            fake_key = "sk-" + "live" + "9876543210abcdef"
            fake_ghp = "ghp_" + "A" * 24

            provider = MockProvider(
                responses=[
                    ModelResponse(
                        content="",
                        tool_calls=(
                            ToolCall(
                                id="w1",
                                name="write_file",
                                arguments={"path": "out.txt", "content": f"key={fake_key} tok={fake_ghp}"},
                            ),
                        ),
                        usage=Usage(tokens_in=60, tokens_out=12),
                    ),
                    ModelResponse(
                        content="Done without verifying.",
                        usage=Usage(tokens_in=90, tokens_cached=50, tokens_out=10),
                    ),
                    ModelResponse(
                        content="",
                        tool_calls=(
                            ToolCall(id="v1", name="verify_file", arguments={"path": "out.txt", "contains": "key="}),
                        ),
                        usage=Usage(tokens_in=120, tokens_cached=80, tokens_out=12),
                    ),
                    ModelResponse(
                        content="Verified out.txt cleanly.",
                        usage=Usage(tokens_in=150, tokens_cached=100, tokens_out=10),
                    ),
                ]
            )
            trace_path = root / "trace.jsonl"
            harness = AgentHarness(
                provider=provider,
                tools=create_default_tools(ws),
                trace_writer=TraceWriter(trace_path, session_id="s_verify"),
                checkpoint_store=CheckpointStore(root / "ckpts"),
                spill_dir=root / "spills",
                hooks=[PreCompletionVerifyHook(max_nudges=1)],
            )
            result = await harness.run("Write out.txt")
            self.assertEqual(result.stop_reason, "completed")
            self.assertIn("verify_file", result.tool_calls_made)

            raw_trace = trace_path.read_text(encoding="utf-8")
            self.assertNotIn(fake_key, raw_trace)
            self.assertNotIn(fake_ghp, raw_trace)
            self.assertIn("[REDACTED]", raw_trace)

            events = [json.loads(line) for line in raw_trace.splitlines() if line.strip()]
            timestamps = [e["timestamp"] for e in events]
            self.assertEqual(timestamps, sorted(timestamps))

    async def test_workspace_containment_and_safe_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            with self.assertRaises(ValueError):
                resolve_in_workspace(ws, "../outside.txt")
            env = build_safe_env({"PATH": "/usr/bin", "SECRET_API_KEY": "should_not_leak"}, allowlist=("PATH",))
            self.assertEqual(env, {"PATH": "/usr/bin"})

    async def test_multi_trial_eval_runner_and_metrics(self) -> None:
        self.assertAlmostEqual(pass_at_k(5, 2, 2), 0.7, places=6)
        self.assertAlmostEqual(pass_pow_k(5, 2, 2), 0.1, places=6)
        low, high = wilson_ci(3, 3)
        self.assertGreater(low, 0.4)
        self.assertLessEqual(high, 1.0)

        summary = await run_eval_suite(ROOT / "evals" / "tasks.jsonl", trials=3, gold=True)
        self.assertEqual(summary["task_count"], 3)
        self.assertEqual(summary["trials_per_task"], 3)
        self.assertTrue(summary["gold_verified"])
        self.assertEqual(summary["pass_pow_k"], 1.0)
        self.assertEqual(summary["pass_at_k"], 1.0)


if __name__ == "__main__":
    unittest.main()
