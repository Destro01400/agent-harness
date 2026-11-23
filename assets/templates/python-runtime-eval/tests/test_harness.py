"""End-to-end invariant and security regression tests for {{PROJECT_NAME}}."""

from __future__ import annotations

import asyncio
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Sequence

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
    derive_messages_from_trace,
    redact_secrets,
)
from {{PACKAGE_NAME}}.provider import (
    HarnessProfile,
    Message,
    MockProvider,
    ModelResponse,
    ToolCall,
    Usage,
)
from {{PACKAGE_NAME}}.tools import (
    ApprovalDirective,
    ApprovalPolicy,
    ToolRegistry,
    ToolSpec,
    build_safe_env,
    create_default_tools,
    resolve_in_workspace,
    truncate_and_spill,
)


class _SlowProvider:
    async def complete(
        self,
        messages: Sequence[Message],
        tools: Sequence[dict[str, Any]],
        profile: HarnessProfile,
    ) -> ModelResponse:
        await asyncio.sleep(0.5)
        return ModelResponse(content="too slow")


class HarnessInvariantsTest(unittest.IsolatedAsyncioTestCase):
    async def test_normal_run_reasoning_echo_role_tool_and_trace_projection(self) -> None:
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
            trace_path = root / "trace.jsonl"
            trace = TraceWriter(trace_path, session_id="s_normal")
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

            # Pure Model-visible <=> logged projection from JSONL trace.
            derived = derive_messages_from_trace(trace_path)
            self.assertEqual(tuple(derived), result.messages)

            # Canonical top-level fields on tool/call and tool/result events.
            events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            tool_call_ev = next(ev for ev in events if ev["event_type"] == "tool/call")
            tool_result_ev = next(ev for ev in events if ev["event_type"] == "tool/result")
            self.assertEqual(tool_call_ev["tool_call_id"], "call_1")
            self.assertEqual(tool_call_ev["tool_name"], "read_file")
            self.assertEqual(tool_result_ev["tool_call_id"], "call_1")
            self.assertFalse(tool_result_ev["is_error"])
            self.assertEqual(tool_result_ev["status"], "ok")

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

    async def test_output_truncation_strictly_bounded_at_120_and_disk_spill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            direct_spill = root / "direct_spills"
            source = "HEAD_" + ("A" * 1990) + "_TAIL"

            bounded, truncated, spill_path = truncate_and_spill(source, 120, direct_spill, "unit_test")
            self.assertTrue(truncated)
            self.assertLessEqual(len(bounded), 120)
            self.assertIsNotNone(spill_path)
            self.assertEqual(Path(spill_path or "").read_text(encoding="utf-8"), source)

            notice_match = re.search(r"\n\.\.\.\[truncated (\d+) chars; full: [^\]]+\]\.\.\.\n", bounded)
            self.assertIsNotNone(notice_match)
            reported_omitted = int(notice_match.group(1))  # type: ignore[union-attr]
            kept_chars = len(bounded) - len(notice_match.group(0))  # type: ignore[union-attr]
            self.assertEqual(reported_omitted, len(source) - kept_chars)

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
                profile=HarnessProfile(max_output_chars=120),
                trace_writer=TraceWriter(root / "trace.jsonl", session_id="s_spill"),
                checkpoint_store=CheckpointStore(root / "ckpts"),
                spill_dir=spill_dir,
            )
            result = await harness.run("Read big.txt")
            self.assertEqual(result.stop_reason, "completed")
            tool_msg = next(m for m in result.messages if m.role == "tool")
            self.assertIn("truncated", tool_msg.content)
            self.assertLessEqual(len(tool_msg.content), 120)
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

    async def test_inspect_ai_approval_policy_modify_validation_order_and_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            tools = create_default_tools(ws)

            # 1. Schema validation MUST run before approval_policy.evaluate().
            decider_calls = 0

            def counting_reject(_name: str, _args: Any) -> str:
                nonlocal decider_calls
                decider_calls += 1
                return "reject"

            strict_policy = ApprovalPolicy(
                default_decision="escalate",
                decider=counting_reject,  # type: ignore[arg-type]
                max_consecutive_rejections=3,
            )
            malformed = await tools.execute(
                ToolCall(id="bad_1", name="write_file", arguments={"path": "missing_content.txt"}),
                approval_policy=strict_policy,
                spill_dir=root / "spills",
            )
            self.assertFalse(malformed.ok)
            self.assertEqual(malformed.error_code, "invalid_arguments")
            self.assertEqual(decider_calls, 0)
            self.assertEqual(strict_policy.consecutive_rejections, 0)

            # 2. 'modify' returns new arguments without mutating caller dict and executes sanitized call.
            original_args = {"path": "note.txt", "content": "raw-unsafe"}
            modify_policy = ApprovalPolicy(
                default_decision="escalate",
                decider=lambda _name, args: ApprovalDirective(
                    decision="modify",
                    reason="Sanitized payload",
                    modified_arguments={"path": str(args["path"]), "content": "sanitized-safe"},
                ),
            )
            mod_res = await tools.execute(
                ToolCall(id="mod_1", name="write_file", arguments=original_args),
                approval_policy=modify_policy,
                spill_dir=root / "spills",
            )
            self.assertTrue(mod_res.ok)
            self.assertEqual(mod_res.approval_decision, "modify")
            self.assertEqual(original_args["content"], "raw-unsafe")
            self.assertEqual((ws / "note.txt").read_text(encoding="utf-8"), "sanitized-safe")

            # 3. 'modify' returning schema-invalid arguments is refused.
            bad_mod_policy = ApprovalPolicy(
                default_decision="escalate",
                decider=lambda _name, _args: ApprovalDirective(
                    decision="modify",
                    modified_arguments={"path": "note.txt", "content": 12345},
                ),
            )
            bad_mod_res = await tools.execute(
                ToolCall(id="mod_bad", name="write_file", arguments={"path": "note.txt", "content": "ok"}),
                approval_policy=bad_mod_policy,
                spill_dir=root / "spills",
            )
            self.assertFalse(bad_mod_res.ok)
            self.assertEqual(bad_mod_res.error_code, "invalid_modified_arguments")

            # 4. Attempting to rename tool during 'modify' is refused.
            rename_policy = ApprovalPolicy(
                default_decision="escalate",
                decider=lambda _name, _args: ApprovalDirective(
                    decision="modify",
                    tool_name="read_file",
                    modified_arguments={"path": "note.txt"},
                ),
            )
            rename_res = await tools.execute(
                ToolCall(id="mod_ren", name="write_file", arguments={"path": "note.txt", "content": "ok"}),
                approval_policy=rename_policy,
                spill_dir=root / "spills",
            )
            self.assertFalse(rename_res.ok)
            self.assertIn("cannot rename tool", rename_res.output)

            # 5. Three consecutive rejections upgrade to 'terminate' and halt AgentHarness.
            reject_policy = ApprovalPolicy(
                default_decision="escalate",
                decider=lambda _name, _args: "reject",
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
                tools=tools,
                trace_writer=TraceWriter(root / "trace.jsonl", session_id="s_deny"),
                checkpoint_store=CheckpointStore(root / "ckpts"),
                approval_policy=reject_policy,
                spill_dir=root / "spills",
            )
            result = await harness.run("Try writing")
            self.assertEqual(result.stop_reason, "approval_circuit_breaker")
            self.assertTrue(reject_policy.circuit_open)
            self.assertEqual(result.steps, 3)
            self.assertTrue(
                any(m.role == "tool" and "approval_denied:terminate" in m.content for m in result.messages)
            )

    async def test_budgets_soft_warning_llm_timeout_and_completed_checkpoint_resume(self) -> None:
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

            # Resuming a completed checkpoint returns immediately without invoking provider.
            spy_provider = MockProvider(responses=[ModelResponse(content="Should not run")])
            harness3 = AgentHarness(
                provider=spy_provider,
                tools=create_default_tools(ws),
                budget=BudgetConfig(max_steps=5),
                trace_writer=TraceWriter(trace_path, session_id="s_resume"),
                checkpoint_store=checkpoints,
                spill_dir=root / "spills",
            )
            part3 = await harness3.run("Read x.txt", resume=True)
            self.assertEqual(part3.stop_reason, "completed")
            self.assertEqual(len(spy_provider.recorded_calls), 0)
            self.assertEqual(part3.final_output, "Resumed and saw checkpoint-ok.")

            # Soft budget warning injected at >= 75% utilization.
            soft_provider = MockProvider(
                responses=[
                    ModelResponse(
                        content="",
                        tool_calls=(ToolCall(id="sw1", name="read_file", arguments={"path": "x.txt"}),),
                        usage=Usage(tokens_in=80, tokens_out=10),
                    ),
                    ModelResponse(
                        content="Wrapped up after budget warning.",
                        usage=Usage(tokens_in=90, tokens_cached=50, tokens_out=10),
                    ),
                ]
            )
            soft_harness = AgentHarness(
                provider=soft_provider,
                tools=create_default_tools(ws),
                budget=BudgetConfig(max_tokens_in=100, max_steps=5),
                trace_writer=TraceWriter(root / "soft.jsonl", session_id="s_soft"),
                checkpoint_store=checkpoints,
                spill_dir=root / "spills",
            )
            soft_res = await soft_harness.run("Trigger soft budget warning")
            self.assertEqual(soft_res.stop_reason, "completed")
            self.assertTrue(
                any(m.role == "user" and "[BUDGET WARNING]" in m.content for m in soft_res.messages)
            )

            # LLM timeout against remaining wall budget.
            timeout_harness = AgentHarness(
                provider=_SlowProvider(),
                tools=create_default_tools(ws),
                budget=BudgetConfig(max_wall_time_s=0.05, max_working_seconds=5.0),
                trace_writer=TraceWriter(root / "wall.jsonl", session_id="s_wall"),
                checkpoint_store=checkpoints,
                spill_dir=root / "spills",
            )
            wall_res = await timeout_harness.run("Slow LLM call")
            self.assertEqual(wall_res.stop_reason, "wall_time_exceeded")

    async def test_verify_fail_enforces_pre_completion_hook_and_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "workspace"
            ws.mkdir()
            fake_key = "sk-" + "live" + "9876543210abcdef"
            fake_ghp = "ghp_" + "A" * 24
            fake_gho = "gho_" + "B" * 24
            fake_pem = (
                "-----BEGIN "
                "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE\n-----END "
                "PRIVATE KEY-----"
            )
            fake_url = "https://api.example.com/v1?access_" + "token=super_secret_987654&foo=1"

            self.assertEqual(redact_secrets(fake_pem), "[REDACTED_PRIVATE_KEY]")
            self.assertEqual(redact_secrets(fake_gho), "[REDACTED]")
            self.assertEqual(
                redact_secrets(fake_url),
                "https://api.example.com/v1?access_token=[REDACTED]&foo=1",
            )

            provider = MockProvider(
                responses=[
                    ModelResponse(
                        content="",
                        tool_calls=(
                            ToolCall(
                                id="w1",
                                name="write_file",
                                arguments={
                                    "path": "out.txt",
                                    "content": f"key={fake_key} tok={fake_ghp} pem={fake_pem} url={fake_url}",
                                },
                            ),
                        ),
                        usage=Usage(tokens_in=60, tokens_out=12),
                    ),
                    ModelResponse(
                        content="",
                        tool_calls=(
                            ToolCall(id="v_fail", name="verify_file", arguments={"path": "out.txt", "contains": "EXPECTED"}),
                        ),
                        usage=Usage(tokens_in=90, tokens_cached=50, tokens_out=12),
                    ),
                    ModelResponse(
                        content="Done despite failed verification.",
                        usage=Usage(tokens_in=120, tokens_cached=80, tokens_out=10),
                    ),
                    ModelResponse(
                        content="",
                        tool_calls=(
                            ToolCall(id="w2", name="write_file", arguments={"path": "out.txt", "content": "EXPECTED_VALUE"}),
                        ),
                        usage=Usage(tokens_in=150, tokens_cached=100, tokens_out=12),
                    ),
                    ModelResponse(
                        content="",
                        tool_calls=(
                            ToolCall(id="v_ok", name="verify_file", arguments={"path": "out.txt", "contains": "EXPECTED"}),
                        ),
                        usage=Usage(tokens_in=180, tokens_cached=120, tokens_out=12),
                    ),
                    ModelResponse(
                        content="Verified out.txt cleanly.",
                        usage=Usage(tokens_in=210, tokens_cached=140, tokens_out=10),
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
            self.assertEqual(result.final_output, "Verified out.txt cleanly.")
            self.assertTrue(
                any(
                    m.role == "user" and "Before finishing, run a verification tool" in m.content
                    for m in result.messages
                )
            )
            self.assertTrue(
                any(m.role == "tool" and "ERROR [verify_failed]" in m.content for m in result.messages)
            )

            raw_trace = trace_path.read_text(encoding="utf-8")
            self.assertNotIn(fake_key, raw_trace)
            self.assertNotIn(fake_ghp, raw_trace)
            self.assertNotIn("MIIEvQIBADANBgkqhkiG9w0BAQE", raw_trace)
            self.assertNotIn("super_secret_987654", raw_trace)
            self.assertIn("[REDACTED_PRIVATE_KEY]", raw_trace)
            self.assertIn("[REDACTED]", raw_trace)

            events = [json.loads(line) for line in raw_trace.splitlines() if line.strip()]
            timestamps = [e["timestamp"] for e in events]
            self.assertEqual(timestamps, sorted(timestamps))

    async def test_workspace_containment_protected_paths_and_safe_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            with self.assertRaises(ValueError):
                resolve_in_workspace(ws, "../outside.txt")

            # Valid '..foo.txt' filename MUST be allowed.
            self.assertEqual(resolve_in_workspace(ws, "..foo.txt").name, "..foo.txt")

            # Protected path deny list (NFC case-normalized).
            for blocked in (
                ".git/config",
                ".GIT/HEAD",
                ".env",
                ".ENV",
                ".env.local",
                ".vscode/settings.json",
                ".cursor/rules.md",
                ".agents/policy.json",
                "sub/mcp.json",
                ".npmrc",
                ".pypirc",
            ):
                with self.assertRaises(ValueError, msg=f"Should block {blocked}"):
                    resolve_in_workspace(ws, blocked)

            # Safe .env templates MUST be allowed.
            for allowed in (".env.example", ".env.sample", ".env.template"):
                self.assertEqual(resolve_in_workspace(ws, allowed).name, allowed)

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
