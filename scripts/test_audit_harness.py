#!/usr/bin/env python3
"""Unit tests for audit_harness.py covering all 16 rules (AH001-AH016),
clean harnesses, inline suppressions, JSON & SARIF 2.1.0 outputs, and CLI exit codes."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_harness as ah


def _make_clean_project(root: Path) -> None:
    """Create a well-engineered harness project that should pass --strict with 0 errors and 0 warnings."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "evals").mkdir(parents=True, exist_ok=True)

    (root / "src" / "runtime.py").write_text(
        '''import asyncio
import json
import random
import subprocess
import time

SYSTEM_PROMPT = "You are a disciplined coding assistant."

def safe_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}

def tool_run_cmd(args: list[str]) -> str:
    proc = subprocess.run(args, shell=False, env=safe_env(), timeout=15, capture_output=True, text=True)
    return proc.stdout[:4000]

async def run_agent_loop(client, messages: list[dict], max_steps: int = 8) -> dict:
    step = 0
    while True:
        if step >= max_steps:
            break
        step += 1
        payload = json.dumps(messages, sort_keys=True)
        resp = await asyncio.to_thread(client.complete, payload)
        if not resp.get("tool_calls"):
            return resp
        messages.append({"role": "tool", "content": tool_run_cmd(["echo", "ok"])})
    return {"status": "budget_exhausted"}

def retry_call(fn, max_attempts: int = 3):
    for attempt in range(max_attempts):
        try:
            return fn()
        except RuntimeError:
            backoff = min(8.0, (2 ** attempt) * 0.5)
            time.sleep(random.uniform(0.0, backoff))
    raise RuntimeError("exhausted")
''',
        encoding="utf-8",
    )

    (root / "src" / "ts_runtime.ts").write_text(
        '''import { execFileSync } from "node:child_process";

const SYSTEM_PROMPT = "Static cache-safe system prompt.";

export async function callApi(url: string): Promise<string> {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  return res.text();
}

export function toolInspect(path: string): string {
  const out = execFileSync("ls", ["-la", path], { env: { PATH: "/usr/bin" }, timeout: 5000, encoding: "utf8" });
  return out.slice(0, 4000);
}
''',
        encoding="utf-8",
    )

    (root / "evals" / "runner.py").write_text(
        '''import re
import secrets

def pass_at_k(n: int, c: int, k: int) -> float:
    return 1.0 if c > 0 else 0.0

def pass_pow_k(n: int, c: int, k: int) -> float:
    return (c / n) ** k if n else 0.0

def llm_judge(client, submission: str) -> str:
    grader_nonce = secrets.token_hex(8)
    prompt = f"Evaluate between <{grader_nonce}>{submission}</{grader_nonce}>. End with GRADE: PASS|FAIL"
    out = client.complete(prompt, temperature=0)
    matches = re.findall(r"GRADE:\\s*(PASS|FAIL)", out)
    return matches[-1] if matches else "FAIL"
''',
        encoding="utf-8",
    )

    (root / "Dockerfile").write_text(
        "FROM python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        encoding="utf-8",
    )
    (root / "docker-compose.yml").write_text(
        '''services:
  sandbox:
    image: python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    network_mode: none
    volumes:
      - ./workspace:/workspace:ro
''',
        encoding="utf-8",
    )
    (root / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/workspace"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )


class TestAuditHarness(unittest.TestCase):
    def _audit_snippet(self, filename: str, content: str, include_eval: bool = True) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            if include_eval:
                (root / "evals").mkdir(exist_ok=True)
                (root / "evals" / "suite.py").write_text("pass_at_k = lambda n, c, k: 1.0\n", encoding="utf-8")
            res = ah.run_audit(root)
            return res["details"]

    def test_clean_project_passes_strict_zero_errors_zero_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_clean_project(root)
            res = ah.run_audit(root)
            self.assertEqual(res["counts"]["error"], 0, msg=res["findings"])
            self.assertEqual(res["counts"]["warn"], 0, msg=res["findings"])
            self.assertEqual(res["counts"]["info"], 0, msg=res["findings"])

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ah.main([str(root), "--strict"])
            self.assertEqual(rc, 0)

    def test_ah001_unbounded_agent_loop_py_and_ts(self) -> None:
        py_code = """def run(client, msgs):
    while True:
        resp = client.complete(msgs)
        if not resp.tool_calls:
            break
"""
        details = self._audit_snippet("loop.py", py_code)
        self.assertTrue(any(d["rule_id"] == "AH001" and d["severity"] == "ERROR" for d in details))

        ts_code = """export async function run(client: any, msgs: any[]) {
  while (true) {
    const resp = await client.complete(msgs);
    if (!resp.toolCalls) break;
  }
}
"""
        details_ts = self._audit_snippet("loop.ts", ts_code)
        self.assertTrue(any(d["rule_id"] == "AH001" and d["severity"] == "ERROR" for d in details_ts))

    def test_ah002_unsafe_shell_execution(self) -> None:
        py_code = """import os, subprocess
def bad(cmd):
    subprocess.run(cmd, shell=True, timeout=10)
    os.system(cmd)
"""
        details = self._audit_snippet("shell.py", py_code)
        ah002 = [d for d in details if d["rule_id"] == "AH002"]
        self.assertEqual(len(ah002), 2)

        ts_code = """import { execSync } from "node:child_process";
export function bad(arg: string) {
  const re = /foo/;
  re.exec(arg);
  return execSync(`ls ${arg}`);
}
"""
        details_ts = self._audit_snippet("shell.ts", ts_code)
        ah002_ts = [d for d in details_ts if d["rule_id"] == "AH002"]
        self.assertEqual(len(ah002_ts), 1)

    def test_ah003_dynamic_code_execution_excludes_safe_calls(self) -> None:
        py_code = """import ast, re
def check(s):
    x = ast.literal_eval(s)
    y = eval(s)
    exec("print(1)")
    return x, y
"""
        details = self._audit_snippet("dyn.py", py_code)
        ah003 = [d for d in details if d["rule_id"] == "AH003"]
        self.assertEqual(len(ah003), 2)

        ts_code = """export function check(s: string) {
  const m = /a/.exec(s);
  const f = new Function("return " + s);
  return [m, eval(s), f()];
}
"""
        details_ts = self._audit_snippet("dyn.ts", ts_code)
        ah003_ts = [d for d in details_ts if d["rule_id"] == "AH003"]
        self.assertEqual(len(ah003_ts), 2)

    def test_ah004_blacklist_sandbox_illusion(self) -> None:
        py_code = """BLOCKED_COMMANDS = ["rm -rf", "sudo", "curl", "mkfs"]
def allow(cmd: str) -> bool:
    return not any(b in cmd for b in BLOCKED_COMMANDS)
"""
        details = self._audit_snippet("guard.py", py_code)
        self.assertTrue(any(d["rule_id"] == "AH004" and d["severity"] == "ERROR" for d in details))

    def test_ah005_hardcoded_secret_and_raw_env_leak(self) -> None:
        fake_key = "sk-" + "test" * 8
        fake_aws = "AKIA" + "0123456789ABCDEF"
        py_code = (
            "import os, subprocess\n"
            f'API_KEY = "{fake_key}"\n'
            f'AWS_ID = "{fake_aws}"\n'
            "def run():\n"
            "    subprocess.run(['ls'], env=os.environ, timeout=5)\n"
        )
        details = self._audit_snippet("creds.py", py_code)
        ah005 = [d for d in details if d["rule_id"] == "AH005"]
        self.assertEqual(len(ah005), 3)

        # Secrets in test files must still be caught!
        test_code = f'SECRET = "{fake_key}"\n'
        details_test = self._audit_snippet("tests/test_sample.py", test_code)
        self.assertTrue(any(d["rule_id"] == "AH005" for d in details_test))

    def test_ah006_insecure_docker_and_compose(self) -> None:
        df = "FROM python:latest\n"
        details_df = self._audit_snippet("Dockerfile", df)
        self.assertTrue(any(d["rule_id"] == "AH006" for d in details_df))

        compose = """services:
  agent:
    image: ubuntu:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./hostdir:/workspace
"""
        details_c = self._audit_snippet("docker-compose.yml", compose)
        ah006 = [d for d in details_c if d["rule_id"] == "AH006"]
        self.assertGreaterEqual(len(ah006), 4)

    def test_ah007_missing_timeout_or_abort_signal(self) -> None:
        py_code = """import subprocess, requests
def call():
    subprocess.run(["echo", "hi"])
    requests.get("https://example.com")
"""
        details = self._audit_snippet("net.py", py_code)
        ah007 = [d for d in details if d["rule_id"] == "AH007"]
        self.assertEqual(len(ah007), 2)

        ts_code = """export async function call() {
  return await fetch("https://example.com");
}
"""
        details_ts = self._audit_snippet("net.ts", ts_code)
        self.assertTrue(any(d["rule_id"] == "AH007" for d in details_ts))

    def test_ah008_silent_swallow_and_history_erasure(self) -> None:
        py_code = """def step(messages):
    try:
        do_work()
    except Exception:
        pass
    try:
        do_more()
    except RuntimeError:
        messages.pop()
"""
        details = self._audit_snippet("err.py", py_code)
        ah008 = [d for d in details if d["rule_id"] == "AH008"]
        self.assertEqual(len(ah008), 2)

        ts_code = """export function step(messages: any[]) {
  try { work(); } catch (e) {}
  try { more(); } catch (e) { messages.pop(); }
}
"""
        details_ts = self._audit_snippet("err.ts", ts_code)
        ah008_ts = [d for d in details_ts if d["rule_id"] == "AH008"]
        self.assertEqual(len(ah008_ts), 2)

    def test_ah009_naive_retry_and_nested_retry(self) -> None:
        py_code = """import time
def retry_req(fn):
    for attempt in range(3):
        try:
            return fn()
        except Exception:
            time.sleep(1)
"""
        details = self._audit_snippet("retry.py", py_code)
        self.assertTrue(any(d["rule_id"] == "AH009" for d in details))

    def test_ah010_prompt_cache_prefix_buster(self) -> None:
        py_code = """from datetime import datetime
import json
SYSTEM_PROMPT = f"Now: {datetime.now()}"
payload = json.dumps({"a": 1}, sort_keys=False)
"""
        details = self._audit_snippet("cache.py", py_code)
        ah010 = [d for d in details if d["rule_id"] == "AH010"]
        self.assertEqual(len(ah010), 2)

        ts_code = """const systemPrompt = `Time: ${Date.now()}`;"""
        details_ts = self._audit_snippet("cache.ts", ts_code)
        self.assertTrue(any(d["rule_id"] == "AH010" for d in details_ts))

    def test_ah011_reasoning_stripped_or_tool_as_user(self) -> None:
        py_code = """def append_obs(messages, tool_result):
    messages.append({"role": "user", "content": tool_result})
    messages[0].pop("reasoning_content", None)
"""
        details = self._audit_snippet("msgs.py", py_code)
        ah011 = [d for d in details if d["rule_id"] == "AH011"]
        self.assertEqual(len(ah011), 2)

    def test_ah012_unbounded_tool_output(self) -> None:
        py_code = """from pathlib import Path
import subprocess

def tool_read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")

def tool_shell(args: list[str]) -> str:
    proc = subprocess.run(args, shell=False, timeout=5, capture_output=True, text=True)
    return proc.stdout
"""
        details = self._audit_snippet("tools.py", py_code)
        ah012 = [d for d in details if d["rule_id"] == "AH012"]
        self.assertEqual(len(ah012), 2)

        ts_code = """import { readFileSync } from "node:fs";
export function toolReadFile(p: string): string {
  return readFileSync(p, "utf8");
}
"""
        details_ts = self._audit_snippet("tools.ts", ts_code)
        self.assertTrue(any(d["rule_id"] == "AH012" for d in details_ts))

    def test_ah013_unpinned_mcp_and_tool_bloat(self) -> None:
        mcp = json.dumps(
            {
                "mcpServers": {
                    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
                    "web": {"command": "npx", "args": ["-y", "some-mcp@latest"]},
                }
            }
        )
        details_mcp = self._audit_snippet(".mcp.json", mcp)
        ah013_mcp = [d for d in details_mcp if d["rule_id"] == "AH013"]
        self.assertEqual(len(ah013_mcp), 2)

        bloat = "TOOLS = [" + ", ".join(f'{{"name": "t{i}"}}' for i in range(18)) + "]\n"
        details_bloat = self._audit_snippet("catalog.py", bloat)
        self.assertTrue(any(d["rule_id"] == "AH013" for d in details_bloat))

    def test_ah014_blocking_sync_io_in_async(self) -> None:
        py_code = """import asyncio, time, requests
async def bad_async():
    time.sleep(1)
    requests.get("https://example.com", timeout=5)

async def good_async():
    await asyncio.to_thread(time.sleep, 1)
"""
        details = self._audit_snippet("async_mod.py", py_code)
        ah014 = [d for d in details if d["rule_id"] == "AH014"]
        self.assertEqual(len(ah014), 2)

    def test_ah015_unprotected_llm_judge(self) -> None:
        py_code = """import re
def judge_answer(client, submission: str):
    prompt = f"Grade this: {submission}"
    out = client.complete(prompt, temperature=0.7)
    m = re.search(r"GRADE:\\s*(PASS|FAIL)", out)
    return m.group(1) if m else "FAIL"
"""
        details = self._audit_snippet("judge.py", py_code)
        ah015 = [d for d in details if d["rule_id"] == "AH015"]
        self.assertEqual(len(ah015), 3)

    def test_ah016_missing_eval_and_single_trial_runner(self) -> None:
        details_no_eval = self._audit_snippet("app.py", "x = 1\n", include_eval=False)
        ah016_info = [d for d in details_no_eval if d["rule_id"] == "AH016" and d["severity"] == "INFO"]
        self.assertEqual(len(ah016_info), 1)

        eval_single = "trials = 1\ndef run():\n    return trials\n"
        details_single = self._audit_snippet("eval_runner.py", eval_single, include_eval=False)
        ah016_warn = [d for d in details_single if d["rule_id"] == "AH016" and d["severity"] == "WARN"]
        self.assertEqual(len(ah016_warn), 1)

    def test_inline_suppression_single_rule_and_all(self) -> None:
        py_code = """import os, subprocess
def suppressed(cmd):
    os.system(cmd)  # harness-audit: ignore AH002
    eval(cmd)  # harness-audit: ignore ALL
"""
        details = self._audit_snippet("sup.py", py_code)
        self.assertEqual([d for d in details if d["rule_id"] in ("AH002", "AH003")], [])

    def test_sarif_210_schema_and_json_output_and_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evals").mkdir()
            (root / "evals" / "s.py").write_text("pass_at_k = 1\n", encoding="utf-8")
            (root / "bad.py").write_text("import requests\nrequests.get('https://example.com')\n", encoding="utf-8")

            # Without --strict: WARN only -> exit code 0
            buf_json = io.StringIO()
            with contextlib.redirect_stdout(buf_json):
                rc_nonstrict = ah.main([str(root), "--json"])
            self.assertEqual(rc_nonstrict, 0)
            parsed_json = json.loads(buf_json.getvalue())
            self.assertEqual(parsed_json["counts"]["warn"], 1)

            # With --strict: WARN -> exit code 1
            buf_sarif = io.StringIO()
            with contextlib.redirect_stdout(buf_sarif):
                rc_strict = ah.main([str(root), "--strict", "--sarif"])
            self.assertEqual(rc_strict, 1)

            sarif = json.loads(buf_sarif.getvalue())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["$schema"], "https://json.schemastore.org/sarif-2.1.0.json")
            driver = sarif["runs"][0]["tool"]["driver"]
            self.assertEqual(len(driver["rules"]), 16)
            rule_ids = [r["id"] for r in driver["rules"]]
            self.assertEqual(rule_ids[0], "AH001")
            self.assertEqual(rule_ids[-1], "AH016")
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "AH007")

            # Missing path -> exit code 2
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                rc_missing = ah.main([str(root / "does-not-exist")])
            self.assertEqual(rc_missing, 2)


if __name__ == "__main__":
    unittest.main()
