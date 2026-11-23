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

    def test_six_verified_false_positives_stay_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evals").mkdir()
            (root / "evals" / "suite.py").write_text("pass_at_k = lambda n, c, k: 1.0\n", encoding="utf-8")

            # FP 1 (AH014 to_thread lambda), FP 2 (AH012 read_local_schema helper), FP 3 (AH013 router.register)
            (root / "clean_tools.py").write_text(
                '''import asyncio
from pathlib import Path
import subprocess
import time

async def safe_offloaded_run(cmd: list[str]) -> str:
    proc = await asyncio.to_thread(lambda: subprocess.run(cmd, shell=False, timeout=5, capture_output=True, text=True))
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, lambda: time.sleep(0.01))
    return proc.stdout[:200]

def read_local_schema(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def wire_routes(router, app, blueprint, api) -> None:
'''
                + "".join(f"    router.register('/r{i}', lambda: {i})\n" for i in range(8))
                + "".join(f"    app.register('/a{i}', lambda: {i})\n" for i in range(4))
                + "".join(f"    blueprint.register('/b{i}', lambda: {i})\n" for i in range(4))
                + "".join(f"    api.register('/api{i}', lambda: {i})\n" for i in range(4)),
                encoding="utf-8",
            )

            # FP 4 (AH003 TS class method eval + obj.eval), FP 5 (AH007 fetch with timeout helper & multiline opts)
            (root / "clean_ts.ts").write_text(
                '''export class Calculator {
  eval(expr: string): number {
    return expr.length;
  }
  async evalAsync(expr: string): Promise<number> {
    return this.eval(expr);
  }
}

export class AsyncEval {
  async eval(expr: string): Promise<string> {
    return expr;
  }
}

function makeInitWithTimeout(init: RequestInit): RequestInit {
  return { ...init, signal: AbortSignal.timeout(5000) };
}

export async function postData(url: string, calc: Calculator): Promise<number> {
  const res = await fetch(url, makeInitWithTimeout({ method: "POST" }));
  const multilineOpts = {
    method: "GET",
    signal: AbortSignal.timeout(3000),
  };
  await fetch(url, multilineOpts);
  return calc.eval(await res.text());
}
''',
                encoding="utf-8",
            )

            # FP 6 (AH006 Dual-Boundary Compose with internal: true network + egress-proxy)
            (root / "docker-compose.yml").write_text(
                '''services:
  sandbox:
    image: python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    user: "10001:10001"
    networks:
      - sandbox_internal
    volumes:
      - ./workspace:/workspace:ro
  egress-proxy:
    image: envoyproxy/envoy:v1.31@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    user: "10001:10001"
    networks:
      - sandbox_internal
      - external_egress

networks:
  sandbox_internal:
    internal: true
  external_egress: {}
''',
                encoding="utf-8",
            )

            res = ah.run_audit(root)
            self.assertEqual(res["counts"], {"error": 0, "warn": 0, "info": 0}, msg=res["findings"])

    def test_typed_python_annassign_aliases_and_false_negatives(self) -> None:
        fake_gho = "gho_" + "A1b2C3d4E5f6G7h8I9j0K1"
        fake_pem = "-----BEGIN " + "PRIVATE KEY-----"
        fake_url = "https://api.example.com/v1?access_token=" + "secret987654"
        py_code = f'''from datetime import datetime
from os import system, popen
import os
import re
import subprocess as sp
from subprocess import run as r
from time import sleep
import httpx
from pathlib import Path

# TODO: migrate to docker
BLOCKED_COMMANDS: list[str] = ["rm -rf", "sudo", "curl"]
SYSTEM_PROMPT: str = f"Today is {{datetime.now()}}"
TOOLS_LITERAL: list[dict[str, str]] = [{", ".join(f'{{"name": "t{i}"}}' for i in range(16))}]

TOKEN_A = "{fake_gho}"
PEM_HDR = "{fake_pem}"
SIGNED = "{fake_url}"

VERDICT_RE: re.Pattern[str] = re.compile(r"GRADE:\\s*(PASS|FAIL)")

def run_unbounded(client, msgs):
    while True:
        step = client.complete(msgs)
        if not step.tool_calls:
            break
    running = True
    while running:
        resp = client.complete(msgs)
        running = bool(resp.tool_calls)
    response = client.complete(msgs)
    while response.tool_calls:
        response = client.complete(msgs)

def bad_shell_and_env(cmd: str):
    r(cmd, shell=True, timeout=5)
    sp.run(cmd, shell=True, timeout=5)
    system(cmd)
    popen(cmd)
    env: dict[str, str] = os.environ.copy()
    sp.run(["ls"], env=env, timeout=5)
    sp.run(["ls"], env=os.environ | {{"X": "1"}}, timeout=5)

def bad_retry(fn):
    for attempt in range(3):
        try:
            return fn()
        except Exception:
            # TODO: add backoff
            sleep(1)

def bad_reasoning(messages, tool_result):
    messages[0].pop("encrypted_content", None)
    del messages[0]["encrypted_content"]
    cleaned = {{k: v for k, v in messages[0].items() if k != "reasoning_content"}}
    messages.append({{"content": tool_result, "role": "user"}})
    return cleaned

def tool_read(args: list[str]) -> str:
    prefix = args[:2]
    out: str = Path(prefix[0]).read_text(encoding="utf-8")
    return out

async def bad_async():
    sleep(1)
    httpx.get("https://example.com", timeout=5)

def judge_submission(client, submission: str) -> str:
    # boundary comment must not disable nonce check
    prompt = f"Grade carefully: {{submission.strip()}}"
    reply = client.complete(prompt, temperature=0.5)
    m = VERDICT_RE.search(reply)
    return m.group(1) if m else "FAIL"
'''
        details = self._audit_snippet("bad_typed_py.py", py_code)
        by_rule: dict[str, list[dict]] = {}
        for d in details:
            by_rule.setdefault(d["rule_id"], []).append(d)

        self.assertEqual(len(by_rule.get("AH001", [])), 3)
        self.assertEqual(len(by_rule.get("AH002", [])), 4)
        self.assertEqual(len(by_rule.get("AH004", [])), 1)
        self.assertEqual(len(by_rule.get("AH005", [])), 5)  # 3 secrets + 2 env leaks
        self.assertEqual(len(by_rule.get("AH009", [])), 1)
        self.assertEqual(len(by_rule.get("AH010", [])), 1)
        self.assertEqual(len(by_rule.get("AH011", [])), 4)
        self.assertEqual(len(by_rule.get("AH012", [])), 1)
        self.assertEqual(len(by_rule.get("AH013", [])), 1)
        self.assertEqual(len(by_rule.get("AH014", [])), 2)
        self.assertEqual(len(by_rule.get("AH015", [])), 3)

        # AH016: retrieval.py must NOT fool _project_has_eval_suite(), and typed trials=1 default caught
        ret_details = self._audit_snippet("retrieval.py", "def retrieve(q: str) -> str:\n    return q\n", include_eval=False)
        self.assertTrue(any(d["rule_id"] == "AH016" and d["severity"] == "INFO" for d in ret_details))

        eval_py = "TRIALS: int = 1\ndef run_eval(tasks, *, trials: int = 1):\n    return len(tasks) * trials\n"
        eval_details = self._audit_snippet("eval_runner.py", eval_py, include_eval=False)
        ah016_warns = [d for d in eval_details if d["rule_id"] == "AH016" and d["severity"] == "WARN"]
        self.assertEqual(len(ah016_warns), 2)

    def test_typescript_false_negatives_and_semicolon_safety(self) -> None:
        ts_code = '''import * as childProc from "node:child_process";
import { spawn, execFile } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import * as fs from "node:fs/promises";

const BLOCKED_COMMANDS: string[] = ["rm -rf", "sudo", "curl"];
const systemPrompt: string = `Now: ${Date.now()}`;
const STATIC_PROMPT = "Static prompt without semicolon"
const unrelatedTime = Date.now()

const sysMsg = {
  role: "system",
  content: `Current: ${Date.now()}`,
};

export async function badLoop(client: any) {
  while (true) {
    const step = await client.complete();
    if (!step.toolCalls) break;
  }
  let running = true;
  while (running) {
    const r = await client.complete();
    running = Boolean(r.toolCalls);
  }
}

export function badShellAndDynamic(userArg: string) {
  spawn(userArg, { shell: true, timeout: 5000 });
  const cmd = `ls ${userArg}`;
  childProc.execSync(cmd, { timeout: 5000 });
  execFile("ls", ["-la"]);
  const fn = Function("return " + userArg);
  return fn();
}

export async function badRetry(fn: () => Promise<void>) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await fn();
    } catch {
      await sleep(1000);
    }
  }
}

export function badReasoning(msg: any, toolResult: string) {
  const { thinking, ...rest } = msg;
  delete msg["thinking"];
  delete msg.reasoning_content;
  const userMsg = { content: toolResult, role: "user" };
  return [rest, userMsg];
}

export const toolReadAll = async (p: string) => fs.readFile(p, "utf8");

export async function blockingAsync(p: string) {
  const raw = readFileSync(p, "utf8");
  writeFileSync(p + ".bak", raw);
}

export async function scoreSubmission(client: any, submission: string) {
  const prompt = `Evaluate this answer and end with GRADE: PASS|FAIL\\n${submission}`;
  const out = await client.complete(prompt, { temperature: 0.7 });
  return out.match(/GRADE:\\s*(PASS|FAIL)/i);
}
'''
        details = self._audit_snippet("scoring.ts", ts_code)
        by_rule: dict[str, list[dict]] = {}
        for d in details:
            by_rule.setdefault(d["rule_id"], []).append(d)

        self.assertEqual(len(by_rule.get("AH001", [])), 2)
        self.assertEqual(len(by_rule.get("AH002", [])), 2)
        self.assertEqual(len(by_rule.get("AH003", [])), 1)
        self.assertEqual(len(by_rule.get("AH004", [])), 1)
        self.assertEqual(len(by_rule.get("AH007", [])), 1)  # execFile without timeout
        self.assertEqual(len(by_rule.get("AH009", [])), 1)
        self.assertEqual(len(by_rule.get("AH010", [])), 2)  # systemPrompt + multiline sysMsg, NOT STATIC_PROMPT
        self.assertEqual(len(by_rule.get("AH011", [])), 4)
        self.assertEqual(len(by_rule.get("AH012", [])), 1)
        self.assertEqual(len(by_rule.get("AH014", [])), 2)
        self.assertEqual(len(by_rule.get("AH015", [])), 3)

        eval_ts = "const trials: number = 1;\nexport function runEval(tasks: any[], trials: number = 1) { return tasks.length * trials; }\n"
        eval_details = self._audit_snippet("eval_runner.ts", eval_ts, include_eval=False)
        ah016_warns = [d for d in eval_details if d["rule_id"] == "AH016" and d["severity"] == "WARN"]
        self.assertEqual(len(ah016_warns), 2)

    def test_docker_compose_per_service_and_mcp_flag_value_parsing(self) -> None:
        # Dockerfile: unpinned tag, implicit :latest, and USER root
        bad_df = "FROM python:3.12\nFROM ubuntu\nUSER root\n"
        df_details = self._audit_snippet("Dockerfile", bad_df)
        self.assertEqual(sum(1 for d in df_details if d["rule_id"] == "AH006"), 3)

        # Clean multi-stage Dockerfile with stage alias & non-root user
        good_df = (
            "FROM python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef AS builder\n"
            "USER root\n"
            "RUN echo build\n"
            "FROM builder\n"
            "USER 10001:10001\n"
        )
        good_df_details = self._audit_snippet("Dockerfile", good_df)
        self.assertEqual([d for d in good_df_details if d["rule_id"] == "AH006"], [])

        # Compose: dummy network_mode: none must NOT hide sandbox network_mode: host or unisolated service
        bad_compose = '''services:
  dummy:
    image: busybox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    network_mode: none
  sandbox:
    image: python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    network_mode: host
  worker:
    image: python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
'''
        comp_details = self._audit_snippet("docker-compose.yml", bad_compose)
        ah006 = [d for d in comp_details if d["rule_id"] == "AH006"]
        self.assertEqual(len(ah006), 2)
        self.assertTrue(any("network_mode: host" in d["message"] for d in ah006))
        self.assertTrue(any("worker" in d["message"] for d in ah006))

        # MCP: --cache /tmp/v1.0 flag-value pair, npx without -y, uvx unpinned vs pinned
        mcp_json = json.dumps(
            {
                "mcpServers": {
                    "npx_flag_val": {"command": "npx", "args": ["-y", "--cache", "/tmp/v1.0", "@scope/pkg"]},
                    "npx_no_y": {"command": "npx", "args": ["@scope/unpinned"]},
                    "uvx_unpinned": {"command": "uvx", "args": ["--python", "3.12", "mcp-server-git"]},
                    "uvx_pinned": {"command": "uvx", "args": ["mcp-server-git==0.6.2"]},
                }
            }
        )
        mcp_details = self._audit_snippet("mcp.json", mcp_json)
        ah013 = [d for d in mcp_details if d["rule_id"] == "AH013"]
        self.assertEqual(len(ah013), 3)
        self.assertTrue(any("@scope/pkg" in d["message"] and "/tmp/v1.0" not in d["message"] for d in ah013))
        self.assertTrue(any("@scope/unpinned" in d["message"] for d in ah013))
        self.assertTrue(any("mcp-server-git" in d["message"] for d in ah013))

    def test_sarif_owasp_tags_uri_encoding_project_ah016_and_output_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # File with space in name, and no eval suite -> triggers AH007 + project-level AH016
            (root / "my agent.py").write_text("import requests\nrequests.get('https://example.com')\n", encoding="utf-8")
            sarif_out = root / "out" / "report.sarif"

            rc = ah.main([str(root), "--sarif", "--output", str(sarif_out)])
            self.assertEqual(rc, 0)  # WARN + INFO without --strict -> 0
            raw_bytes = sarif_out.read_bytes()
            self.assertFalse(raw_bytes.startswith(b"\xef\xbb\xbf"))  # UTF-8 without BOM

            sarif = json.loads(raw_bytes.decode("utf-8"))
            rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
            self.assertIn("owasp-asi05", rules["AH002"]["properties"]["tags"])
            self.assertNotIn("owasp-asi02", rules["AH002"]["properties"]["tags"])
            self.assertIn("owasp-asi05", rules["AH003"]["properties"]["tags"])
            self.assertNotIn("owasp-asi02", rules["AH003"]["properties"]["tags"])

            results = sarif["runs"][0]["results"]
            uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]
            self.assertNotIn(".", uris)
            self.assertEqual(uris, ["my%20agent.py", "my%20agent.py"])

            # When no files exist for a project-level finding, locations should be omitted (never ".")
            empty_sarif = ah.build_sarif_report(
                {
                    "primary_file": None,
                    "details": [{"rule_id": "AH016", "severity": "INFO", "file": None, "line": None, "message": "No evals"}],
                }
            )
            self.assertNotIn("locations", empty_sarif["runs"][0]["results"][0])


if __name__ == "__main__":
    unittest.main()
