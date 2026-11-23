/** End-to-end invariant tests for {{PROJECT_NAME}} (Node 24+ native type stripping). */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { passAtK, passPowK, runEvalSuite, wilsonCi } from "../src/eval_runner.ts";
import {
  AgentHarness,
  CheckpointStore,
  LoopDetectionHook,
  PreCompletionVerifyHook,
  TraceWriter,
  createBudgetConfig,
} from "../src/harness.ts";
import { MockProvider, createDefaultProfile } from "../src/provider.ts";
import {
  ApprovalPolicy,
  ToolRegistry,
  buildSafeEnv,
  createDefaultTools,
  resolveInWorkspace,
} from "../src/tools.ts";

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function withTempDir(prefix: string, fn: (dir: string) => Promise<void>): Promise<void> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fn(tmp).finally(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
}

describe("AgentHarness invariants", () => {
  it("runs normally, echoes reasoning_content, preserves system prefix, and emits role=tool", async () => {
    await withTempDir("ts_normal_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      fs.writeFileSync(path.join(ws, "hello.txt"), "alpha-42", "utf8");

      const provider = new MockProvider({
        responses: [
          {
            content: "",
            reasoning_content: "Inspect hello.txt first.",
            tool_calls: [{ id: "call_1", name: "read_file", arguments: { path: "hello.txt" } }],
            usage: { tokens_in: 100, tokens_cached: 0, tokens_out: 25, thinking_tokens: 10, cost_usd: 0.001 },
          },
          {
            content: "File contains alpha-42.",
            reasoning_content: "Verified from tool output.",
            usage: { tokens_in: 140, tokens_cached: 90, tokens_out: 18, thinking_tokens: 6, cost_usd: 0.001 },
          },
        ],
      });

      const harness = new AgentHarness({
        provider,
        tools: createDefaultTools(ws),
        traceWriter: new TraceWriter(path.join(root, "trace.jsonl"), { sessionId: "s_normal" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        spillDir: path.join(root, "spills"),
      });

      const result = await harness.run("Read hello.txt");
      assert.equal(result.stopReason, "completed");
      assert.ok(result.finalOutput.includes("alpha-42"));
      assert.equal(provider.recordedCalls.length, 2);

      const secondMessages = provider.recordedCalls[1]!.messages;
      assert.deepEqual(provider.recordedCalls[0]!.messages[0], secondMessages[0]);
      assert.equal(secondMessages[2]!.reasoning_content, "Inspect hello.txt first.");
      assert.equal(secondMessages[3]!.role, "tool");
      assert.equal(secondMessages[3]!.tool_call_id, "call_1");
    });
  });

  it("enforces AbortSignal tool timeout and keeps error in context", async () => {
    await withTempDir("ts_timeout_", async (root) => {
      const registry = new ToolRegistry([
        {
          name: "slow_op",
          description: "Simulated slow operation.",
          parameters: { type: "object", additionalProperties: false, properties: {}, required: [] },
          timeoutMs: 40,
          handler: async (_args, signal) =>
            await new Promise<string>((resolve, reject) => {
              const id = setTimeout(() => resolve("too late"), 400);
              signal.addEventListener("abort", () => {
                clearTimeout(id);
                const err = new Error("Aborted");
                err.name = "AbortError";
                reject(err);
              });
            }),
        },
      ]);

      const provider = new MockProvider({
        responses: [
          {
            content: "",
            tool_calls: [{ id: "t_slow", name: "slow_op", arguments: {} }],
            usage: { tokens_in: 50, tokens_out: 10 },
          },
          {
            content: "Recovered from timeout.",
            usage: { tokens_in: 80, tokens_cached: 40, tokens_out: 12 },
          },
        ],
      });

      const harness = new AgentHarness({
        provider,
        tools: registry,
        traceWriter: new TraceWriter(path.join(root, "trace.jsonl"), { sessionId: "s_timeout" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        spillDir: path.join(root, "spills"),
      });

      const result = await harness.run("Run slow op");
      assert.equal(result.stopReason, "completed");
      const toolMsgs = result.messages.filter((m) => m.role === "tool");
      assert.equal(toolMsgs.length, 1);
      assert.ok(toolMsgs[0]!.content.includes("ERROR [timeout]"));
    });
  });

  it("truncates oversized tool output and spills full content to disk", async () => {
    await withTempDir("ts_spill_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      fs.writeFileSync(path.join(ws, "big.txt"), "X".repeat(2000), "utf8");

      const spillDir = path.join(root, "spills");
      const provider = new MockProvider({
        responses: [
          {
            content: "",
            tool_calls: [{ id: "t_big", name: "read_file", arguments: { path: "big.txt" } }],
            usage: { tokens_in: 60, tokens_out: 10 },
          },
          {
            content: "Handled spilled output.",
            usage: { tokens_in: 90, tokens_cached: 50, tokens_out: 10 },
          },
        ],
      });

      const harness = new AgentHarness({
        provider,
        tools: createDefaultTools(ws),
        profile: createDefaultProfile({ maxOutputChars: 240 }),
        traceWriter: new TraceWriter(path.join(root, "trace.jsonl"), { sessionId: "s_spill" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        spillDir,
      });

      const result = await harness.run("Read big.txt");
      assert.equal(result.stopReason, "completed");
      const toolMsg = result.messages.find((m) => m.role === "tool");
      assert.ok(toolMsg?.content.includes("truncated"));
      const spillFiles = fs.readdirSync(spillDir).filter((f) => f.endsWith(".txt"));
      assert.equal(spillFiles.length, 1);
      assert.equal(fs.readFileSync(path.join(spillDir, spillFiles[0]!), "utf8").length, 2000);
    });
  });

  it("detects identical repeated tool calls with LoopDetectionHook", async () => {
    await withTempDir("ts_loop_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      fs.writeFileSync(path.join(ws, "a.txt"), "same", "utf8");

      const provider = new MockProvider({
        responses: [
          { content: "", tool_calls: [{ id: "r1", name: "read_file", arguments: { path: "a.txt" } }], usage: { tokens_in: 50, tokens_out: 10 } },
          { content: "", tool_calls: [{ id: "r2", name: "read_file", arguments: { path: "a.txt" } }], usage: { tokens_in: 70, tokens_cached: 40, tokens_out: 10 } },
          { content: "", tool_calls: [{ id: "r3", name: "read_file", arguments: { path: "a.txt" } }], usage: { tokens_in: 90, tokens_cached: 60, tokens_out: 10 } },
          { content: "Stopped repeating.", usage: { tokens_in: 110, tokens_cached: 80, tokens_out: 10 } },
        ],
      });

      const harness = new AgentHarness({
        provider,
        tools: createDefaultTools(ws),
        traceWriter: new TraceWriter(path.join(root, "trace.jsonl"), { sessionId: "s_loop" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        spillDir: path.join(root, "spills"),
        hooks: [new LoopDetectionHook(2)],
      });

      const result = await harness.run("Loop test");
      assert.equal(result.stopReason, "completed");
      const toolOutputs = result.messages.filter((m) => m.role === "tool").map((m) => m.content);
      assert.ok(toolOutputs.some((text) => text.includes("doom_loop_detected")));
    });
  });

  it("trips ApprovalPolicy circuit breaker after 3 consecutive rejections", async () => {
    await withTempDir("ts_deny_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });

      const policy = new ApprovalPolicy({
        defaultDecision: "ask",
        decider: () => "deny_once",
        maxConsecutiveRejections: 3,
      });

      const provider = new MockProvider({
        responses: [
          { content: "", tool_calls: [{ id: "d1", name: "write_file", arguments: { path: "a.txt", content: "1" } }], usage: { tokens_in: 50, tokens_out: 10 } },
          { content: "", tool_calls: [{ id: "d2", name: "write_file", arguments: { path: "b.txt", content: "2" } }], usage: { tokens_in: 70, tokens_cached: 40, tokens_out: 10 } },
          { content: "", tool_calls: [{ id: "d3", name: "write_file", arguments: { path: "c.txt", content: "3" } }], usage: { tokens_in: 90, tokens_cached: 60, tokens_out: 10 } },
          { content: "Unreachable turn.", usage: { tokens_in: 100, tokens_cached: 70, tokens_out: 10 } },
        ],
      });

      const harness = new AgentHarness({
        provider,
        tools: createDefaultTools(ws),
        traceWriter: new TraceWriter(path.join(root, "trace.jsonl"), { sessionId: "s_deny" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        approvalPolicy: policy,
        spillDir: path.join(root, "spills"),
      });

      const result = await harness.run("Try writing");
      assert.equal(result.stopReason, "approval_circuit_breaker");
      assert.equal(policy.circuitOpen, true);
      assert.equal(result.steps, 3);
    });
  });

  it("enforces budget cap and resumes cleanly from atomic checkpoint", async () => {
    await withTempDir("ts_resume_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      fs.writeFileSync(path.join(ws, "x.txt"), "checkpoint-ok", "utf8");

      const ckpts = new CheckpointStore(path.join(root, "ckpts"));
      const tracePath = path.join(root, "trace.jsonl");

      const harness1 = new AgentHarness({
        provider: new MockProvider({
          responses: [
            {
              content: "",
              tool_calls: [{ id: "c1", name: "read_file", arguments: { path: "x.txt" } }],
              usage: { tokens_in: 60, tokens_out: 10 },
            },
          ],
        }),
        tools: createDefaultTools(ws),
        budget: createBudgetConfig({ maxSteps: 1 }),
        traceWriter: new TraceWriter(tracePath, { sessionId: "s_resume" }),
        checkpointStore: ckpts,
        spillDir: path.join(root, "spills"),
      });

      const part1 = await harness1.run("Read x.txt");
      assert.equal(part1.stopReason, "max_steps");
      assert.equal(part1.steps, 1);

      const harness2 = new AgentHarness({
        provider: new MockProvider({
          responses: [
            {
              content: "Resumed and saw checkpoint-ok.",
              usage: { tokens_in: 90, tokens_cached: 50, tokens_out: 15 },
            },
          ],
        }),
        tools: createDefaultTools(ws),
        budget: createBudgetConfig({ maxSteps: 3 }),
        traceWriter: new TraceWriter(tracePath, { sessionId: "s_resume" }),
        checkpointStore: ckpts,
        spillDir: path.join(root, "spills"),
      });

      const part2 = await harness2.run("Read x.txt", { resume: true });
      assert.equal(part2.stopReason, "completed");
      assert.equal(part2.steps, 2);
      assert.ok(part2.finalOutput.includes("checkpoint-ok"));
    });
  });

  it("nudges verification after mutation and redacts secrets in monotonic traces", async () => {
    await withTempDir("ts_verify_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      const fakeKey = "sk-" + "live" + "9876543210abcdef";
      const fakeGhp = "ghp_" + "A".repeat(24);
      const tracePath = path.join(root, "trace.jsonl");

      const harness = new AgentHarness({
        provider: new MockProvider({
          responses: [
            {
              content: "",
              tool_calls: [
                {
                  id: "w1",
                  name: "write_file",
                  arguments: { path: "out.txt", content: `key=${fakeKey} tok=${fakeGhp}` },
                },
              ],
              usage: { tokens_in: 60, tokens_out: 12 },
            },
            {
              content: "Finished without checking.",
              usage: { tokens_in: 90, tokens_cached: 50, tokens_out: 10 },
            },
            {
              content: "",
              tool_calls: [
                { id: "v1", name: "verify_file", arguments: { path: "out.txt", contains: "key=" } },
              ],
              usage: { tokens_in: 120, tokens_cached: 80, tokens_out: 12 },
            },
            {
              content: "Verified out.txt cleanly.",
              usage: { tokens_in: 150, tokens_cached: 100, tokens_out: 10 },
            },
          ],
        }),
        tools: createDefaultTools(ws),
        traceWriter: new TraceWriter(tracePath, { sessionId: "s_verify" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        spillDir: path.join(root, "spills"),
        hooks: [new PreCompletionVerifyHook(1)],
      });

      const result = await harness.run("Write out.txt");
      assert.equal(result.stopReason, "completed");
      assert.ok(result.toolCallsMade.includes("verify_file"));

      const rawTrace = fs.readFileSync(tracePath, "utf8");
      assert.equal(rawTrace.includes(fakeKey), false);
      assert.equal(rawTrace.includes(fakeGhp), false);
      assert.ok(rawTrace.includes("[REDACTED]"));

      const events = rawTrace
        .trim()
        .split(/\r?\n/)
        .map((line) => JSON.parse(line) as { timestamp: string });
      const timestamps = events.map((e) => e.timestamp);
      assert.deepEqual(timestamps, [...timestamps].sort());
    });
  });

  it("blocks path traversal and filters subprocess environment via allowlist", async () => {
    await withTempDir("ts_sec_", async (root) => {
      const ws = path.join(root, "ws");
      fs.mkdirSync(ws, { recursive: true });
      assert.throws(() => resolveInWorkspace(ws, "../outside.txt"), /outside workspace/);
      const safeEnv = buildSafeEnv({ PATH: "/usr/bin", SECRET_KEY: "do_not_leak" }, ["PATH"]);
      assert.deepEqual(safeEnv, { PATH: "/usr/bin" });
    });
  });

  it("computes exact pass@k, pass^k, Wilson CI, and runs multi-trial gold eval suite", async () => {
    assert.ok(Math.abs(passAtK(5, 2, 2) - 0.7) < 1e-6);
    assert.ok(Math.abs(passPowK(5, 2, 2) - 0.1) < 1e-6);
    const [low, high] = wilsonCi(3, 3);
    assert.ok(low > 0.4 && high <= 1);

    const summary = await runEvalSuite(path.join(PROJECT_ROOT, "evals", "tasks.jsonl"), {
      trials: 3,
      gold: true,
    });
    assert.equal(summary.task_count, 3);
    assert.equal(summary.trials_per_task, 3);
    assert.equal(summary.gold_verified, true);
    assert.equal(summary.pass_pow_k, 1);
    assert.equal(summary.pass_at_k, 1);
  });
});
