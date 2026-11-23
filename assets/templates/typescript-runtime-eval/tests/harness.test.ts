/** End-to-end invariant and security regression tests for {{PROJECT_NAME}} (Node 24+ native type stripping). */

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  parseCliArgs,
  passAtK,
  passPowK,
  runEvalSuite,
  wilsonCi,
} from "../src/eval_runner.ts";
import {
  AgentHarness,
  CheckpointStore,
  LoopDetectionHook,
  PreCompletionVerifyHook,
  TraceWriter,
  createBudgetConfig,
  deriveMessagesFromTrace,
  redactSecrets,
} from "../src/harness.ts";
import { MockProvider, createDefaultProfile } from "../src/provider.ts";
import {
  ApprovalPolicy,
  ToolRegistry,
  buildSafeEnv,
  createDefaultTools,
  resolveInWorkspace,
  resolveInWorkspaceAsync,
  truncateAndSpill,
  truncateAndSpillAsync,
} from "../src/tools.ts";

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function withTempDir(prefix: string, fn: (dir: string) => Promise<void>): Promise<void> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fn(tmp).finally(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });
}

describe("AgentHarness invariants", () => {
  it("runs normally, echoes reasoning_content, preserves system prefix, emits role=tool, and reconstructs messages from trace", async () => {
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

      const tracePath = path.join(root, "trace.jsonl");
      const harness = new AgentHarness({
        provider,
        tools: createDefaultTools(ws),
        traceWriter: new TraceWriter(tracePath, { sessionId: "s_normal" }),
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

      // True Model-visible <=> logged projection from JSONL trace.
      const derived = await deriveMessagesFromTrace(tracePath);
      assert.deepEqual(derived, result.messages);

      // Canonical top-level fields on tool/call and tool/result events.
      const rawEvents = fs
        .readFileSync(tracePath, "utf8")
        .trim()
        .split(/\r?\n/)
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      const toolCallEv = rawEvents.find((ev) => ev.event_type === "tool/call");
      const toolResultEv = rawEvents.find((ev) => ev.event_type === "tool/result");
      assert.equal(toolCallEv?.tool_call_id, "call_1");
      assert.equal(toolCallEv?.tool_name, "read_file");
      assert.equal(toolResultEv?.tool_call_id, "call_1");
      assert.equal(toolResultEv?.is_error, false);
      assert.equal(toolResultEv?.status, "ok");
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

  it("truncates oversized tool output strictly <= maxChars even at 120 and spills full content to disk", async () => {
    await withTempDir("ts_spill_", async (root) => {
      const spillDir = path.join(root, "spills");
      const source = `HEAD_${"A".repeat(1990)}_TAIL`;

      const syncOut = truncateAndSpill(source, 120, spillDir, "sync_label");
      assert.equal(syncOut.truncated, true);
      assert.ok(syncOut.output.length <= 120, `Expected <= 120, got ${syncOut.output.length}`);
      assert.ok(syncOut.spillPath !== null);
      assert.equal(fs.readFileSync(syncOut.spillPath!, "utf8"), source);
      const match = /truncated (\d+) chars/.exec(syncOut.output);
      assert.ok(match !== null);
      const reportedOmitted = Number(match![1]);
      const noticeLen = syncOut.output.match(/\n\.\.\.\[truncated \d+ chars; full: [^\]]+\]\.\.\.\n/)![0].length;
      const keptChars = syncOut.output.length - noticeLen;
      assert.equal(reportedOmitted, source.length - keptChars);

      const asyncOut = await truncateAndSpillAsync(source, 120, spillDir, "async_label");
      assert.equal(asyncOut.truncated, true);
      assert.ok(asyncOut.output.length <= 120);

      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      fs.writeFileSync(path.join(ws, "big.txt"), "X".repeat(2000), "utf8");

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

      const runSpillDir = path.join(root, "run_spills");
      const harness = new AgentHarness({
        provider,
        tools: createDefaultTools(ws),
        profile: createDefaultProfile({ maxOutputChars: 120 }),
        traceWriter: new TraceWriter(path.join(root, "trace.jsonl"), { sessionId: "s_spill" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        spillDir: runSpillDir,
      });

      const result = await harness.run("Read big.txt");
      assert.equal(result.stopReason, "completed");
      const toolMsg = result.messages.find((m) => m.role === "tool");
      assert.ok(toolMsg?.content.includes("truncated"));
      assert.ok((toolMsg?.content.length ?? 999) <= 120);
      const spillFiles = fs.readdirSync(runSpillDir).filter((f) => f.endsWith(".txt"));
      assert.equal(spillFiles.length, 1);
      assert.equal(fs.readFileSync(path.join(runSpillDir, spillFiles[0]!), "utf8").length, 2000);
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

  it("supports Inspect AI 5-decision ApprovalPolicy (modify + schema-before-approval + 3-rejection breaker)", async () => {
    await withTempDir("ts_approval_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      const tools = createDefaultTools(ws);

      // 1. Schema validation MUST run before approvalPolicy.evaluate().
      let deciderCalls = 0;
      const strictPolicy = new ApprovalPolicy({
        defaultDecision: "escalate",
        decider: () => {
          deciderCalls += 1;
          return "reject";
        },
        maxConsecutiveRejections: 3,
      });

      const malformedRes = await tools.execute(
        { id: "bad_1", name: "write_file", arguments: { path: "only_path.txt" } },
        { approvalPolicy: strictPolicy, spillDir: path.join(root, "spills") },
      );
      assert.equal(malformedRes.ok, false);
      assert.equal(malformedRes.errorCode, "invalid_arguments");
      assert.equal(deciderCalls, 0);
      assert.equal(strictPolicy.consecutiveRejections, 0);

      // 2. 'modify' rewrites arguments without mutating caller object, and re-validates schema.
      const originalArgs: Record<string, unknown> = { path: "note.txt", content: "unsafe-raw" };
      const modifyPolicy = new ApprovalPolicy({
        defaultDecision: "escalate",
        decider: (_tool, args) => ({
          decision: "modify",
          reason: "Sanitized content",
          modifiedArguments: { path: String(args.path), content: "sanitized-safe" },
        }),
      });
      const modRes = await tools.execute(
        { id: "mod_1", name: "write_file", arguments: originalArgs },
        { approvalPolicy: modifyPolicy, spillDir: path.join(root, "spills") },
      );
      assert.equal(modRes.ok, true);
      assert.equal(modRes.approvalDecision, "modify");
      assert.equal(originalArgs.content, "unsafe-raw");
      assert.equal(fs.readFileSync(path.join(ws, "note.txt"), "utf8"), "sanitized-safe");

      // 3. 'modify' producing schema-invalid arguments is refused.
      const badModifyPolicy = new ApprovalPolicy({
        defaultDecision: "escalate",
        decider: () => ({
          decision: "modify",
          modifiedArguments: { path: "note.txt", content: 12345 },
        }),
      });
      const badModRes = await tools.execute(
        { id: "mod_bad", name: "write_file", arguments: { path: "note.txt", content: "ok" } },
        { approvalPolicy: badModifyPolicy, spillDir: path.join(root, "spills") },
      );
      assert.equal(badModRes.ok, false);
      assert.equal(badModRes.errorCode, "invalid_modified_arguments");

      // 4. Attempting to rename tool during 'modify' is rejected.
      const renamePolicy = new ApprovalPolicy({
        defaultDecision: "escalate",
        decider: () => ({
          decision: "modify",
          toolName: "read_file",
          modifiedArguments: { path: "note.txt" },
        }),
      });
      const renameRes = await tools.execute(
        { id: "mod_rename", name: "write_file", arguments: { path: "note.txt", content: "ok" } },
        { approvalPolicy: renamePolicy, spillDir: path.join(root, "spills") },
      );
      assert.equal(renameRes.ok, false);
      assert.ok(renameRes.output.includes("cannot rename tool"));

      // 5. Three consecutive rejections upgrade to 'terminate' and halt AgentHarness.
      const rejectPolicy = new ApprovalPolicy({
        defaultDecision: "escalate",
        decider: () => "reject",
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
        tools,
        traceWriter: new TraceWriter(path.join(root, "trace.jsonl"), { sessionId: "s_deny" }),
        checkpointStore: new CheckpointStore(path.join(root, "ckpts")),
        approvalPolicy: rejectPolicy,
        spillDir: path.join(root, "spills"),
      });

      const result = await harness.run("Try writing");
      assert.equal(result.stopReason, "approval_circuit_breaker");
      assert.equal(rejectPolicy.circuitOpen, true);
      assert.equal(result.steps, 3);
      assert.ok(
        result.messages.some((m) => m.role === "tool" && m.content.includes("approval_denied:terminate")),
      );
    });
  });

  it("enforces budgets, soft 75% warning, LLM timeout, and completed checkpoint resume", async () => {
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

      // Resuming a completed session must NOT re-call the provider.
      const spyProvider = new MockProvider({
        responses: [{ content: "Should never run" }],
      });
      const harness3 = new AgentHarness({
        provider: spyProvider,
        tools: createDefaultTools(ws),
        budget: createBudgetConfig({ maxSteps: 5 }),
        traceWriter: new TraceWriter(tracePath, { sessionId: "s_resume" }),
        checkpointStore: ckpts,
        spillDir: path.join(root, "spills"),
      });
      const part3 = await harness3.run("Read x.txt", { resume: true });
      assert.equal(part3.stopReason, "completed");
      assert.equal(spyProvider.recordedCalls.length, 0);
      assert.equal(part3.finalOutput, "Resumed and saw checkpoint-ok.");

      // Soft budget warning triggers at >= 75% utilization.
      const softProvider = new MockProvider({
        responses: [
          {
            content: "",
            tool_calls: [{ id: "sw1", name: "read_file", arguments: { path: "x.txt" } }],
            usage: { tokens_in: 80, tokens_out: 10 },
          },
          {
            content: "Wrapped up after budget warning.",
            usage: { tokens_in: 90, tokens_cached: 50, tokens_out: 10 },
          },
        ],
      });
      const softHarness = new AgentHarness({
        provider: softProvider,
        tools: createDefaultTools(ws),
        budget: createBudgetConfig({ maxTokensIn: 100, maxSteps: 5 }),
        traceWriter: new TraceWriter(path.join(root, "soft.jsonl"), { sessionId: "s_soft" }),
        checkpointStore: ckpts,
        spillDir: path.join(root, "spills"),
      });
      const softRes = await softHarness.run("Trigger soft budget warning");
      assert.equal(softRes.stopReason, "completed");
      assert.ok(
        softRes.messages.some((m) => m.role === "user" && m.content.includes("[BUDGET WARNING]")),
      );

      // LLM call enforces AbortSignal.timeout(remainingWallMs).
      const slowProvider = new MockProvider({
        handler: async () =>
          await new Promise((resolve) => {
            setTimeout(() => resolve({ content: "too slow" }), 500);
          }),
      });
      const timeoutHarness = new AgentHarness({
        provider: slowProvider,
        tools: createDefaultTools(ws),
        budget: createBudgetConfig({ maxWallTimeMs: 40, maxWorkingMs: 5000 }),
        traceWriter: new TraceWriter(path.join(root, "wall.jsonl"), { sessionId: "s_wall" }),
        checkpointStore: ckpts,
        spillDir: path.join(root, "spills"),
      });
      const wallRes = await timeoutHarness.run("Slow LLM call");
      assert.equal(wallRes.stopReason, "wall_time_exceeded");
    });
  });

  it("refuses exit on VERIFY_FAIL and redacts PKCS#8 PEM, GitHub tokens, and ?access_token=", async () => {
    await withTempDir("ts_verify_", async (root) => {
      const ws = path.join(root, "workspace");
      fs.mkdirSync(ws, { recursive: true });
      const fakeKey = "sk-" + "live" + "9876543210abcdef";
      const fakeGhp = "ghp_" + "A".repeat(24);
      const fakeGho = "gho_" + "B".repeat(24);
      const fakePem =
        "-----BEGIN " +
        "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE\n-----END " +
        "PRIVATE KEY-----";
      const fakeUrl = "https://api.example.com/v1?access_" + "token=super_secret_987654&foo=1";

      assert.equal(String(redactSecrets(fakePem)).includes("BEGIN PRIVATE KEY"), false);
      assert.equal(String(redactSecrets(fakePem)), "[REDACTED_PRIVATE_KEY]");
      assert.equal(String(redactSecrets(fakeGho)), "[REDACTED]");
      assert.equal(
        String(redactSecrets(fakeUrl)),
        "https://api.example.com/v1?access_token=[REDACTED]&foo=1",
      );

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
                  arguments: {
                    path: "out.txt",
                    content: `key=${fakeKey} tok=${fakeGhp} pem=${fakePem} url=${fakeUrl}`,
                  },
                },
              ],
              usage: { tokens_in: 60, tokens_out: 12 },
            },
            {
              // Verification fails because EXPECTED is not present!
              content: "",
              tool_calls: [
                { id: "v_fail", name: "verify_file", arguments: { path: "out.txt", contains: "EXPECTED" } },
              ],
              usage: { tokens_in: 90, tokens_cached: 50, tokens_out: 12 },
            },
            {
              // Attempt premature finish after VERIFY_FAIL -> PreCompletionVerifyHook MUST nudge!
              content: "Trying to exit despite failed verification.",
              usage: { tokens_in: 120, tokens_cached: 80, tokens_out: 10 },
            },
            {
              content: "",
              tool_calls: [
                { id: "w2", name: "write_file", arguments: { path: "out.txt", content: "EXPECTED_VALUE" } },
              ],
              usage: { tokens_in: 150, tokens_cached: 100, tokens_out: 12 },
            },
            {
              content: "",
              tool_calls: [
                { id: "v_ok", name: "verify_file", arguments: { path: "out.txt", contains: "EXPECTED" } },
              ],
              usage: { tokens_in: 180, tokens_cached: 120, tokens_out: 12 },
            },
            {
              content: "Verified out.txt cleanly.",
              usage: { tokens_in: 210, tokens_cached: 140, tokens_out: 10 },
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
      assert.equal(result.finalOutput, "Verified out.txt cleanly.");
      assert.ok(
        result.messages.some((m) => m.role === "user" && m.content.includes("Before finishing, run a verification tool")),
      );
      assert.ok(
        result.messages.some((m) => m.role === "tool" && m.content.includes("ERROR [verify_failed]")),
      );

      const rawTrace = fs.readFileSync(tracePath, "utf8");
      assert.equal(rawTrace.includes(fakeKey), false);
      assert.equal(rawTrace.includes(fakeGhp), false);
      assert.equal(rawTrace.includes("MIIEvQIBADANBgkqhkiG9w0BAQE"), false);
      assert.equal(rawTrace.includes("super_secret_987654"), false);
      assert.ok(rawTrace.includes("[REDACTED_PRIVATE_KEY]"));
      assert.ok(rawTrace.includes("[REDACTED]"));

      const events = rawTrace
        .trim()
        .split(/\r?\n/)
        .map((line) => JSON.parse(line) as { timestamp: string });
      const timestamps = events.map((e) => e.timestamp);
      assert.deepEqual(timestamps, [...timestamps].sort());
    });
  });

  it("blocks multi-level symlink/junction escape & protected paths while allowing ..foo.txt and .env.example", async () => {
    await withTempDir("ts_sec_", async (root) => {
      const ws = path.join(root, "ws");
      const outside = path.join(root, "outside_secret");
      fs.mkdirSync(ws, { recursive: true });
      fs.mkdirSync(outside, { recursive: true });

      // Basic traversal blocked.
      assert.throws(() => resolveInWorkspace(ws, "../outside.txt"), /outside workspace/);
      await assert.rejects(() => resolveInWorkspaceAsync(ws, "../outside.txt"), /outside workspace/);

      // Legitimate filename starting with '..' MUST be allowed.
      const dotdotPath = resolveInWorkspace(ws, "..foo.txt");
      assert.equal(path.basename(dotdotPath), "..foo.txt");
      const dotdotAsync = await resolveInWorkspaceAsync(ws, "..foo.txt");
      assert.equal(dotdotAsync, dotdotPath);

      // Multi-level symlink/junction escape with non-existent intermediate subdir MUST be blocked.
      const linkPath = path.join(ws, "escape_link");
      fs.symlinkSync(outside, linkPath, process.platform === "win32" ? "junction" : "dir");
      assert.throws(
        () => resolveInWorkspace(ws, "escape_link/new_sub/pwned.txt"),
        /outside workspace/,
      );
      await assert.rejects(
        () => resolveInWorkspaceAsync(ws, "escape_link/new_sub/pwned.txt"),
        /outside workspace/,
      );

      // Verify write_file tool refuses to create file outside workspace via junction.
      const tools = createDefaultTools(ws);
      const escapeRes = await tools.execute(
        {
          id: "esc_1",
          name: "write_file",
          arguments: { path: "escape_link/new_sub/pwned.txt", content: "PWNED" },
        },
        { approvalPolicy: new ApprovalPolicy(), spillDir: path.join(root, "spills") },
      );
      assert.equal(escapeRes.ok, false);
      assert.equal(fs.existsSync(path.join(outside, "new_sub", "pwned.txt")), false);

      // Protected path deny list (NFC case-normalized).
      for (const blocked of [
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
      ]) {
        assert.throws(() => resolveInWorkspace(ws, blocked), /protected path/i, `Should block ${blocked}`);
        await assert.rejects(
          () => resolveInWorkspaceAsync(ws, blocked),
          /protected path/i,
          `Async should block ${blocked}`,
        );
      }

      // Safe .env template files MUST be allowed.
      for (const allowed of [".env.example", ".env.sample", ".env.template"]) {
        const resolved = resolveInWorkspace(ws, allowed);
        assert.equal(path.basename(resolved), allowed);
      }

      const safeEnv = buildSafeEnv({ PATH: "/usr/bin", SECRET_KEY: "do_not_leak" }, ["PATH"]);
      assert.deepEqual(safeEnv, { PATH: "/usr/bin" });
    });
  });

  it("computes overflow-safe pass@k, pass^k, Wilson CI, validates CLI --trials strictly, and runs gold eval suite", async () => {
    assert.ok(Math.abs(passAtK(5, 2, 2) - 0.7) < 1e-6);
    assert.ok(Math.abs(passPowK(5, 2, 2) - 0.1) < 1e-6);

    // Overflow-safe large inputs must stay finite (never NaN).
    const largeAtK = passAtK(1100, 10, 500);
    const largePowK = passPowK(1100, 1090, 500);
    assert.equal(Number.isFinite(largeAtK), true);
    assert.equal(Number.isFinite(largePowK), true);
    assert.ok(largeAtK > 0.99 && largeAtK < 1.0);
    assert.ok(largePowK > 0.0 && largePowK < 0.01);

    // Non-integer / NaN inputs rejected.
    assert.throws(() => passAtK(Number.NaN, 1, 1));
    assert.throws(() => passPowK(5, 2.5, 2));

    const [low, high] = wilsonCi(3, 3);
    assert.ok(low > 0.4 && high <= 1);

    // CLI parser rejects invalid --trials and unknown flags cleanly.
    assert.throws(() => parseCliArgs(["--trials", "abc"]), /Invalid --trials/);
    assert.throws(() => parseCliArgs(["--trials", "0"]), /Invalid --trials/);
    assert.throws(() => parseCliArgs(["--unknown-flag"]), /Unknown option/);
    assert.equal(parseCliArgs(["--help"]).help, true);

    // Subprocess checks confirm non-zero exit code 2 on invalid CLI flags.
    for (const badArgs of [
      ["--trials", "abc"],
      ["--trials", "0"],
      ["--unknown-flag"],
    ]) {
      let exitCode = 0;
      let stderrText = "";
      try {
        execFileSync(
          process.execPath,
          [path.join(PROJECT_ROOT, "src", "eval_runner.ts"), ...badArgs],
          { stdio: "pipe", timeout: 10000 },
        );
      } catch (err) {
        const execErr = err as { status?: number; stderr?: Buffer | string };
        exitCode = Number(execErr.status ?? 1);
        stderrText = String(execErr.stderr ?? "");
      }
      assert.equal(exitCode, 2, `Expected exit 2 for ${badArgs.join(" ")}`);
      assert.ok(stderrText.includes("Error:"), `Expected stderr error for ${badArgs.join(" ")}`);
    }

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
