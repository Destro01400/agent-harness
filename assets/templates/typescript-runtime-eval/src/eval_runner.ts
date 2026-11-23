/** Isolated multi-trial evaluation runner with exact pass@k, pass^k, Wilson CI, and --gold mode. */

import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  AgentHarness,
  CheckpointStore,
  TraceWriter,
  createBudgetConfig,
  type RunResult,
} from "./harness.ts";
import {
  MockProvider,
  canonicalJson,
  createDefaultProfile,
  type ModelResponse,
  type ToolCall,
} from "./provider.ts";
import { createDefaultTools, writeFileAtomicAsync } from "./tools.ts";

function assertInteger(value: number, name: string): void {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error(`Parameter '${name}' must be an integer, got: ${String(value)}`);
  }
}

/** Overflow-safe exact unbiased estimator for pass@k: 1 - prod((n - c - i) / (n - i)). */
export function passAtK(n: number, c: number, k: number): number {
  assertInteger(n, "n");
  assertInteger(c, "c");
  assertInteger(k, "k");
  if (n < 1 || k < 1 || k > n || c < 0 || c > n) {
    throw new Error(`Invalid parameters: n=${n}, c=${c}, k=${k}`);
  }
  if (n - c < k) return 1;
  let prod = 1;
  for (let i = 0; i < k; i += 1) {
    prod *= (n - c - i) / (n - i);
  }
  return 1 - prod;
}

/** Overflow-safe exact unbiased estimator for pass^k: prod((c - i) / (n - i)). */
export function passPowK(n: number, c: number, k: number): number {
  assertInteger(n, "n");
  assertInteger(c, "c");
  assertInteger(k, "k");
  if (n < 1 || k < 1 || k > n || c < 0 || c > n) {
    throw new Error(`Invalid parameters: n=${n}, c=${c}, k=${k}`);
  }
  if (c < k) return 0;
  let prod = 1;
  for (let i = 0; i < k; i += 1) {
    prod *= (c - i) / (n - i);
  }
  return prod;
}

/** Wilson score 95% confidence interval for a binomial proportion. */
export function wilsonCi(
  successes: number,
  total: number,
  z = 1.959963984540054,
): [number, number] {
  assertInteger(successes, "successes");
  assertInteger(total, "total");
  if (typeof z !== "number" || !Number.isFinite(z) || z <= 0) {
    throw new Error(`Invalid z value: ${String(z)}`);
  }
  if (total < 1 || successes < 0 || successes > total) {
    throw new Error(`Invalid Wilson CI inputs: successes=${successes}, total=${total}`);
  }
  const phat = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const center = (phat + z2 / (2 * total)) / denom;
  const half = (z * Math.sqrt((phat * (1 - phat) + z2 / (4 * total)) / total)) / denom;
  return [Math.max(0, center - half), Math.min(1, center + half)];
}

export interface EvalTask {
  readonly id: string;
  readonly input: string;
  readonly expected: Record<string, unknown>;
  readonly graders: readonly Record<string, unknown>[];
  readonly setup_files?: Readonly<Record<string, string>>;
  readonly gold_plan?: readonly {
    content?: string;
    tool_calls?: readonly { name: string; arguments?: Record<string, unknown> }[];
  }[];
}

function parseTasksText(rawText: string): EvalTask[] {
  const lines = rawText.replace(/^\uFEFF/, "").split(/\r?\n/);
  const tasks: EvalTask[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i]!.trim();
    if (!trimmed) continue;
    const item = JSON.parse(trimmed) as EvalTask;
    const id = String(item.id ?? "").trim();
    if (!id || seen.has(id)) {
      throw new Error(`Invalid or duplicate task id at line ${i + 1}: ${id}`);
    }
    seen.add(id);
    tasks.push(item);
  }
  return tasks;
}

export function loadTasks(filePath: string): EvalTask[] {
  return parseTasksText(fs.readFileSync(filePath, "utf8"));
}

async function loadTasksAsync(filePath: string): Promise<EvalTask[]> {
  const text = await fsp.readFile(filePath, "utf8");
  return parseTasksText(text);
}

export function gradeOutcome(
  task: EvalTask,
  result: RunResult,
  workspace: string,
): { passed: boolean; failures: string[] } {
  const failures: string[] = [];
  const wsReal = fs.realpathSync(path.resolve(workspace));
  for (const grader of task.graders) {
    const type = String(grader.type ?? "");
    if (type === "contains") {
      const value = String(grader.value ?? "");
      if (!result.finalOutput.includes(value)) {
        failures.push(`contains failed: missing '${value}'`);
      }
    } else if (type === "regex") {
      const pattern = String(grader.pattern ?? "");
      if (!new RegExp(pattern).test(result.finalOutput)) {
        failures.push(`regex failed: pattern '${pattern}' not matched`);
      }
    } else if (type === "file_contains") {
      const relPath = String(grader.path ?? "");
      const value = String(grader.value ?? "");
      const fullPath = path.resolve(wsReal, relPath);
      const rel = path.relative(wsReal, fullPath);
      if (rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
        failures.push(`file_contains failed: path '${relPath}' escapes workspace`);
      } else if (!fs.existsSync(fullPath)) {
        failures.push(`file_contains failed: missing file ${relPath}`);
      } else if (!fs.readFileSync(fullPath, "utf8").includes(value)) {
        failures.push(`file_contains failed: ${relPath} missing '${value}'`);
      }
    } else if (type === "tool_used") {
      const name = String(grader.name ?? "");
      if (!result.toolCallsMade.includes(name)) {
        failures.push(`tool_used failed: ${name} was never invoked`);
      }
    } else if (type === "max_steps") {
      const limit = Number(grader.limit ?? 0);
      if (result.steps > limit) {
        failures.push(`max_steps failed: ${result.steps} > ${limit}`);
      }
    } else {
      failures.push(`unknown grader type: '${type}'`);
    }
  }
  return { passed: failures.length === 0, failures };
}

async function gradeOutcomeAsync(
  task: EvalTask,
  result: RunResult,
  workspace: string,
): Promise<{ passed: boolean; failures: string[] }> {
  const failures: string[] = [];
  const wsReal = await fsp.realpath(path.resolve(workspace));
  for (const grader of task.graders) {
    const type = String(grader.type ?? "");
    if (type === "contains") {
      const value = String(grader.value ?? "");
      if (!result.finalOutput.includes(value)) {
        failures.push(`contains failed: missing '${value}'`);
      }
    } else if (type === "regex") {
      const pattern = String(grader.pattern ?? "");
      if (!new RegExp(pattern).test(result.finalOutput)) {
        failures.push(`regex failed: pattern '${pattern}' not matched`);
      }
    } else if (type === "file_contains") {
      const relPath = String(grader.path ?? "");
      const value = String(grader.value ?? "");
      const fullPath = path.resolve(wsReal, relPath);
      const rel = path.relative(wsReal, fullPath);
      if (rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
        failures.push(`file_contains failed: path '${relPath}' escapes workspace`);
      } else {
        try {
          const text = await fsp.readFile(fullPath, "utf8");
          if (!text.includes(value)) {
            failures.push(`file_contains failed: ${relPath} missing '${value}'`);
          }
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code === "ENOENT") {
            failures.push(`file_contains failed: missing file ${relPath}`);
          } else {
            throw err;
          }
        }
      }
    } else if (type === "tool_used") {
      const name = String(grader.name ?? "");
      if (!result.toolCallsMade.includes(name)) {
        failures.push(`tool_used failed: ${name} was never invoked`);
      }
    } else if (type === "max_steps") {
      const limit = Number(grader.limit ?? 0);
      if (result.steps > limit) {
        failures.push(`max_steps failed: ${result.steps} > ${limit}`);
      }
    } else {
      failures.push(`unknown grader type: '${type}'`);
    }
  }
  return { passed: failures.length === 0, failures };
}

function buildScriptedProvider(task: EvalTask, gold: boolean): MockProvider {
  const plan = task.gold_plan ?? [];
  const responses: ModelResponse[] = plan.map((stepSpec, turnIdx) => {
    const toolCalls: ToolCall[] = (stepSpec.tool_calls ?? []).map((tc, idx) => ({
      id: `tc_${task.id}_${turnIdx}_${idx}`,
      name: tc.name,
      arguments: tc.arguments ?? {},
    }));
    return {
      content: stepSpec.content ?? "",
      tool_calls: toolCalls,
      reasoning_content: `Step ${turnIdx + 1} deterministic ${gold ? "gold" : "demo"} plan.`,
      usage: {
        tokens_in: 120 + turnIdx * 40,
        tokens_cached: turnIdx > 0 ? 80 : 0,
        tokens_out: 32,
        thinking_tokens: 8,
        cost_usd: 0.0002,
      },
    };
  });
  if (responses.length === 0) {
    responses.push({
      content: String(task.expected.answer ?? "DONE"),
      usage: { tokens_in: 100, tokens_cached: 0, tokens_out: 16, thinking_tokens: 0, cost_usd: 0.0001 },
    });
  }
  return new MockProvider({ responses });
}

export interface EvalSummary {
  readonly gold_mode: boolean;
  readonly gold_verified: boolean;
  readonly pass_at_1: number;
  readonly pass_at_k: number;
  readonly pass_pow_k: number;
  readonly task_count: number;
  readonly tasks: readonly Record<string, unknown>[];
  readonly trials_per_task: number;
  readonly wilson_ci_95: readonly [number, number];
}

export async function runEvalSuite(
  tasksPath: string,
  options: { trials?: number; gold?: boolean } = {},
): Promise<EvalSummary> {
  const trials = options.trials ?? 3;
  const gold = options.gold ?? false;
  if (typeof trials !== "number" || !Number.isInteger(trials) || trials < 1) {
    throw new Error(`trials must be an integer >= 1, got: ${String(trials)}`);
  }

  const tasks = await loadTasksAsync(tasksPath);
  const taskReports: Record<string, unknown>[] = [];
  let totalPasses = 0;
  let totalTrials = 0;

  for (const task of tasks) {
    const trialResults: Record<string, unknown>[] = [];
    for (let trialIdx = 1; trialIdx <= trials; trialIdx += 1) {
      const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), `eval_${task.id}_t${trialIdx}_`));
      try {
        const workspace = path.join(tmpRoot, "workspace");
        await fsp.mkdir(workspace, { recursive: true });
        for (const [relPath, content] of Object.entries(task.setup_files ?? {})) {
          const dest = path.join(workspace, relPath);
          await fsp.mkdir(path.dirname(dest), { recursive: true });
          await fsp.writeFile(dest, content, "utf8");
        }

        const harness = new AgentHarness({
          provider: buildScriptedProvider(task, gold),
          tools: createDefaultTools(workspace),
          profile: createDefaultProfile({ name: "eval-profile" }),
          budget: createBudgetConfig({ maxSteps: 8 }),
          traceWriter: new TraceWriter(
            path.join(tmpRoot, "traces", `${task.id}_trial_${trialIdx}.jsonl`),
            { sessionId: `${task.id}_trial_${trialIdx}` },
          ),
          checkpointStore: new CheckpointStore(path.join(tmpRoot, "checkpoints")),
          spillDir: path.join(tmpRoot, "spills"),
        });

        const result = await harness.run(task.input);
        const graded = await gradeOutcomeAsync(task, result, workspace);
        trialResults.push({
          failures: graded.failures,
          passed: graded.passed,
          steps: result.steps,
          stop_reason: result.stopReason,
          trial: trialIdx,
        });
      } finally {
        await fsp.rm(tmpRoot, { recursive: true, force: true });
      }
    }

    const passedCount = trialResults.filter((r) => r.passed === true).length;
    totalPasses += passedCount;
    totalTrials += trials;
    const [ciLow, ciHigh] = wilsonCi(passedCount, trials);
    taskReports.push({
      gold_verified: gold && passedCount === trials,
      id: task.id,
      pass_at_1: Number(passAtK(trials, passedCount, 1).toFixed(6)),
      pass_at_k: Number(passAtK(trials, passedCount, trials).toFixed(6)),
      pass_pow_k: Number(passPowK(trials, passedCount, trials).toFixed(6)),
      passed_trials: passedCount,
      total_trials: trials,
      trials: trialResults,
      wilson_ci_95: [Number(ciLow.toFixed(6)), Number(ciHigh.toFixed(6))],
    });
  }

  const [aggLow, aggHigh] = totalTrials > 0 ? wilsonCi(totalPasses, totalTrials) : [0, 0];
  const avg = (key: string): number =>
    taskReports.length === 0
      ? 0
      : taskReports.reduce((acc, item) => acc + Number(item[key]), 0) / taskReports.length;

  return {
    gold_mode: gold,
    gold_verified: gold && taskReports.every((item) => item.gold_verified === true),
    pass_at_1: Number(avg("pass_at_1").toFixed(6)),
    pass_at_k: Number(avg("pass_at_k").toFixed(6)),
    pass_pow_k: Number(avg("pass_pow_k").toFixed(6)),
    task_count: taskReports.length,
    tasks: taskReports,
    trials_per_task: trials,
    wilson_ci_95: [Number(aggLow.toFixed(6)), Number(aggHigh.toFixed(6))],
  };
}

export interface ParsedCliArgs {
  readonly help: boolean;
  readonly tasksPath: string;
  readonly trials: number;
  readonly gold: boolean;
  readonly outputPath: string | null;
}

const USAGE_TEXT = [
  "Usage: node src/eval_runner.ts [options]",
  "",
  "Options:",
  "  --tasks <path>    Path to tasks JSONL file (default: evals/tasks.jsonl)",
  "  --trials <int>    Positive integer number of trials per task (default: 3)",
  "  --gold            Verify task/grader soundness using deterministic gold plans",
  "  --output <path>   Optional path to write JSON summary",
  "  -h, --help        Show this help message and exit",
].join("\n");

export function parseCliArgs(args: readonly string[]): ParsedCliArgs {
  let help = false;
  let tasksPath = path.resolve("evals/tasks.jsonl");
  let trials = 3;
  let gold = false;
  let outputPath: string | null = null;

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]!;
    if (token === "--help" || token === "-h") {
      help = true;
    } else if (token === "--tasks") {
      const value = args[i + 1];
      if (!value || value.startsWith("-")) {
        throw new Error("Option '--tasks' requires a file path argument.");
      }
      tasksPath = path.resolve(value);
      i += 1;
    } else if (token === "--trials") {
      const raw = args[i + 1];
      if (raw === undefined) {
        throw new Error("Option '--trials' requires a positive integer argument.");
      }
      const parsed = Number.parseInt(raw, 10);
      if (!/^\d+$/.test(raw) || !Number.isInteger(parsed) || parsed < 1) {
        throw new Error(
          `Invalid --trials value '${raw}'. Expected a positive integer >= 1.`,
        );
      }
      trials = parsed;
      i += 1;
    } else if (token === "--gold") {
      gold = true;
    } else if (token === "--output") {
      const value = args[i + 1];
      if (!value || value.startsWith("-")) {
        throw new Error("Option '--output' requires a file path argument.");
      }
      outputPath = path.resolve(value);
      i += 1;
    } else {
      throw new Error(`Unknown option or argument: '${token}'. Run with --help for usage.`);
    }
  }

  return { help, tasksPath, trials, gold, outputPath };
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  let parsed: ParsedCliArgs;
  try {
    parsed = parseCliArgs(argv);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${msg}\n${USAGE_TEXT}\n`);
    return 2;
  }

  if (parsed.help) {
    process.stdout.write(`${USAGE_TEXT}\n`);
    return 0;
  }

  const summary = await runEvalSuite(parsed.tasksPath, {
    trials: parsed.trials,
    gold: parsed.gold,
  });
  const rendered = canonicalJson(summary, 2);
  if (parsed.outputPath) {
    await writeFileAtomicAsync(parsed.outputPath, `${rendered}\n`);
  }
  process.stdout.write(`${rendered}\n`);
  return parsed.gold && !summary.gold_verified ? 1 : 0;
}

const isMain =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isMain) {
  const code = await main();
  process.exitCode = code;
}
