/** Tool contracts, strict validation, AbortSignal timeouts, spilling, containment, and approvals. */

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import type { ToolCall, ToolSchema } from "./provider.ts";

export type ApprovalDecision =
  | "allow_once"
  | "allow_session"
  | "ask"
  | "deny_once"
  | "deny_session";

const VALID_APPROVAL_DECISIONS = new Set<string>([
  "allow_once",
  "allow_session",
  "ask",
  "deny_once",
  "deny_session",
]);

export const DEFAULT_ENV_ALLOWLIST: readonly string[] = [
  "PATH",
  "LANG",
  "LC_ALL",
  "TMP",
  "TEMP",
];

/** Construct an explicit zero-credential subprocess environment from an allowlist. */
export function buildSafeEnv(
  sourceEnv: Readonly<Record<string, string | undefined>>,
  allowlist: readonly string[] = DEFAULT_ENV_ALLOWLIST,
): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const key of allowlist) {
    const value = sourceEnv[key];
    if (typeof value === "string") {
      safe[key] = value;
    }
  }
  return safe;
}

/** Canonicalize path with realpathSync and reject traversal or symlink escape outside workspace. */
export function resolveInWorkspace(workspace: string, relativePath: string): string {
  if (!relativePath || typeof relativePath !== "string") {
    throw new Error("Path must be a non-empty string");
  }
  const rootReal = fs.realpathSync(path.resolve(workspace));
  const rawCandidate = path.resolve(rootReal, relativePath);

  let targetReal: string;
  if (fs.existsSync(rawCandidate)) {
    targetReal = fs.realpathSync(rawCandidate);
  } else {
    const parent = path.dirname(rawCandidate);
    const parentReal = fs.existsSync(parent) ? fs.realpathSync(parent) : parent;
    targetReal = path.resolve(parentReal, path.basename(rawCandidate));
  }

  const rel = path.relative(rootReal, targetReal);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error(
      `Path '${relativePath}' resolves outside workspace root. Use a relative path inside the workspace.`,
    );
  }
  return targetReal;
}

export interface SpillOutcome {
  readonly output: string;
  readonly truncated: boolean;
  readonly spillPath: string | null;
}

/** Bound tool output in context while atomically spilling full text to disk. */
export function truncateAndSpill(
  text: string,
  maxChars: number,
  spillDir: string,
  label: string,
): SpillOutcome {
  if (maxChars < 120) {
    throw new Error("maxChars must be at least 120");
  }
  if (text.length <= maxChars) {
    return { output: text, truncated: false, spillPath: null };
  }

  fs.mkdirSync(spillDir, { recursive: true });
  const digest = crypto.createHash("sha256").update(text, "utf8").digest("hex").slice(0, 12);
  const safeLabel = label.replace(/[^a-zA-Z0-9_-]/g, "_");
  const spillPath = path.join(spillDir, `${safeLabel}_${digest}.txt`);
  const tmpPath = path.join(spillDir, `.spill_${crypto.randomUUID()}.tmp`);

  try {
    fs.writeFileSync(tmpPath, text, "utf8");
    fs.renameSync(tmpPath, spillPath);
  } catch (err) {
    if (fs.existsSync(tmpPath)) {
      fs.unlinkSync(tmpPath);
    }
    throw err;
  }

  const omitted = text.length - maxChars;
  const notice = `\n... [truncated ${omitted} chars; full output saved to ${path.basename(spillPath)} in spill directory] ...\n`;
  const budget = Math.max(40, maxChars - notice.length);
  const headLen = Math.floor(budget / 2);
  const tailLen = budget - headLen;
  const bounded = `${text.slice(0, headLen)}${notice}${text.slice(text.length - tailLen)}`;
  return { output: bounded, truncated: true, spillPath };
}

export interface ApprovalEvaluation {
  readonly approved: boolean;
  readonly decision: ApprovalDecision;
  readonly reason: string;
}

export type ApprovalDecider = (
  toolName: string,
  args: Readonly<Record<string, unknown>>,
) => ApprovalDecision;

export class ApprovalPolicy {
  private readonly defaultDecision: ApprovalDecision;
  private readonly perTool: Map<string, ApprovalDecision>;
  private readonly sessionOverrides: Map<string, ApprovalDecision>;
  private readonly decider: ApprovalDecider | undefined;
  readonly maxConsecutiveRejections: number;
  consecutiveRejections: number;
  circuitOpen: boolean;

  constructor(options: {
    defaultDecision?: ApprovalDecision;
    perTool?: Readonly<Record<string, ApprovalDecision>>;
    decider?: ApprovalDecider;
    maxConsecutiveRejections?: number;
  } = {}) {
    const def = options.defaultDecision ?? "allow_once";
    if (!VALID_APPROVAL_DECISIONS.has(def)) {
      throw new Error(`Unsupported approval decision: ${def}`);
    }
    const maxRej = options.maxConsecutiveRejections ?? 3;
    if (maxRej < 1) {
      throw new Error("maxConsecutiveRejections must be >= 1");
    }
    this.defaultDecision = def;
    this.perTool = new Map(Object.entries(options.perTool ?? {}));
    this.sessionOverrides = new Map();
    this.decider = options.decider;
    this.maxConsecutiveRejections = maxRej;
    this.consecutiveRejections = 0;
    this.circuitOpen = false;
  }

  evaluate(toolName: string, args: Readonly<Record<string, unknown>>): ApprovalEvaluation {
    if (this.circuitOpen) {
      return {
        approved: false,
        decision: "deny_session",
        reason: "Approval circuit breaker is open after repeated rejections. Stop and ask the user.",
      };
    }

    let decision: ApprovalDecision =
      this.sessionOverrides.get(toolName) ??
      this.perTool.get(toolName) ??
      this.defaultDecision;

    if (decision === "ask") {
      decision = this.decider ? this.decider(toolName, args) : "deny_once";
    }
    if (!VALID_APPROVAL_DECISIONS.has(decision)) {
      decision = "deny_once";
    }

    if (decision === "allow_session") {
      this.sessionOverrides.set(toolName, "allow_session");
      this.consecutiveRejections = 0;
      return { approved: true, decision, reason: "Allowed for session" };
    }
    if (decision === "allow_once") {
      this.consecutiveRejections = 0;
      return { approved: true, decision, reason: "Allowed once" };
    }
    if (decision === "deny_session") {
      this.sessionOverrides.set(toolName, "deny_session");
    }

    this.consecutiveRejections += 1;
    if (this.consecutiveRejections >= this.maxConsecutiveRejections) {
      this.circuitOpen = true;
      return {
        approved: false,
        decision,
        reason: `Tool '${toolName}' denied (${decision}); circuit breaker tripped after ${this.consecutiveRejections} consecutive rejections.`,
      };
    }
    return {
      approved: false,
      decision,
      reason: `Tool '${toolName}' was denied by approval policy (${decision}). Choose a safer alternative or ask the user.`,
    };
  }
}

export type ToolHandler = (
  args: Record<string, unknown>,
  signal: AbortSignal,
) => Promise<string>;

export interface ToolSpec {
  readonly name: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
  readonly handler: ToolHandler;
  readonly timeoutMs?: number;
  readonly mutating?: boolean;
  readonly verification?: boolean;
  readonly inputExamples?: readonly Record<string, unknown>[];
}

export interface ToolResult {
  readonly toolCallId: string;
  readonly name: string;
  readonly output: string;
  readonly ok: boolean;
  readonly durationMs: number;
  readonly truncated: boolean;
  readonly spillPath: string | null;
  readonly errorCode: string | null;
}

function matchesJsonType(value: unknown, expectedType: string): boolean {
  if (expectedType === "string") return typeof value === "string";
  if (expectedType === "integer") return typeof value === "number" && Number.isInteger(value);
  if (expectedType === "number") return typeof value === "number" && !Number.isNaN(value);
  if (expectedType === "boolean") return typeof value === "boolean";
  if (expectedType === "array") return Array.isArray(value);
  if (expectedType === "object") return value !== null && typeof value === "object" && !Array.isArray(value);
  return true;
}

export function validateToolArguments(spec: ToolSpec, args: unknown): string | null {
  if (args === null || typeof args !== "object" || Array.isArray(args)) {
    return `ERROR [invalid_arguments]: Tool '${spec.name}' expects a JSON object.`;
  }
  const argObj = args as Record<string, unknown>;
  const schema = spec.parameters;
  const properties = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required = (schema.required ?? []) as string[];

  const missing = required.filter((key) => !(key in argObj));
  if (missing.length > 0) {
    return `ERROR [missing_required]: Tool '${spec.name}' is missing required parameter(s): ${missing.join(", ")}. Expected properties: ${Object.keys(properties).sort().join(", ")}.`;
  }

  if (schema.additionalProperties === false) {
    const allowed = new Set(Object.keys(properties));
    const extra = Object.keys(argObj).filter((k) => !allowed.has(k)).sort();
    if (extra.length > 0) {
      return `ERROR [unknown_parameter]: Tool '${spec.name}' received unsupported parameter(s): ${extra.join(", ")}. Allowed: ${Object.keys(properties).sort().join(", ")}.`;
    }
  }

  for (const [key, val] of Object.entries(argObj)) {
    const propSchema = properties[key];
    if (!propSchema || typeof propSchema.type !== "string") continue;
    if (!matchesJsonType(val, propSchema.type)) {
      return `ERROR [type_mismatch]: Parameter '${key}' for tool '${spec.name}' must be type '${propSchema.type}'.`;
    }
  }
  return null;
}

async function runWithAbortTimeout<T>(
  timeoutMs: number,
  fn: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  let timerId: ReturnType<typeof setTimeout> | undefined;

  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timerId = setTimeout(() => {
      const err = new Error(`Timed out after ${timeoutMs}ms`);
      err.name = "TimeoutError";
      controller.abort(err);
      reject(err);
    }, timeoutMs);
  });

  try {
    return await Promise.race([fn(controller.signal), timeoutPromise]);
  } finally {
    if (timerId !== undefined) {
      clearTimeout(timerId);
    }
  }
}

export class ToolRegistry {
  private readonly tools: Map<string, ToolSpec>;

  constructor(specs: readonly ToolSpec[] = []) {
    this.tools = new Map();
    for (const spec of specs) {
      this.register(spec);
    }
  }

  register(spec: ToolSpec): void {
    if (this.tools.has(spec.name)) {
      throw new Error(`Duplicate tool registration: ${spec.name}`);
    }
    this.tools.set(spec.name, spec);
  }

  get(name: string, aliases?: Readonly<Record<string, string>>): ToolSpec | undefined {
    const resolved = aliases && name in aliases ? aliases[name] : name;
    return this.tools.get(resolved);
  }

  schemas(): ToolSchema[] {
    return [...this.tools.keys()].sort().map((name) => {
      const spec = this.tools.get(name)!;
      const schema: ToolSchema = {
        name: spec.name,
        description: spec.description,
        parameters: spec.parameters,
        ...(spec.inputExamples ? { input_examples: spec.inputExamples } : {}),
      };
      return schema;
    });
  }

  async execute(
    toolCall: ToolCall,
    options: {
      approvalPolicy: ApprovalPolicy;
      spillDir: string;
      maxOutputChars?: number;
      defaultTimeoutMs?: number;
      aliases?: Readonly<Record<string, string>>;
    },
  ): Promise<ToolResult> {
    const started = performance.now();
    const spec = this.get(toolCall.name, options.aliases);
    if (!spec) {
      const available = [...this.tools.keys()].sort().join(", ") || "(none)";
      return {
        toolCallId: toolCall.id,
        name: toolCall.name,
        output: `ERROR [unknown_tool]: Tool '${toolCall.name}' is not registered. Available tools: ${available}.`,
        ok: false,
        durationMs: performance.now() - started,
        truncated: false,
        spillPath: null,
        errorCode: "unknown_tool",
      };
    }

    const approval = options.approvalPolicy.evaluate(spec.name, toolCall.arguments);
    if (!approval.approved) {
      return {
        toolCallId: toolCall.id,
        name: spec.name,
        output: `ERROR [approval_denied:${approval.decision}]: ${approval.reason}`,
        ok: false,
        durationMs: performance.now() - started,
        truncated: false,
        spillPath: null,
        errorCode: `approval_denied:${approval.decision}`,
      };
    }

    const validationError = validateToolArguments(spec, toolCall.arguments);
    if (validationError !== null) {
      return {
        toolCallId: toolCall.id,
        name: spec.name,
        output: validationError,
        ok: false,
        durationMs: performance.now() - started,
        truncated: false,
        spillPath: null,
        errorCode: "invalid_arguments",
      };
    }

    const defaultTimeoutMs = options.defaultTimeoutMs ?? 15000;
    const timeoutMs = spec.timeoutMs && spec.timeoutMs > 0
      ? Math.min(spec.timeoutMs, defaultTimeoutMs)
      : defaultTimeoutMs;

    let rawOutput: string;
    try {
      rawOutput = await runWithAbortTimeout(timeoutMs, (signal) =>
        spec.handler({ ...toolCall.arguments }, signal),
      );
    } catch (err) {
      const isTimeout = err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
      const message = err instanceof Error ? err.message : String(err);
      return {
        toolCallId: toolCall.id,
        name: spec.name,
        output: isTimeout
          ? `ERROR [timeout]: Tool '${spec.name}' exceeded its ${timeoutMs}ms timeout. Narrow the request scope or retry.`
          : `ERROR [execution_error]: Tool '${spec.name}' failed: ${message}. Inspect arguments and retry safely.`,
        ok: false,
        durationMs: performance.now() - started,
        truncated: false,
        spillPath: null,
        errorCode: isTimeout ? "timeout" : "execution_error",
      };
    }

    const spilled = truncateAndSpill(
      String(rawOutput),
      options.maxOutputChars ?? 8000,
      options.spillDir,
      `${spec.name}_${toolCall.id}`,
    );
    return {
      toolCallId: toolCall.id,
      name: spec.name,
      output: spilled.output,
      ok: true,
      durationMs: performance.now() - started,
      truncated: spilled.truncated,
      spillPath: spilled.spillPath,
      errorCode: null,
    };
  }
}

async function listFilesRecursive(root: string, dir: string, results: string[]): Promise<void> {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await listFilesRecursive(root, full, results);
    } else if (entry.isFile()) {
      results.push(path.relative(root, full).replace(/\\/g, "/"));
    }
  }
}

export function createDefaultTools(workspace: string): ToolRegistry {
  const root = path.resolve(workspace);

  return new ToolRegistry([
    {
      name: "list_files",
      description: "List files inside a workspace-relative directory.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: { directory: { type: "string" } },
        required: [],
      },
      inputExamples: [{ directory: "." }],
      handler: async (args) => {
        const rel = typeof args.directory === "string" ? args.directory : ".";
        const target = resolveInWorkspace(root, rel);
        const found: string[] = [];
        await listFilesRecursive(root, target, found);
        found.sort();
        return found.length > 0 ? found.join("\n") : "(empty workspace)";
      },
    },
    {
      name: "read_file",
      description: "Read a UTF-8 text file inside the workspace.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: { path: { type: "string" } },
        required: ["path"],
      },
      inputExamples: [{ path: "notes.txt" }],
      handler: async (args) => {
        const target = resolveInWorkspace(root, String(args.path));
        return await fsp.readFile(target, "utf8");
      },
    },
    {
      name: "verify_file",
      description: "Deterministically verify that a workspace file exists and optionally contains text.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          contains: { type: "string" },
        },
        required: ["path"],
      },
      verification: true,
      inputExamples: [{ path: "result.txt", contains: "OK" }],
      handler: async (args) => {
        const relPath = String(args.path);
        const expected = typeof args.contains === "string" ? args.contains : "";
        const target = resolveInWorkspace(root, relPath);
        const content = await fsp.readFile(target, "utf8");
        if (expected && !content.includes(expected)) {
          return `VERIFY_FAIL: '${relPath}' does not contain '${expected}'.`;
        }
        return `VERIFY_OK: '${relPath}' exists (${content.length} chars).`;
      },
    },
    {
      name: "write_file",
      description: "Atomically write UTF-8 text to a workspace-relative path.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          content: { type: "string" },
        },
        required: ["path", "content"],
      },
      mutating: true,
      inputExamples: [{ path: "result.txt", content: "hello" }],
      handler: async (args) => {
        const relPath = String(args.path);
        const content = String(args.content);
        const target = resolveInWorkspace(root, relPath);
        await fsp.mkdir(path.dirname(target), { recursive: true });
        const tmpPath = path.join(path.dirname(target), `.write_${crypto.randomUUID()}.tmp`);
        try {
          await fsp.writeFile(tmpPath, content, "utf8");
          await fsp.rename(tmpPath, target);
        } catch (err) {
          if (fs.existsSync(tmpPath)) {
            await fsp.unlink(tmpPath);
          }
          throw err;
        }
        return `Wrote ${content.length} chars to ${relPath}.`;
      },
    },
  ]);
}
