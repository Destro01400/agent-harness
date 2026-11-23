/** Tool contracts, strict validation, AbortSignal timeouts, spilling, containment, and approvals. */

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import type { ToolCall, ToolSchema } from "./provider.ts";

export type ApprovalDecision = "approve" | "modify" | "reject" | "escalate" | "terminate";

const VALID_APPROVAL_DECISIONS = new Set<string>([
  "approve",
  "modify",
  "reject",
  "escalate",
  "terminate",
]);

export const DEFAULT_ENV_ALLOWLIST: readonly string[] = [
  "PATH",
  "LANG",
  "LC_ALL",
  "TMP",
  "TEMP",
];

const PROTECTED_PATH_SEGMENTS = new Set<string>([
  ".git",
  ".vscode",
  ".cursor",
  ".agents",
  "mcp.json",
  ".npmrc",
  ".pypirc",
]);

const ALLOWED_ENV_TEMPLATES = new Set<string>([
  ".env.example",
  ".env.sample",
  ".env.template",
]);

const MAX_SYMLINK_HOPS = 40;

/** Recoverable tool failure carrying a structured machine-readable error code. */
export class ToolExecutionError extends Error {
  readonly code: string;

  constructor(message: string, code = "execution_error") {
    super(message);
    this.name = "ToolExecutionError";
    this.code = code;
  }
}

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

function isProtectedSegment(rawSegment: string): boolean {
  const norm = rawSegment.normalize("NFC").toLowerCase();
  if (PROTECTED_PATH_SEGMENTS.has(norm)) {
    return true;
  }
  if (ALLOWED_ENV_TEMPLATES.has(norm)) {
    return false;
  }
  return norm === ".env" || norm.startsWith(".env.");
}

function assertWorkspaceContainmentAndPolicy(
  rootReal: string,
  targetReal: string,
  originalRelativePath: string,
): void {
  const rel = path.relative(rootReal, targetReal);
  if (rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error(
      `Path '${originalRelativePath}' resolves outside workspace root. Use a relative path inside the workspace.`,
    );
  }
  const segments = rel.split(/[\\/]+/).filter((seg) => seg.length > 0);
  for (const seg of segments) {
    if (isProtectedSegment(seg)) {
      throw new Error(
        `Access to protected path '${originalRelativePath}' ('${seg}') is denied by workspace policy.`,
      );
    }
  }
}

function resolveDeepestExistingSync(rawCandidate: string): string {
  let candidate = rawCandidate;
  for (let hop = 0; hop < MAX_SYMLINK_HOPS; hop += 1) {
    const tail: string[] = [];
    let cursor = candidate;
    let symlinkRedirect: string | null = null;

    while (true) {
      let lstatInfo: fs.Stats | null = null;
      try {
        lstatInfo = fs.lstatSync(cursor);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== "ENOENT" && code !== "ENOTDIR") {
          throw err;
        }
      }

      if (lstatInfo !== null) {
        if (fs.existsSync(cursor)) {
          const existingReal = fs.realpathSync(cursor);
          return tail.length > 0 ? path.resolve(existingReal, ...tail) : existingReal;
        }
        if (lstatInfo.isSymbolicLink()) {
          const linkTarget = fs.readlinkSync(cursor);
          const resolvedLink = path.resolve(path.dirname(cursor), linkTarget);
          symlinkRedirect = tail.length > 0 ? path.resolve(resolvedLink, ...tail) : resolvedLink;
          break;
        }
      }

      const parent = path.dirname(cursor);
      if (parent === cursor) {
        return tail.length > 0 ? path.resolve(cursor, ...tail) : cursor;
      }
      tail.unshift(path.basename(cursor));
      cursor = parent;
    }

    if (symlinkRedirect === null) {
      break;
    }
    candidate = symlinkRedirect;
  }
  throw new Error(`Too many symbolic link levels while resolving '${rawCandidate}'.`);
}

async function pathAccessibleAsync(p: string): Promise<boolean> {
  try {
    await fsp.access(p);
    return true;
  } catch {
    return false;
  }
}

async function resolveDeepestExistingAsync(rawCandidate: string): Promise<string> {
  let candidate = rawCandidate;
  for (let hop = 0; hop < MAX_SYMLINK_HOPS; hop += 1) {
    const tail: string[] = [];
    let cursor = candidate;
    let symlinkRedirect: string | null = null;

    while (true) {
      let lstatInfo: fs.Stats | null = null;
      try {
        lstatInfo = await fsp.lstat(cursor);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== "ENOENT" && code !== "ENOTDIR") {
          throw err;
        }
      }

      if (lstatInfo !== null) {
        if (await pathAccessibleAsync(cursor)) {
          const existingReal = await fsp.realpath(cursor);
          return tail.length > 0 ? path.resolve(existingReal, ...tail) : existingReal;
        }
        if (lstatInfo.isSymbolicLink()) {
          const linkTarget = await fsp.readlink(cursor);
          const resolvedLink = path.resolve(path.dirname(cursor), linkTarget);
          symlinkRedirect = tail.length > 0 ? path.resolve(resolvedLink, ...tail) : resolvedLink;
          break;
        }
      }

      const parent = path.dirname(cursor);
      if (parent === cursor) {
        return tail.length > 0 ? path.resolve(cursor, ...tail) : cursor;
      }
      tail.unshift(path.basename(cursor));
      cursor = parent;
    }

    if (symlinkRedirect === null) {
      break;
    }
    candidate = symlinkRedirect;
  }
  throw new Error(`Too many symbolic link levels while resolving '${rawCandidate}'.`);
}

/**
 * Canonicalize a workspace-relative path (walking ancestors for non-existent tails),
 * reject symlink/junction escapes outside workspace, and block NFC protected paths.
 */
export function resolveInWorkspace(workspace: string, relativePath: string): string {
  if (!relativePath || typeof relativePath !== "string" || relativePath.includes("\0")) {
    throw new Error("Path must be a non-empty string without NUL bytes");
  }
  const rootReal = fs.realpathSync(path.resolve(workspace));
  const rawCandidate = path.resolve(rootReal, relativePath);
  const targetReal = resolveDeepestExistingSync(rawCandidate);
  assertWorkspaceContainmentAndPolicy(rootReal, targetReal, relativePath);
  return targetReal;
}

/** Async version of resolveInWorkspace using node:fs/promises (non-blocking inside async loops). */
export async function resolveInWorkspaceAsync(workspace: string, relativePath: string): Promise<string> {
  if (!relativePath || typeof relativePath !== "string" || relativePath.includes("\0")) {
    throw new Error("Path must be a non-empty string without NUL bytes");
  }
  const rootReal = await fsp.realpath(path.resolve(workspace));
  const rawCandidate = path.resolve(rootReal, relativePath);
  const targetReal = await resolveDeepestExistingAsync(rawCandidate);
  assertWorkspaceContainmentAndPolicy(rootReal, targetReal, relativePath);
  return targetReal;
}

/** Crash-safe atomic UTF-8 file write via temp file + handle.sync() + rename. */
export async function writeFileAtomicAsync(targetPath: string, content: string): Promise<void> {
  const dir = path.dirname(targetPath);
  await fsp.mkdir(dir, { recursive: true });
  const tmpPath = path.join(dir, `.tmp_${crypto.randomUUID()}.tmp`);
  try {
    const handle = await fsp.open(tmpPath, "w");
    try {
      await handle.writeFile(content, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fsp.rename(tmpPath, targetPath);
  } catch (err) {
    try {
      await fsp.unlink(tmpPath);
    } catch (cleanupErr) {
      if ((cleanupErr as NodeJS.ErrnoException).code !== "ENOENT") {
        throw cleanupErr;
      }
    }
    throw err;
  }
}

export interface SpillOutcome {
  readonly output: string;
  readonly truncated: boolean;
  readonly spillPath: string | null;
}

function buildBoundedSpillOutput(text: string, maxChars: number, spillPath: string): string {
  const fileName = path.basename(spillPath);
  const makeNotice = (omitted: number): string =>
    `\n...[truncated ${omitted} chars; full: ${fileName}]...\n`;

  let kept = Math.max(0, maxChars - makeNotice(text.length).length);
  for (let i = 0; i < 4; i += 1) {
    const omitted = text.length - kept;
    const notice = makeNotice(omitted);
    const nextKept = Math.max(0, maxChars - notice.length);
    if (nextKept === kept) {
      break;
    }
    kept = nextKept;
  }

  let omitted = text.length - kept;
  let notice = makeNotice(omitted);
  if (notice.length > maxChars) {
    return `\n...[truncated ${text.length} chars]...\n`.slice(0, maxChars);
  }
  if (kept + notice.length > maxChars) {
    kept = Math.max(0, maxChars - notice.length);
    omitted = text.length - kept;
    notice = makeNotice(omitted);
    if (kept + notice.length > maxChars) {
      kept = Math.max(0, kept - (kept + notice.length - maxChars));
      omitted = text.length - kept;
      notice = makeNotice(omitted);
    }
  }

  if (kept === 0) {
    return notice.slice(0, maxChars);
  }
  const headLen = Math.floor(kept / 2);
  const tailLen = kept - headLen;
  const head = text.slice(0, headLen);
  const tail = tailLen > 0 ? text.slice(text.length - tailLen) : "";
  return `${head}${notice}${tail}`;
}

function computeSpillPath(text: string, spillDir: string, label: string): string {
  const digest = crypto.createHash("sha256").update(text, "utf8").digest("hex").slice(0, 12);
  const safeLabel = label.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 32) || "tool";
  return path.join(spillDir, `${safeLabel}_${digest}.txt`);
}

/** Bound tool output in context (strictly <= maxChars) while atomically spilling full text to disk. */
export function truncateAndSpill(
  text: string,
  maxChars: number,
  spillDir: string,
  label: string,
): SpillOutcome {
  if (!Number.isInteger(maxChars) || maxChars < 120) {
    throw new Error("maxChars must be an integer >= 120");
  }
  if (text.length <= maxChars) {
    return { output: text, truncated: false, spillPath: null };
  }

  fs.mkdirSync(spillDir, { recursive: true });
  const spillPath = computeSpillPath(text, spillDir, label);
  const tmpPath = path.join(spillDir, `.spill_${crypto.randomUUID()}.tmp`);

  try {
    const fd = fs.openSync(tmpPath, "w");
    try {
      fs.writeFileSync(fd, text, "utf8");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmpPath, spillPath);
  } catch (err) {
    if (fs.existsSync(tmpPath)) {
      fs.unlinkSync(tmpPath);
    }
    throw err;
  }

  const bounded = buildBoundedSpillOutput(text, maxChars, spillPath);
  return { output: bounded, truncated: true, spillPath };
}

/** Async version of truncateAndSpill using node:fs/promises with handle.sync() durability. */
export async function truncateAndSpillAsync(
  text: string,
  maxChars: number,
  spillDir: string,
  label: string,
): Promise<SpillOutcome> {
  if (!Number.isInteger(maxChars) || maxChars < 120) {
    throw new Error("maxChars must be an integer >= 120");
  }
  if (text.length <= maxChars) {
    return { output: text, truncated: false, spillPath: null };
  }

  const spillPath = computeSpillPath(text, spillDir, label);
  await writeFileAtomicAsync(spillPath, text);
  const bounded = buildBoundedSpillOutput(text, maxChars, spillPath);
  return { output: bounded, truncated: true, spillPath };
}

export interface ApprovalDirective {
  readonly decision: ApprovalDecision;
  readonly reason?: string;
  readonly modifiedArguments?: Record<string, unknown>;
  /** Must not rename the tool; providing a different toolName is rejected. */
  readonly toolName?: string;
}

export interface ApprovalEvaluation {
  readonly approved: boolean;
  readonly decision: ApprovalDecision;
  readonly reason: string;
  readonly modifiedArguments?: Record<string, unknown>;
  readonly terminateRun: boolean;
}

export type ApprovalDecider = (
  toolName: string,
  args: Readonly<Record<string, unknown>>,
) => ApprovalDecision | ApprovalDirective;

function normalizeDirective(raw: ApprovalDecision | ApprovalDirective): ApprovalDirective {
  if (typeof raw === "string") {
    return { decision: raw };
  }
  return raw;
}

/**
 * Inspect AI aligned 5-decision ApprovalPolicy (`approve`, `modify`, `reject`, `escalate`, `terminate`)
 * with defensive cloning (never mutating proposed args in place) and 3-consecutive-rejection breaker.
 */
export class ApprovalPolicy {
  private readonly defaultDecision: ApprovalDecision;
  private readonly perTool: Map<string, ApprovalDecision>;
  private readonly decider: ApprovalDecider | undefined;
  private readonly escalators: readonly ApprovalDecider[];
  readonly maxConsecutiveRejections: number;
  consecutiveRejections: number;
  circuitOpen: boolean;

  constructor(options: {
    defaultDecision?: ApprovalDecision;
    perTool?: Readonly<Record<string, ApprovalDecision>>;
    decider?: ApprovalDecider;
    escalators?: readonly ApprovalDecider[];
    maxConsecutiveRejections?: number;
  } = {}) {
    const def: ApprovalDecision =
      options.defaultDecision ?? (options.decider ? "escalate" : "approve");
    if (!VALID_APPROVAL_DECISIONS.has(def)) {
      throw new Error(`Unsupported approval decision: ${def}`);
    }
    const maxRej = options.maxConsecutiveRejections ?? 3;
    if (!Number.isInteger(maxRej) || maxRej < 1) {
      throw new Error("maxConsecutiveRejections must be an integer >= 1");
    }
    for (const [tool, rule] of Object.entries(options.perTool ?? {})) {
      if (!VALID_APPROVAL_DECISIONS.has(rule)) {
        throw new Error(`Unsupported approval decision '${rule}' for tool '${tool}'`);
      }
    }
    this.defaultDecision = def;
    this.perTool = new Map(Object.entries(options.perTool ?? {}));
    this.decider = options.decider;
    this.escalators = [...(options.escalators ?? [])];
    this.maxConsecutiveRejections = maxRej;
    this.consecutiveRejections = 0;
    this.circuitOpen = false;
  }

  evaluate(toolName: string, args: Readonly<Record<string, unknown>>): ApprovalEvaluation {
    if (this.circuitOpen) {
      return {
        approved: false,
        decision: "terminate",
        reason: "Approval circuit breaker is open after repeated rejections. Run terminated.",
        terminateRun: true,
      };
    }

    const baseDecision: ApprovalDecision = this.perTool.get(toolName) ?? this.defaultDecision;
    let directive: ApprovalDirective = { decision: baseDecision };

    const layers: ApprovalDecider[] = [];
    if (this.decider) {
      layers.push(this.decider);
    }
    layers.push(...this.escalators);

    if (directive.decision === "escalate") {
      for (const layer of layers) {
        const snapshot = structuredClone(args) as Readonly<Record<string, unknown>>;
        const next = normalizeDirective(layer(toolName, snapshot));
        directive = next;
        if (directive.decision !== "escalate") {
          break;
        }
      }
    }

    let decision: ApprovalDecision = VALID_APPROVAL_DECISIONS.has(directive.decision)
      ? directive.decision
      : "reject";

    if (directive.toolName !== undefined && directive.toolName !== toolName) {
      return this.recordRejection(
        toolName,
        "reject",
        `Approval policy cannot rename tool '${toolName}' to '${directive.toolName}'.`,
      );
    }

    if (decision === "approve") {
      this.consecutiveRejections = 0;
      return {
        approved: true,
        decision: "approve",
        reason: directive.reason ?? "Approved by policy",
        terminateRun: false,
      };
    }

    if (decision === "modify") {
      const mod = directive.modifiedArguments;
      if (mod === null || typeof mod !== "object" || Array.isArray(mod)) {
        return this.recordRejection(
          toolName,
          "reject",
          "Approval decision 'modify' requires a JSON object in modifiedArguments.",
        );
      }
      this.consecutiveRejections = 0;
      return {
        approved: true,
        decision: "modify",
        reason: directive.reason ?? "Approved with modified arguments",
        modifiedArguments: structuredClone(mod) as Record<string, unknown>,
        terminateRun: false,
      };
    }

    if (decision === "terminate") {
      this.circuitOpen = true;
      return {
        approved: false,
        decision: "terminate",
        reason: directive.reason ?? `Tool '${toolName}' triggered immediate termination.`,
        terminateRun: true,
      };
    }

    // "reject" or unresolved "escalate" fail closed and increment rejection counter.
    const defaultReason =
      decision === "escalate"
        ? `Tool '${toolName}' was escalated with no approver accepting the call.`
        : `Tool '${toolName}' was rejected by approval policy.`;
    return this.recordRejection(toolName, decision, directive.reason ?? defaultReason);
  }

  private recordRejection(
    toolName: string,
    decision: ApprovalDecision,
    reason: string,
  ): ApprovalEvaluation {
    this.consecutiveRejections += 1;
    if (this.consecutiveRejections >= this.maxConsecutiveRejections) {
      this.circuitOpen = true;
      return {
        approved: false,
        decision: "terminate",
        reason: `Tool '${toolName}' rejected (${decision}); circuit breaker upgraded to terminate after ${this.consecutiveRejections} consecutive rejections. ${reason}`,
        terminateRun: true,
      };
    }
    return {
      approved: false,
      decision,
      reason: `${reason} Choose a safer alternative or ask the user.`,
      terminateRun: false,
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
  readonly approvalDecision?: ApprovalDecision;
  readonly executedArguments?: Record<string, unknown>;
}

function matchesJsonType(value: unknown, expectedType: string): boolean {
  if (expectedType === "string") return typeof value === "string";
  if (expectedType === "integer") return typeof value === "number" && Number.isInteger(value);
  if (expectedType === "number") return typeof value === "number" && Number.isFinite(value);
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

    // 1. Validate arguments against schema BEFORE approval so malformed calls never prompt or trip breaker.
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

    // 2. Evaluate Inspect AI 5-decision ApprovalPolicy on a defensive copy.
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
        approvalDecision: approval.decision,
      };
    }

    let effectiveArgs: Record<string, unknown>;
    if (approval.decision === "modify") {
      const revalidationError = validateToolArguments(spec, approval.modifiedArguments);
      if (revalidationError !== null) {
        return {
          toolCallId: toolCall.id,
          name: spec.name,
          output: `ERROR [invalid_modified_arguments]: Approval policy 'modify' produced invalid arguments: ${revalidationError}`,
          ok: false,
          durationMs: performance.now() - started,
          truncated: false,
          spillPath: null,
          errorCode: "invalid_modified_arguments",
          approvalDecision: approval.decision,
        };
      }
      effectiveArgs = structuredClone(approval.modifiedArguments!) as Record<string, unknown>;
    } else {
      effectiveArgs = structuredClone(toolCall.arguments) as Record<string, unknown>;
    }

    const defaultTimeoutMs = options.defaultTimeoutMs ?? 15000;
    const timeoutMs =
      spec.timeoutMs && spec.timeoutMs > 0
        ? Math.min(spec.timeoutMs, defaultTimeoutMs)
        : defaultTimeoutMs;

    let rawOutput: string;
    try {
      rawOutput = await runWithAbortTimeout(timeoutMs, (signal) =>
        spec.handler(structuredClone(effectiveArgs) as Record<string, unknown>, signal),
      );
    } catch (err) {
      if (err instanceof ToolExecutionError) {
        return {
          toolCallId: toolCall.id,
          name: spec.name,
          output: `ERROR [${err.code}]: ${err.message}`,
          ok: false,
          durationMs: performance.now() - started,
          truncated: false,
          spillPath: null,
          errorCode: err.code,
          approvalDecision: approval.decision,
          executedArguments: effectiveArgs,
        };
      }
      const isTimeout =
        err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
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
        approvalDecision: approval.decision,
        executedArguments: effectiveArgs,
      };
    }

    const spilled = await truncateAndSpillAsync(
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
      approvalDecision: approval.decision,
      executedArguments: effectiveArgs,
    };
  }
}

async function listFilesRecursive(root: string, dir: string, results: string[]): Promise<void> {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (isProtectedSegment(entry.name)) {
      continue;
    }
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
        const rootReal = await fsp.realpath(root);
        const target = await resolveInWorkspaceAsync(rootReal, rel);
        const found: string[] = [];
        await listFilesRecursive(rootReal, target, found);
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
        const target = await resolveInWorkspaceAsync(root, String(args.path));
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
        const target = await resolveInWorkspaceAsync(root, relPath);
        const content = await fsp.readFile(target, "utf8");
        if (expected && !content.includes(expected)) {
          throw new ToolExecutionError(
            `VERIFY_FAIL: '${relPath}' does not contain '${expected}'.`,
            "verify_failed",
          );
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
        const rootReal = await fsp.realpath(root);
        const target = await resolveInWorkspaceAsync(rootReal, relPath);
        if (target === rootReal) {
          throw new ToolExecutionError(
            "Refusing to overwrite workspace root directory.",
            "invalid_path",
          );
        }
        await writeFileAtomicAsync(target, content);
        return `Wrote ${content.length} chars to ${relPath}.`;
      },
    },
  ]);
}
