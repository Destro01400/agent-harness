/** Bounded agent harness loop, append-only redacted traces, atomic checkpoints, and hooks. */

import crypto from "node:crypto";
import fsp from "node:fs/promises";
import path from "node:path";
import {
  canonicalJson,
  createDefaultProfile,
  normalizeUsage,
  type HarnessProfile,
  type LLMProvider,
  type Message,
  type ModelResponse,
  type ToolCall,
} from "./provider.ts";
import {
  ApprovalPolicy,
  ToolRegistry,
  writeFileAtomicAsync,
  type ToolResult,
} from "./tools.ts";

const SECRET_PATTERNS: readonly (readonly [RegExp, string])[] = [
  [
    /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
    "[REDACTED_PRIVATE_KEY]",
  ],
  [/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
  [/\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]"],
  [/\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b/g, "[REDACTED]"],
  [/\bAIza[0-9A-Za-z_-]{16,}\b/g, "[REDACTED]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]"],
  [/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "[REDACTED]"],
  [/\bBearer\s+[A-Za-z0-9._-]{16,}/gi, "Bearer [REDACTED]"],
  [/([?&](?:X-Amz-Signature|access_token|token|sig|api_key)=)[^&\s"']+/gi, "$1[REDACTED]"],
];

export function redactSecrets(value: unknown): unknown {
  if (typeof value === "string") {
    let out = value;
    for (const [pattern, replacement] of SECRET_PATTERNS) {
      out = out.replace(pattern, replacement);
    }
    return out;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item));
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactSecrets(v);
    }
    return out;
  }
  return value;
}

export interface BudgetConfig {
  readonly maxSteps: number;
  readonly maxTokensIn: number;
  readonly maxTokensOut: number;
  readonly maxCostUsd: number;
  readonly maxWallTimeMs: number;
  readonly maxMessages: number;
  readonly maxWorkingMs: number;
  readonly softWarningFraction: number;
}

export function createBudgetConfig(overrides: Partial<BudgetConfig> = {}): BudgetConfig {
  const cfg: BudgetConfig = {
    maxSteps: overrides.maxSteps ?? 12,
    maxTokensIn: overrides.maxTokensIn ?? 200000,
    maxTokensOut: overrides.maxTokensOut ?? 50000,
    maxCostUsd: overrides.maxCostUsd ?? 2.0,
    maxWallTimeMs: overrides.maxWallTimeMs ?? 120000,
    maxMessages: overrides.maxMessages ?? 64,
    maxWorkingMs: overrides.maxWorkingMs ?? 120000,
    softWarningFraction: overrides.softWarningFraction ?? 0.75,
  };
  if (
    cfg.maxSteps < 1 ||
    cfg.maxTokensIn < 1 ||
    cfg.maxTokensOut < 1 ||
    cfg.maxWallTimeMs <= 0 ||
    cfg.maxMessages < 2 ||
    cfg.maxWorkingMs <= 0
  ) {
    throw new Error("Invalid BudgetConfig limits");
  }
  if (cfg.maxCostUsd < 0) {
    throw new Error("maxCostUsd must be >= 0");
  }
  if (cfg.softWarningFraction <= 0 || cfg.softWarningFraction > 1) {
    throw new Error("softWarningFraction must be in (0, 1]");
  }
  return cfg;
}

export interface TraceEventInput {
  readonly eventType: string;
  readonly operationName: string;
  readonly step: number;
  readonly status?: string;
  readonly tokensIn?: number;
  readonly tokensCached?: number;
  readonly tokensOut?: number;
  readonly thinkingTokens?: number;
  readonly payload?: Record<string, unknown>;
  readonly topLevel?: Record<string, unknown>;
}

export class TraceWriter {
  readonly filePath: string;
  readonly traceId: string;
  readonly sessionId: string;
  private lastTsMs: number;
  private dirEnsured: boolean;

  constructor(filePath: string, options: { traceId?: string; sessionId?: string } = {}) {
    this.filePath = filePath;
    this.traceId = options.traceId ?? crypto.randomUUID().replace(/-/g, "");
    this.sessionId = options.sessionId ?? crypto.randomUUID().replace(/-/g, "");
    this.lastTsMs = 0;
    this.dirEnsured = false;
  }

  private nextTimestamp(): string {
    let now = Date.now();
    if (now <= this.lastTsMs) {
      now = this.lastTsMs + 1;
    }
    this.lastTsMs = now;
    return new Date(now).toISOString();
  }

  async writeEvent(input: TraceEventInput): Promise<Record<string, unknown>> {
    if (!this.dirEnsured) {
      await fsp.mkdir(path.dirname(this.filePath), { recursive: true });
      this.dirEnsured = true;
    }

    const extra = input.topLevel
      ? (redactSecrets(input.topLevel) as Record<string, unknown>)
      : {};
    const record: Record<string, unknown> = {
      ...extra,
      event_type: input.eventType,
      "gen_ai.operation.name": input.operationName,
      payload: redactSecrets(input.payload ?? {}),
      session_id: this.sessionId,
      status: input.status ?? "ok",
      step: input.step,
      thinking_tokens: input.thinkingTokens ?? 0,
      timestamp: this.nextTimestamp(),
      tokens_cached: input.tokensCached ?? 0,
      tokens_in: input.tokensIn ?? 0,
      tokens_out: input.tokensOut ?? 0,
      trace_id: this.traceId,
    };
    await fsp.appendFile(this.filePath, `${canonicalJson(record)}\n`, "utf8");
    return record;
  }
}

interface MutableAssistantDraft {
  role: "assistant";
  content: string;
  tool_calls?: ToolCall[];
  reasoning_content?: string;
  thinking_blocks?: Record<string, unknown>[];
}

/** Pure projection: derive the model-visible Message history from canonical JSONL trace events. */
export function deriveMessagesFromEvents(events: readonly Record<string, unknown>[]): Message[] {
  const messages: (Message | MutableAssistantDraft)[] = [];
  const assistantByStep = new Map<number, number>();
  let lastAssistantIdx = -1;

  for (const event of events) {
    const evType = String(event.event_type ?? "").toLowerCase();
    const payload =
      event.payload !== null && typeof event.payload === "object" && !Array.isArray(event.payload)
        ? (event.payload as Record<string, unknown>)
        : {};
    const step = typeof event.step === "number" ? event.step : 0;

    if (evType === "agent_start") {
      if (typeof payload.system_prompt === "string") {
        messages.push({ role: "system", content: payload.system_prompt });
      }
      if (typeof payload.user_input === "string") {
        messages.push({ role: "user", content: payload.user_input });
      }
    } else if (evType === "user/message") {
      const content = String(event.content ?? payload.content ?? "");
      messages.push({ role: "user", content });
    } else if (evType === "assistant/message") {
      const draft: MutableAssistantDraft = {
        role: "assistant",
        content: String(event.content ?? payload.content ?? ""),
      };
      if (typeof payload.reasoning_content === "string") {
        draft.reasoning_content = payload.reasoning_content;
      }
      if (Array.isArray(payload.thinking_blocks) && payload.thinking_blocks.length > 0) {
        draft.thinking_blocks = structuredClone(
          payload.thinking_blocks as Record<string, unknown>[],
        );
      }
      const idx = messages.length;
      messages.push(draft);
      assistantByStep.set(step, idx);
      lastAssistantIdx = idx;
    } else if (evType === "tool/call") {
      const callId = String(event.tool_call_id ?? payload.tool_call_id ?? "");
      const toolName = String(event.tool_name ?? payload.tool_name ?? "");
      const rawArgs = event.arguments ?? payload.arguments ?? {};
      const toolCall: ToolCall = {
        id: callId,
        name: toolName,
        arguments:
          rawArgs !== null && typeof rawArgs === "object" && !Array.isArray(rawArgs)
            ? (structuredClone(rawArgs) as Record<string, unknown>)
            : {},
      };
      const targetIdx = assistantByStep.get(step) ?? lastAssistantIdx;
      if (targetIdx >= 0 && messages[targetIdx]?.role === "assistant") {
        const draft = messages[targetIdx] as MutableAssistantDraft;
        if (!draft.tool_calls) {
          draft.tool_calls = [];
        }
        draft.tool_calls.push(toolCall);
      }
    } else if (evType === "tool/result") {
      const callId = String(event.tool_call_id ?? payload.tool_call_id ?? "");
      const toolName = String(event.tool_name ?? payload.tool_name ?? "");
      const output = String(event.output ?? payload.output ?? "");
      messages.push({
        role: "tool",
        content: output,
        tool_call_id: callId,
        name: toolName,
      });
    }
  }

  return messages as Message[];
}

/** Reconstruct model-visible messages directly from an append-only JSONL session trace file. */
export async function deriveMessagesFromTrace(tracePath: string): Promise<Message[]> {
  const raw = await fsp.readFile(tracePath, "utf8");
  const events: Record<string, unknown>[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    events.push(JSON.parse(trimmed) as Record<string, unknown>);
  }
  return deriveMessagesFromEvents(events);
}

export interface CheckpointState {
  readonly completed: boolean;
  readonly messages: Message[];
  readonly mutated: boolean;
  readonly session_id: string;
  readonly soft_warning_sent: boolean;
  readonly step: number;
  readonly stop_reason: string;
  readonly tool_calls_made: string[];
  readonly totals: {
    cost_usd: number;
    thinking_tokens: number;
    tokens_cached: number;
    tokens_in: number;
    tokens_out: number;
  };
  readonly trace_id: string;
  readonly verification_nudges: number;
  readonly verified_after_mutation: boolean;
  readonly working_ms: number;
}

export class CheckpointStore {
  readonly directory: string;

  constructor(directory: string) {
    this.directory = directory;
  }

  private pathFor(sessionId: string): string {
    const safe = sessionId.replace(/[^a-zA-Z0-9_-]/g, "_");
    return path.join(this.directory, `${safe}.checkpoint.json`);
  }

  async save(sessionId: string, state: CheckpointState): Promise<string> {
    const target = this.pathFor(sessionId);
    const body = `${canonicalJson(redactSecrets(state), 2)}\n`;
    await writeFileAtomicAsync(target, body);
    return target;
  }

  async load(sessionId: string): Promise<CheckpointState | null> {
    const target = this.pathFor(sessionId);
    try {
      const content = await fsp.readFile(target, "utf8");
      return JSON.parse(content) as CheckpointState;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return null;
      }
      throw err;
    }
  }
}

export interface HookContext {
  step: number;
  messages: Message[];
  mutated: boolean;
  verifiedAfterMutation: boolean;
  verificationNudges: number;
  toolHistory: string[];
}

export interface MiddlewareHook {
  preStep?(ctx: HookContext): void;
  preTool?(ctx: HookContext, toolCall: ToolCall): string | null;
  postTool?(
    ctx: HookContext,
    toolCall: ToolCall,
    result: ToolResult,
    meta: { mutating: boolean; verification: boolean },
  ): void;
  preExit?(ctx: HookContext, finalContent: string): string | null;
}

export class LoopDetectionHook implements MiddlewareHook {
  private readonly maxIdenticalRepeats: number;
  private lastSignature: string | null;
  private repeatCount: number;

  constructor(maxIdenticalRepeats = 2) {
    if (maxIdenticalRepeats < 1) {
      throw new Error("maxIdenticalRepeats must be >= 1");
    }
    this.maxIdenticalRepeats = maxIdenticalRepeats;
    this.lastSignature = null;
    this.repeatCount = 0;
  }

  preTool(_ctx: HookContext, toolCall: ToolCall): string | null {
    const sig = `${toolCall.name}:${canonicalJson(toolCall.arguments)}`;
    if (sig === this.lastSignature) {
      this.repeatCount += 1;
    } else {
      this.lastSignature = sig;
      this.repeatCount = 1;
    }
    if (this.repeatCount > this.maxIdenticalRepeats) {
      return `ERROR [doom_loop_detected]: Identical call to '${toolCall.name}' repeated ${this.repeatCount} times with unchanged arguments. Change approach or stop.`;
    }
    return null;
  }
}

export class PreCompletionVerifyHook implements MiddlewareHook {
  private readonly maxNudges: number;

  constructor(maxNudges = 1) {
    this.maxNudges = maxNudges;
  }

  postTool(
    ctx: HookContext,
    _toolCall: ToolCall,
    result: ToolResult,
    meta: { mutating: boolean; verification: boolean },
  ): void {
    if (result.ok && meta.mutating) {
      ctx.mutated = true;
      ctx.verifiedAfterMutation = false;
    } else if (meta.verification) {
      ctx.verifiedAfterMutation = result.ok;
    }
  }

  preExit(ctx: HookContext): string | null {
    if (ctx.mutated && !ctx.verifiedAfterMutation && ctx.verificationNudges < this.maxNudges) {
      ctx.verificationNudges += 1;
      return "Before finishing, run a verification tool (such as verify_file) to confirm your workspace changes against the expected outcome.";
    }
    return null;
  }
}

export interface RunResult {
  readonly sessionId: string;
  readonly traceId: string;
  readonly finalOutput: string;
  readonly stopReason: string;
  readonly steps: number;
  readonly tokensIn: number;
  readonly tokensCached: number;
  readonly tokensOut: number;
  readonly thinkingTokens: number;
  readonly costUsd: number;
  readonly toolCallsMade: readonly string[];
  readonly messages: readonly Message[];
}

export class AgentHarness {
  private readonly provider: LLMProvider;
  private readonly tools: ToolRegistry;
  private readonly profile: HarnessProfile;
  private readonly budget: BudgetConfig;
  private readonly trace: TraceWriter;
  private readonly checkpoints: CheckpointStore;
  private readonly approvalPolicy: ApprovalPolicy;
  private readonly spillDir: string;
  private readonly hooks: readonly MiddlewareHook[];

  constructor(options: {
    provider: LLMProvider;
    tools: ToolRegistry;
    profile?: HarnessProfile;
    budget?: BudgetConfig;
    traceWriter: TraceWriter;
    checkpointStore: CheckpointStore;
    approvalPolicy?: ApprovalPolicy;
    spillDir: string;
    hooks?: readonly MiddlewareHook[];
  }) {
    this.provider = options.provider;
    this.tools = options.tools;
    this.profile = options.profile ?? createDefaultProfile();
    this.budget = options.budget ?? createBudgetConfig();
    this.trace = options.traceWriter;
    this.checkpoints = options.checkpointStore;
    this.approvalPolicy = options.approvalPolicy ?? new ApprovalPolicy();
    this.spillDir = options.spillDir;
    if (options.hooks !== undefined) {
      this.hooks = [...options.hooks];
    } else {
      const defaults: MiddlewareHook[] = [];
      if (this.profile.enableLoopDetection) {
        defaults.push(new LoopDetectionHook());
      }
      if (this.profile.enablePreCompletionVerify) {
        defaults.push(new PreCompletionVerifyHook());
      }
      this.hooks = defaults;
    }
  }

  async run(userInput: string, options: { resume?: boolean } = {}): Promise<RunResult> {
    const started = performance.now();
    const toolSchemas = this.tools.schemas();

    let messages: Message[] = [];
    let startStep = 1;
    const totals = {
      cost_usd: 0,
      thinking_tokens: 0,
      tokens_cached: 0,
      tokens_in: 0,
      tokens_out: 0,
    };
    let toolCallsMade: string[] = [];
    let mutated = false;
    let verifiedAfterMutation = false;
    let verificationNudges = 0;
    let workingMs = 0;
    let softWarningSent = false;

    if (options.resume) {
      const saved = await this.checkpoints.load(this.trace.sessionId);
      if (saved) {
        if (saved.completed) {
          const lastAssistant = [...saved.messages]
            .reverse()
            .find((m) => m.role === "assistant");
          return {
            sessionId: saved.session_id,
            traceId: saved.trace_id,
            finalOutput: lastAssistant?.content ?? "",
            stopReason: saved.stop_reason || "completed",
            steps: saved.step,
            tokensIn: saved.totals.tokens_in,
            tokensCached: saved.totals.tokens_cached,
            tokensOut: saved.totals.tokens_out,
            thinkingTokens: saved.totals.thinking_tokens,
            costUsd: saved.totals.cost_usd,
            toolCallsMade: [...saved.tool_calls_made],
            messages: structuredClone(saved.messages),
          };
        }
        messages = structuredClone(saved.messages);
        startStep = saved.step + 1;
        Object.assign(totals, saved.totals);
        toolCallsMade = [...saved.tool_calls_made];
        mutated = saved.mutated;
        verifiedAfterMutation = saved.verified_after_mutation;
        verificationNudges = saved.verification_nudges ?? 0;
        workingMs = saved.working_ms ?? 0;
        softWarningSent = saved.soft_warning_sent ?? false;
      }
    }

    if (messages.length === 0) {
      messages = [
        { role: "system", content: this.profile.systemPrompt },
        { role: "user", content: userInput },
      ];
      await this.trace.writeEvent({
        eventType: "agent_start",
        operationName: "invoke_agent",
        step: 0,
        payload: {
          profile: this.profile.name,
          system_prompt: this.profile.systemPrompt,
          user_input: userInput,
        },
      });
    }

    const ctx: HookContext = {
      step: startStep,
      messages,
      mutated,
      verifiedAfterMutation,
      verificationNudges,
      toolHistory: toolCallsMade,
    };

    let lastOutput = "";
    let stopReason = "max_steps";
    let executedSteps = startStep - 1;

    for (let step = startStep; step <= this.budget.maxSteps; step += 1) {
      ctx.step = step;
      const wallElapsedMs = performance.now() - started;
      if (wallElapsedMs > this.budget.maxWallTimeMs) {
        stopReason = "wall_time_exceeded";
        break;
      }
      if (workingMs > this.budget.maxWorkingMs) {
        stopReason = "working_time_exceeded";
        break;
      }
      if (messages.length >= this.budget.maxMessages) {
        stopReason = "message_budget_exceeded";
        break;
      }
      if (totals.tokens_in >= this.budget.maxTokensIn) {
        stopReason = "token_in_budget_exceeded";
        break;
      }
      if (totals.tokens_out >= this.budget.maxTokensOut) {
        stopReason = "token_out_budget_exceeded";
        break;
      }
      if (totals.cost_usd > this.budget.maxCostUsd) {
        stopReason = "cost_budget_exceeded";
        break;
      }

      if (!softWarningSent) {
        const utilizations: readonly (readonly [string, number])[] = [
          ["steps", (step - 1) / this.budget.maxSteps],
          ["tokens_in", totals.tokens_in / this.budget.maxTokensIn],
          ["tokens_out", totals.tokens_out / this.budget.maxTokensOut],
          ["cost_usd", this.budget.maxCostUsd > 0 ? totals.cost_usd / this.budget.maxCostUsd : 0],
          ["messages", messages.length / this.budget.maxMessages],
          ["wall_time", wallElapsedMs / this.budget.maxWallTimeMs],
          ["working_time", workingMs / this.budget.maxWorkingMs],
        ];
        const highest = utilizations.reduce((best, curr) => (curr[1] > best[1] ? curr : best));
        if (highest[1] >= this.budget.softWarningFraction) {
          softWarningSent = true;
          const pct = Math.min(100, Math.round(highest[1] * 100));
          const warningText =
            `[BUDGET WARNING]: Approaching ${highest[0]} budget limit (${pct}% used). ` +
            "Wrap up verification and deliver your concise final answer.";
          messages.push({ role: "user", content: warningText });
          await this.trace.writeEvent({
            eventType: "user/message",
            operationName: "plan",
            step,
            topLevel: { content: warningText },
            payload: {
              content: warningText,
              kind: "budget_warning",
              metric: highest[0],
              utilization: Number(highest[1].toFixed(4)),
            },
          });
        }
      }

      executedSteps = step;
      for (const hook of this.hooks) {
        hook.preStep?.(ctx);
      }

      const remainingWallMs = this.budget.maxWallTimeMs - (performance.now() - started);
      const remainingWorkingMs = this.budget.maxWorkingMs - workingMs;
      const callTimeoutMs = Math.floor(Math.min(remainingWallMs, remainingWorkingMs));
      if (callTimeoutMs <= 0) {
        stopReason = remainingWallMs <= remainingWorkingMs
          ? "wall_time_exceeded"
          : "working_time_exceeded";
        break;
      }

      const llmStarted = performance.now();
      let response: ModelResponse;
      try {
        const timeoutSignal = AbortSignal.timeout(callTimeoutMs);
        response = await this.provider.complete(messages, toolSchemas, this.profile, {
          signal: timeoutSignal,
        });
      } catch (err) {
        workingMs += performance.now() - llmStarted;
        const isAbortOrTimeout =
          err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
        if (isAbortOrTimeout) {
          stopReason =
            performance.now() - started >= this.budget.maxWallTimeMs
              ? "wall_time_exceeded"
              : "working_time_exceeded";
          break;
        }
        throw err;
      }
      workingMs += performance.now() - llmStarted;

      const usage = normalizeUsage(response.usage);
      totals.tokens_in += usage.tokens_in;
      totals.tokens_cached += usage.tokens_cached;
      totals.tokens_out += usage.tokens_out;
      totals.thinking_tokens += usage.thinking_tokens;
      totals.cost_usd += usage.cost_usd;

      const toolCalls = response.tool_calls ?? [];
      const assistantMsg: Message = {
        role: "assistant",
        content: response.content,
        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
        ...(this.profile.preserveReasoningContent && response.reasoning_content !== undefined
          ? { reasoning_content: response.reasoning_content }
          : {}),
        ...(this.profile.preserveThinkingBlocks && response.thinking_blocks !== undefined
          ? { thinking_blocks: response.thinking_blocks }
          : {}),
      };
      messages.push(assistantMsg);
      lastOutput = response.content;

      const turnStopReason = toolCalls.length > 0
        ? "tool_use"
        : (response.stop_reason ?? "end_turn");

      await this.trace.writeEvent({
        eventType: "assistant/message",
        operationName: "chat",
        step,
        tokensIn: usage.tokens_in,
        tokensCached: usage.tokens_cached,
        tokensOut: usage.tokens_out,
        thinkingTokens: usage.thinking_tokens,
        topLevel: {
          content: response.content,
          stop_reason: turnStopReason,
        },
        payload: {
          content: response.content,
          has_reasoning: assistantMsg.reasoning_content !== undefined,
          ...(assistantMsg.reasoning_content !== undefined
            ? { reasoning_content: assistantMsg.reasoning_content }
            : {}),
          ...(assistantMsg.thinking_blocks !== undefined
            ? { thinking_blocks: assistantMsg.thinking_blocks }
            : {}),
          stop_reason: turnStopReason,
          tool_call_count: toolCalls.length,
        },
      });

      if (toolCalls.length > 0) {
        let circuitTripped = false;
        for (const tc of toolCalls) {
          toolCallsMade.push(tc.name);
          await this.trace.writeEvent({
            eventType: "tool/call",
            operationName: "execute_tool",
            step,
            topLevel: {
              arguments: tc.arguments,
              tool_call_id: tc.id,
              tool_name: tc.name,
            },
            payload: {
              arguments: tc.arguments,
              tool_call_id: tc.id,
              tool_name: tc.name,
            },
          });

          let blockedReason: string | null = null;
          for (const hook of this.hooks) {
            const verdict = hook.preTool?.(ctx, tc) ?? null;
            if (verdict !== null) {
              blockedReason = verdict;
              break;
            }
          }

          const toolStarted = performance.now();
          const result: ToolResult =
            blockedReason !== null
              ? {
                  toolCallId: tc.id,
                  name: tc.name,
                  output: blockedReason,
                  ok: false,
                  durationMs: 0,
                  truncated: false,
                  spillPath: null,
                  errorCode: "hook_blocked",
                }
              : await this.tools.execute(tc, {
                  approvalPolicy: this.approvalPolicy,
                  spillDir: this.spillDir,
                  maxOutputChars: this.profile.maxOutputChars,
                  defaultTimeoutMs: this.profile.defaultToolTimeoutMs,
                  aliases: this.profile.toolAliases,
                });
          workingMs += performance.now() - toolStarted;

          if (result.approvalDecision === "modify") {
            await this.trace.writeEvent({
              eventType: "approval/decision",
              operationName: "execute_tool",
              step,
              topLevel: {
                tool_call_id: tc.id,
                tool_name: result.name,
              },
              payload: {
                decision: "modify",
                modified_arguments: result.executedArguments ?? {},
                tool_call_id: tc.id,
                tool_name: result.name,
              },
            });
          }

          const spec = this.tools.get(tc.name, this.profile.toolAliases);
          for (const hook of this.hooks) {
            hook.postTool?.(ctx, tc, result, {
              mutating: Boolean(spec?.mutating),
              verification: Boolean(spec?.verification),
            });
          }

          // Emit tool outputs strictly with role="tool" and keep failed turns in context.
          messages.push({
            role: "tool",
            content: result.output,
            tool_call_id: tc.id,
            name: result.name,
          });
          await this.trace.writeEvent({
            eventType: "tool/result",
            operationName: "execute_tool",
            step,
            status: result.ok ? "ok" : "error",
            topLevel: {
              is_error: !result.ok,
              output: result.output,
              tool_call_id: tc.id,
              tool_name: result.name,
            },
            payload: {
              duration_ms: Number(result.durationMs.toFixed(2)),
              error_code: result.errorCode,
              is_error: !result.ok,
              output: result.output,
              spill_path: result.spillPath,
              tool_call_id: tc.id,
              tool_name: result.name,
              truncated: result.truncated,
            },
          });

          if (this.approvalPolicy.circuitOpen) {
            circuitTripped = true;
          }
        }

        await this.checkpoints.save(this.trace.sessionId, {
          completed: false,
          messages,
          mutated: ctx.mutated,
          session_id: this.trace.sessionId,
          soft_warning_sent: softWarningSent,
          step,
          stop_reason: "in_progress",
          tool_calls_made: toolCallsMade,
          totals: { ...totals },
          trace_id: this.trace.traceId,
          verification_nudges: ctx.verificationNudges,
          verified_after_mutation: ctx.verifiedAfterMutation,
          working_ms: Number(workingMs.toFixed(2)),
        });

        if (circuitTripped) {
          stopReason =
            this.approvalPolicy.consecutiveRejections >=
            this.approvalPolicy.maxConsecutiveRejections
              ? "approval_circuit_breaker"
              : "approval_terminated";
          break;
        }
        continue;
      }

      let exitNudge: string | null = null;
      for (const hook of this.hooks) {
        const verdict = hook.preExit?.(ctx, response.content) ?? null;
        if (verdict !== null) {
          exitNudge = verdict;
          break;
        }
      }

      if (exitNudge !== null) {
        messages.push({ role: "user", content: exitNudge });
        await this.trace.writeEvent({
          eventType: "user/message",
          operationName: "plan",
          step,
          topLevel: { content: exitNudge },
          payload: { content: exitNudge, kind: "pre_exit_nudge" },
        });
        continue;
      }

      stopReason = "completed";
      await this.checkpoints.save(this.trace.sessionId, {
        completed: true,
        messages,
        mutated: ctx.mutated,
        session_id: this.trace.sessionId,
        soft_warning_sent: softWarningSent,
        step,
        stop_reason: stopReason,
        tool_calls_made: toolCallsMade,
        totals: { ...totals },
        trace_id: this.trace.traceId,
        verification_nudges: ctx.verificationNudges,
        verified_after_mutation: ctx.verifiedAfterMutation,
        working_ms: Number(workingMs.toFixed(2)),
      });
      break;
    }

    await this.trace.writeEvent({
      eventType: "agent_end",
      operationName: "invoke_agent",
      step: executedSteps,
      status: stopReason === "completed" ? "ok" : "stopped",
      topLevel: { stop_reason: stopReason },
      payload: {
        cost_usd: Number(totals.cost_usd.toFixed(6)),
        stop_reason: stopReason,
        steps: executedSteps,
        working_ms: Number(workingMs.toFixed(2)),
      },
    });

    return {
      sessionId: this.trace.sessionId,
      traceId: this.trace.traceId,
      finalOutput: lastOutput,
      stopReason,
      steps: executedSteps,
      tokensIn: totals.tokens_in,
      tokensCached: totals.tokens_cached,
      tokensOut: totals.tokens_out,
      thinkingTokens: totals.thinking_tokens,
      costUsd: totals.cost_usd,
      toolCallsMade,
      messages,
    };
  }
}
