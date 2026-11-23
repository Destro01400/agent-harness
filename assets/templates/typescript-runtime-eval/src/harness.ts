/** Bounded agent harness loop, append-only redacted traces, atomic checkpoints, and hooks. */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  canonicalJson,
  createDefaultProfile,
  normalizeUsage,
  type HarnessProfile,
  type LLMProvider,
  type Message,
  type ToolCall,
} from "./provider.ts";
import { ApprovalPolicy, ToolRegistry, type ToolResult } from "./tools.ts";

const SECRET_PATTERNS: readonly (readonly [RegExp, string])[] = [
  [
    /-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----/g,
    "[REDACTED_PRIVATE_KEY]",
  ],
  [/\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]"],
  [/\bsk-[A-Za-z0-9_-]{12,}\b/g, "[REDACTED]"],
  [/\bAIza[0-9A-Za-z_-]{16,}\b/g, "[REDACTED]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]"],
  [/\bghp_[A-Za-z0-9]{20,}\b/g, "[REDACTED]"],
  [/Bearer\s+[A-Za-z0-9._-]{16,}/g, "Bearer [REDACTED]"],
  [/([?&](?:X-Amz-Signature|token|sig|api_key)=)[^&\s"']+/g, "$1[REDACTED]"],
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
}

export function createBudgetConfig(overrides: Partial<BudgetConfig> = {}): BudgetConfig {
  const cfg: BudgetConfig = {
    maxSteps: overrides.maxSteps ?? 12,
    maxTokensIn: overrides.maxTokensIn ?? 200000,
    maxTokensOut: overrides.maxTokensOut ?? 50000,
    maxCostUsd: overrides.maxCostUsd ?? 2.0,
    maxWallTimeMs: overrides.maxWallTimeMs ?? 120000,
  };
  if (cfg.maxSteps < 1 || cfg.maxTokensIn < 1 || cfg.maxTokensOut < 1 || cfg.maxWallTimeMs <= 0) {
    throw new Error("Invalid BudgetConfig limits");
  }
  if (cfg.maxCostUsd < 0) {
    throw new Error("maxCostUsd must be >= 0");
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
}

export class TraceWriter {
  readonly filePath: string;
  readonly traceId: string;
  readonly sessionId: string;
  private lastTsMs: number;

  constructor(filePath: string, options: { traceId?: string; sessionId?: string } = {}) {
    this.filePath = filePath;
    this.traceId = options.traceId ?? crypto.randomUUID().replace(/-/g, "");
    this.sessionId = options.sessionId ?? crypto.randomUUID().replace(/-/g, "");
    this.lastTsMs = 0;
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
  }

  private nextTimestamp(): string {
    let now = Date.now();
    if (now <= this.lastTsMs) {
      now = this.lastTsMs + 1;
    }
    this.lastTsMs = now;
    return new Date(now).toISOString();
  }

  writeEvent(input: TraceEventInput): Record<string, unknown> {
    const record: Record<string, unknown> = {
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
    fs.appendFileSync(this.filePath, `${canonicalJson(record)}\n`, "utf8");
    return record;
  }
}

export interface CheckpointState {
  readonly completed: boolean;
  readonly messages: Message[];
  readonly mutated: boolean;
  readonly session_id: string;
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
  readonly verified_after_mutation: boolean;
}

export class CheckpointStore {
  readonly directory: string;

  constructor(directory: string) {
    this.directory = directory;
    fs.mkdirSync(this.directory, { recursive: true });
  }

  private pathFor(sessionId: string): string {
    const safe = sessionId.replace(/[^a-zA-Z0-9_-]/g, "_");
    return path.join(this.directory, `${safe}.checkpoint.json`);
  }

  save(sessionId: string, state: CheckpointState): string {
    const target = this.pathFor(sessionId);
    const tmpPath = path.join(this.directory, `.ckpt_${crypto.randomUUID()}.tmp`);
    const body = `${canonicalJson(redactSecrets(state), 2)}\n`;
    try {
      fs.writeFileSync(tmpPath, body, "utf8");
      fs.renameSync(tmpPath, target);
    } catch (err) {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
      throw err;
    }
    return target;
  }

  load(sessionId: string): CheckpointState | null {
    const target = this.pathFor(sessionId);
    if (!fs.existsSync(target)) {
      return null;
    }
    return JSON.parse(fs.readFileSync(target, "utf8")) as CheckpointState;
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
    } else if (result.ok && meta.verification) {
      ctx.verifiedAfterMutation = true;
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

    if (options.resume) {
      const saved = this.checkpoints.load(this.trace.sessionId);
      if (saved) {
        messages = structuredClone(saved.messages);
        startStep = saved.step + 1;
        Object.assign(totals, saved.totals);
        toolCallsMade = [...saved.tool_calls_made];
        mutated = saved.mutated;
        verifiedAfterMutation = saved.verified_after_mutation;
      }
    }

    if (messages.length === 0) {
      messages = [
        { role: "system", content: this.profile.systemPrompt },
        { role: "user", content: userInput },
      ];
      this.trace.writeEvent({
        eventType: "agent_start",
        operationName: "invoke_agent",
        step: 0,
        payload: { profile: this.profile.name, user_input: userInput },
      });
    }

    const ctx: HookContext = {
      step: startStep,
      messages,
      mutated,
      verifiedAfterMutation,
      verificationNudges: 0,
      toolHistory: toolCallsMade,
    };

    let lastOutput = "";
    let stopReason = "max_steps";
    let executedSteps = startStep - 1;

    for (let step = startStep; step <= this.budget.maxSteps; step += 1) {
      ctx.step = step;
      if (performance.now() - started > this.budget.maxWallTimeMs) {
        stopReason = "wall_time_exceeded";
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

      executedSteps = step;
      for (const hook of this.hooks) {
        hook.preStep?.(ctx);
      }

      const response = await this.provider.complete(messages, toolSchemas, this.profile);
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

      this.trace.writeEvent({
        eventType: "model_response",
        operationName: "chat",
        step,
        tokensIn: usage.tokens_in,
        tokensCached: usage.tokens_cached,
        tokensOut: usage.tokens_out,
        thinkingTokens: usage.thinking_tokens,
        payload: {
          content: response.content,
          has_reasoning: assistantMsg.reasoning_content !== undefined,
          stop_reason: response.stop_reason ?? "end_turn",
          tool_call_count: toolCalls.length,
        },
      });

      if (toolCalls.length > 0) {
        let circuitTripped = false;
        for (const tc of toolCalls) {
          toolCallsMade.push(tc.name);
          this.trace.writeEvent({
            eventType: "tool_call",
            operationName: "execute_tool",
            step,
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

          const result: ToolResult = blockedReason !== null
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
          this.trace.writeEvent({
            eventType: "tool_result",
            operationName: "execute_tool",
            step,
            status: result.ok ? "ok" : "error",
            payload: {
              duration_ms: Number(result.durationMs.toFixed(2)),
              error_code: result.errorCode,
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

        this.checkpoints.save(this.trace.sessionId, {
          completed: false,
          messages,
          mutated: ctx.mutated,
          session_id: this.trace.sessionId,
          step,
          stop_reason: "in_progress",
          tool_calls_made: toolCallsMade,
          totals: { ...totals },
          trace_id: this.trace.traceId,
          verified_after_mutation: ctx.verifiedAfterMutation,
        });

        if (circuitTripped) {
          stopReason = "approval_circuit_breaker";
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
        this.trace.writeEvent({
          eventType: "pre_exit_nudge",
          operationName: "plan",
          step,
          payload: { nudge: exitNudge },
        });
        continue;
      }

      stopReason = "completed";
      this.checkpoints.save(this.trace.sessionId, {
        completed: true,
        messages,
        mutated: ctx.mutated,
        session_id: this.trace.sessionId,
        step,
        stop_reason: stopReason,
        tool_calls_made: toolCallsMade,
        totals: { ...totals },
        trace_id: this.trace.traceId,
        verified_after_mutation: ctx.verifiedAfterMutation,
      });
      break;
    }

    this.trace.writeEvent({
      eventType: "agent_end",
      operationName: "invoke_agent",
      step: executedSteps,
      status: stopReason === "completed" ? "ok" : "stopped",
      payload: {
        cost_usd: Number(totals.cost_usd.toFixed(6)),
        stop_reason: stopReason,
        steps: executedSteps,
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
