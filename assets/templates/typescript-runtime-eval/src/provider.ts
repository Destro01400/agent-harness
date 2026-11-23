/** Thin LLM provider seam, immutable message contracts, canonical JSON, and HarnessProfile. */

export interface ToolCall {
  readonly id: string;
  readonly name: string;
  readonly arguments: Record<string, unknown>;
}

export interface Message {
  readonly role: "system" | "user" | "assistant" | "tool";
  readonly content: string;
  readonly tool_calls?: readonly ToolCall[];
  readonly tool_call_id?: string;
  readonly name?: string;
  readonly reasoning_content?: string;
  readonly thinking_blocks?: readonly Record<string, unknown>[];
}

export interface Usage {
  readonly tokens_in: number;
  readonly tokens_cached: number;
  readonly tokens_out: number;
  readonly thinking_tokens: number;
  readonly cost_usd: number;
}

export interface ModelResponse {
  readonly content: string;
  readonly tool_calls?: readonly ToolCall[];
  readonly usage?: Partial<Usage>;
  readonly reasoning_content?: string;
  readonly thinking_blocks?: readonly Record<string, unknown>[];
  readonly stop_reason?: string;
}

export interface HarnessProfile {
  readonly name: string;
  readonly systemPrompt: string;
  readonly preserveReasoningContent: boolean;
  readonly preserveThinkingBlocks: boolean;
  readonly toolAliases: Readonly<Record<string, string>>;
  readonly maxOutputChars: number;
  readonly defaultToolTimeoutMs: number;
  readonly enableLoopDetection: boolean;
  readonly enablePreCompletionVerify: boolean;
  readonly temperature: number;
}

export interface ToolSchema {
  readonly name: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
  readonly input_examples?: readonly Record<string, unknown>[];
}

export interface CompleteOptions {
  readonly signal?: AbortSignal;
}

export interface LLMProvider {
  complete(
    messages: readonly Message[],
    tools: readonly ToolSchema[],
    profile: HarnessProfile,
    options?: CompleteOptions,
  ): Promise<ModelResponse>;
}

export interface RecordedCall {
  readonly callIndex: number;
  readonly messages: Message[];
  readonly profile: string;
  readonly tools: ToolSchema[];
}

export function createDefaultProfile(overrides: Partial<HarnessProfile> = {}): HarnessProfile {
  return {
    name: overrides.name ?? "default-profile",
    systemPrompt:
      overrides.systemPrompt ??
      "You are a focused, deterministic assistant. Use the registered tools to inspect and verify ground truth before answering concisely.",
    preserveReasoningContent: overrides.preserveReasoningContent ?? true,
    preserveThinkingBlocks: overrides.preserveThinkingBlocks ?? true,
    toolAliases: overrides.toolAliases ?? {},
    maxOutputChars: overrides.maxOutputChars ?? 8000,
    defaultToolTimeoutMs: overrides.defaultToolTimeoutMs ?? 15000,
    enableLoopDetection: overrides.enableLoopDetection ?? true,
    enablePreCompletionVerify: overrides.enablePreCompletionVerify ?? true,
    temperature: overrides.temperature ?? 0,
  };
}

export function normalizeUsage(partial: Partial<Usage> = {}): Usage {
  const usage: Usage = {
    tokens_in: partial.tokens_in ?? 0,
    tokens_cached: partial.tokens_cached ?? 0,
    tokens_out: partial.tokens_out ?? 0,
    thinking_tokens: partial.thinking_tokens ?? 0,
    cost_usd: partial.cost_usd ?? 0,
  };
  if (usage.tokens_in < 0 || usage.tokens_cached < 0) {
    throw new Error("Input token counts must be non-negative");
  }
  if (usage.tokens_cached > usage.tokens_in) {
    throw new Error("tokens_cached cannot exceed tokens_in");
  }
  if (usage.tokens_out < 0 || usage.thinking_tokens < 0) {
    throw new Error("Output token counts must be non-negative");
  }
  if (usage.thinking_tokens > usage.tokens_out) {
    throw new Error("thinking_tokens cannot exceed tokens_out");
  }
  if (usage.cost_usd < 0) {
    throw new Error("cost_usd must be non-negative");
  }
  return usage;
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortKeysDeep(item));
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const sorted: Record<string, unknown> = {};
    for (const [key, val] of entries) {
      sorted[key] = sortKeysDeep(val);
    }
    return sorted;
  }
  return value;
}

/** Deterministic key-sorted JSON serialization for KV-cache-safe prefixes and traces. */
export function canonicalJson(value: unknown, indent?: number): string {
  return JSON.stringify(sortKeysDeep(value), null, indent);
}

export type MockHandler = (
  messages: readonly Message[],
  tools: readonly ToolSchema[],
  profile: HarnessProfile,
  callIndex: number,
  options?: CompleteOptions,
) => ModelResponse | Promise<ModelResponse>;

async function raceWithAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) {
    return await promise;
  }
  if (signal.aborted) {
    throw signal.reason instanceof Error ? signal.reason : new Error("Operation aborted");
  }
  let onAbort: (() => void) | undefined;
  const abortPromise = new Promise<never>((_resolve, reject) => {
    onAbort = () => {
      reject(signal.reason instanceof Error ? signal.reason : new Error("Operation aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([promise, abortPromise]);
  } finally {
    if (onAbort) {
      signal.removeEventListener("abort", onAbort);
    }
  }
}

export class MockProvider implements LLMProvider {
  private readonly responses: readonly ModelResponse[];
  private readonly handler: MockHandler | undefined;
  private callIndex: number;
  readonly recordedCalls: RecordedCall[];

  constructor(options: { responses?: readonly ModelResponse[]; handler?: MockHandler }) {
    if (!options.responses && !options.handler) {
      throw new Error("MockProvider requires either scripted responses or a handler");
    }
    this.responses = options.responses ?? [];
    this.handler = options.handler;
    this.callIndex = 0;
    this.recordedCalls = [];
  }

  async complete(
    messages: readonly Message[],
    tools: readonly ToolSchema[],
    profile: HarnessProfile,
    options?: CompleteOptions,
  ): Promise<ModelResponse> {
    if (options?.signal?.aborted) {
      throw options.signal.reason instanceof Error
        ? options.signal.reason
        : new Error("Provider request aborted");
    }

    const idx = this.callIndex;
    this.callIndex += 1;
    this.recordedCalls.push({
      callIndex: idx,
      messages: structuredClone(messages) as Message[],
      profile: profile.name,
      tools: structuredClone(tools) as ToolSchema[],
    });

    if (this.handler) {
      return await raceWithAbort(
        Promise.resolve(this.handler(messages, tools, profile, idx, options)),
        options?.signal,
      );
    }

    const scripted = this.responses[idx];
    if (!scripted) {
      return {
        content: "MockProvider exhausted scripted responses.",
        usage: { tokens_in: 64, tokens_cached: 32, tokens_out: 12, thinking_tokens: 0, cost_usd: 0.0001 },
        stop_reason: "end_turn",
      };
    }
    return scripted;
  }
}
