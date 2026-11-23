# Production Deployment, Scaling, Migrations & Rollback

Taking an agent harness from a single-developer CLI to a multi-tenant production service requires decoupling **Brain**, **Session**, and **Hands** so each scales and fails independently, enforcing tenant quotas and retry budgets, composing environments via declarative profiles, migrating durable sessions safely across schema versions, and gating rollouts with shadow/canary replay and emergency kill switches.

## Table of Contents

1. [Decoupled Scaling: Brain, Session & Hands](#1-decoupled-scaling-brain-session--hands)
2. [Async Queues, Workers & Per-Tenant Governance](#2-async-queues-workers--per-tenant-governance)
3. [Declarative Layered Profiles (`dsh` Bundle + Patch Model)](#3-declarative-layered-profiles-dsh-bundle--patch-model)
4. [Immutable Versioned Session Migrations (`v0 → vN`)](#4-immutable-versioned-session-migrations-v0--vn)
5. [Canary/Shadow Evals & Digital-Twin Trace Replay](#5-canaryshadow-evals--digital-twin-trace-replay)
6. [Supply-Chain Kill Switches & Safe Rollback](#6-supply-chain-kill-switches--safe-rollback)
7. [Implementation Patterns (Python & TypeScript)](#7-implementation-patterns-python--typescript)
8. [Production Readiness Checklist](#8-production-readiness-checklist)

---

## 1. Decoupled Scaling: Brain, Session & Hands

Coupling the LLM orchestration loop inside the same mutable container as tool execution creates three severe production failures: slow cold starts on every chat turn, lost conversation state on container OOM/crash, and credentials co-located with agent-generated code.

Production harnesses (Anthropic *Managed Agents*, DeepSeek Harness `dsh`, OpenHands, Google ADK) split into three independently scalable planes:

| Plane | Responsibility | Scaling & Failure Model | Interface Contract |
|---|---|---|---|
| **Brain (Harness Loop)** | Stateless turn orchestration, prompt assembly, streaming, compaction, policy checks | Horizontal stateless workers (`wake(sessionId)`); survives restarts with zero lost state | Reads/writes Session log; calls LLM API + Hands |
| **Session (Append-Only Event Log)** | Canonical source of truth (`session.vN.jsonl` / Postgres / SQLite / Object Store) outside context window & container | Durable, replicated storage; pure `deriveMessages()` projections decouple storage from compaction | `appendEvent(sessionId, event)`, `getEvents(sessionId, fromSeq)` |
| **Hands (Isolated Execution Sandbox)** | Ephemeral containers, microVMs (Firecracker/gVisor), or OS sandboxes (`bwrap`/Seatbelt/Windows ACL) | Cattle pools, warm-pool autoscaling, **lazy provisioning**; zero raw credentials inside sandbox | Uniform seam: `execute(name, input) → string` (`ctx.fs` + `ctx.subprocess`) |

### Lazy Sandbox Provisioning (Measured Impact)
Anthropic *Managed Agents* (Apr 2026) stopped provisioning a container before Turn 1 and instead provisioned sandboxes **lazily on first tool call requiring execution**:
- **p50 Time-To-First-Token (TTFT) dropped ~60%.**
- **p95 TTFT dropped >90%.**
- Read-only turns, clarifications, and pure reasoning queries incur zero container startup cost.

---

## 2. Async Queues, Workers & Per-Tenant Governance

Agent runs last seconds to hours and exhibit bursty tool/LLM fan-out. Never tie multi-minute agent loops directly to synchronous HTTP request threads.

### Execution Topology
- **Ingress API (Fast):** Authenticates tenant, validates request spec (explicit `resolve(request) -> Spec`, no silent `?? default` fallbacks), enqueues durable job with `idempotency_key`, returns `session_id` + SSE/WebSocket cursor (`gen_ai.request.stream_cursor`).
- **Durable Worker Queue:** Claims jobs with visibility timeouts and heartbeats; separates **transient streaming frames** (published to pub/sub for live UI) from **settled durable commits** (written to Session store).
- **Orphan & Cleanup Sweeper:** Background reaper destroys expired/abandoned sandboxes and containers (`init: true`, hard TTL) even if a worker crashes (`SIGKILL`/OOM).

### Per-Tenant Quotas & Token-Bucket Retry Budgets
1. **Orthogonal Tenant Quotas:** Enforce per-tenant limits on concurrent active sessions, concurrent sandboxes (`max_sandboxes`), daily/hourly token & USD spend ceilings, and subagent fan-out caps (`ASI08`).
2. **Single-Layer Token-Bucket Retry Budget (AWS Builders' Library):** Rather than blind per-request retries (which amplify outages by $r^d$, e.g. $3^5 = 243\times$ across 5 layers), enforce a **shared per-provider / per-tenant token-bucket retry budget** (e.g., retries may consume at most 10% of normal traffic capacity). When the bucket empties, fail fast with a clear retryable status instead of melting downstream providers.
3. **Zero-Credential Vault Proxy:** Keep git tokens, cloud IAM roles, and MCP OAuth secrets in a host/cluster vault behind a session-scoped validating proxy. Issue only short-lived, scope-bound session tokens to the harness.

---

## 3. Declarative Layered Profiles (`dsh` Bundle + Patch Model)

Hardcoding `if env == "prod"` or `if "codex" in model:` across runtime code makes deployments impossible to audit or roll back cleanly. Adopt DeepSeek Harness's (`dsh`) **declarative layered profile** architecture:

```text
Base Bundle (dsh-base: core loop, session log, spill, timeouts, sandbox)
  + Environment Profile (web | headless | sdk | sdk-minimal | ci-eval)
    + Model Profile (prompt prefix/suffix, edit tool variant, reasoning effort schedule)
      + Tenant / Deployment Patch Overlay (cordis.patch.yml / --patch)
        = Resolved Immutable Spec (--dump-config prints exact effective tree)
```

Key operational properties:
- **Reproducible minimal benchmark profile (`sdk-minimal`):** Strip UI/product plugins cleanly to evaluate core loop regressions without noise.
- **Explicit `--dump-config` / resolved spec logging:** Record the exact SHA-256 hash of the resolved profile spec in every session's `turn/start` event so any production trace can be reproduced byte-for-byte.
- **No silent runtime defaults:** Fail loud at `resolve(request) -> Spec` if a required budget, sandbox mode, or provider rate is missing.

---

## 4. Immutable Versioned Session Migrations (`v0 → vN`)

Agent sessions live for days or weeks—across multiple harness deployments. Mutating existing session files in place risks permanent data corruption and breaks mid-flight replay.

Follow DeepSeek Harness's **immutable versioned generation** contract:
1. Name durable log files with explicit schema versions: `session.v0.jsonl`, `session.v1.jsonl`, `session.v2.jsonl[.zstd]`.
2. **Never overwrite, rename, or delete a committed generation** during migration.
3. Write **small, pure, adjacent migrations** (`v0 → v1`, `v1 → v2`, `v2 → v3`) that compose monotonically (`v0 → v3` runs `v0→v1→v2→v3`).
4. **Verify before atomic publication:** Stream migrated events to a temporary file, validate schema + invariants (no orphan tool calls, valid monotonic timestamps), `fsync`, and atomically publish `session.vN.jsonl` (`O_EXCL` / atomic rename). On any failure, delete the temp file—the prior committed generation remains 100% intact.

---

## 5. Canary/Shadow Evals & Digital-Twin Trace Replay

Never roll out a new model checkpoint, prompt edit, tool description, compaction algorithm, or loosened security policy straight to 100% production traffic.

### Four-Stage Progressive Rollout Gate
1. **Offline CI Regression + Keyless Snapshot Replay:** Run the CI regression suite (`pass^k` + Wilson CI) and replay recorded golden session snapshots through the new harness profile without live LLM API keys (DeepSeek Harness pattern) to verify exact request framing, cache-prefix stability, and tool ordering.
2. **Digital-Twin Trace Replay (`ASI08` Control):** Before expanding tool permissions or loosening an approval/sandbox policy, replay historical production traces against the proposed policy in a dry-run **digital twin** to measure newly permitted actions, blast radius, and blocked legitimate workflows.
3. **Shadow Execution (Dark Launch):** Fork a sampled percentage of live read-only inputs to the candidate profile asynchronously; compare latency, token/cost ratio, KV-cache hit rate, and automated grader scores with zero user impact.
4. **Canary Rollout with Automated Rollback Triggers:** Shift `1% → 10% → 50% → 100%` of traffic while monitoring live OTel GenAI metrics:
   - `gen_ai.invoke_agent.duration` & `gen_ai.server.time_to_first_token`
   - `gen_ai.usage.cache_read.input_tokens / gen_ai.usage.input_tokens` (instant alert if KV-cache hit rate collapses!)
   - `gen_ai.invoke_agent.tool_calls` & `error.type` rate
   - `gen_ai.evaluation.result` pass rate & consecutive-rejection circuit-breaker trips

---

## 6. Supply-Chain Kill Switches & Safe Rollback

OWASP Agentic Top 10 (`ASI04`, `ASI10`) mandates **immediate global containment** when a third-party MCP server, tool plugin, skill, or model version misbehaves or suffers a supply-chain compromise:

- **Global Tool / MCP Kill Switch:** Maintain a low-latency, out-of-band feature-flag / denylist read at the host PEP/PDP *before* every `tools/pre-execute` hook—not cached solely at container boot. Flipping a tool or MCP server to `disabled` immediately blocks in-flight sessions on their very next step and returns an actionable error to the model.
- **Per-Session & Global Credential Revocation:** Because real credentials live in the out-of-sandbox vault proxy, revoking a compromised session's short-lived token instantly severs all git/API/MCP access without waiting for container teardown.
- **Deterministic Profile Rollback:** Rolling back a bad harness release is reverting the declarative profile bundle version (immutable artifact digest) while preserving forward/backward compatibility of the append-only Session log.

---

## 7. Implementation Patterns (Python & TypeScript)

### Python Pattern: Immutable Adjacent Session Migrator (`v0 → vN`) & Token-Bucket Retry Budget

```python
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MigratorFn = Callable[[dict], dict]


class ImmutableSessionMigrator:
    """Composes adjacent vN -> vN+1 migrations without mutating committed generations."""

    def __init__(self, migrations: dict[int, MigratorFn]) -> None:
        self._migrations = dict(migrations)

    def migrate_file(self, session_dir: Path, *, from_ver: int, to_ver: int) -> Path:
        if to_ver <= from_ver:
            raise ValueError(f"Target version {to_ver} must exceed source version {from_ver}.")
        src = session_dir / f"session.v{from_ver}.jsonl"
        dst = session_dir / f"session.v{to_ver}.jsonl"
        if dst.exists():
            return dst  # Idempotent: already migrated

        steps = [self._migrations[v] for v in range(from_ver, to_ver)]
        fd, tmp_name = tempfile.mkstemp(dir=session_dir, prefix=f".session.v{to_ver}.", suffix=".tmp")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out, src.open("r", encoding="utf-8") as inp:
                for line_no, raw in enumerate(inp, start=1):
                    if not raw.strip():
                        continue
                    event = json.loads(raw)
                    for step_fn in steps:
                        event = step_fn(event)
                    if "event_type" not in event or "timestamp" not in event:
                        raise ValueError(f"Migrated event at line {line_no} failed invariant check.")
                    out.write(json.dumps(event, sort_keys=True) + "\n")
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp_path, dst)  # Atomic publication; src untouched
            return dst
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise


@dataclass
class RetryBudget:
    """Token-bucket retry budget (AWS pattern) preventing retry-storm amplification."""

    capacity: float = 20.0
    refill_per_success: float = 0.1  # Max ~10% retry ratio
    retry_cost: float = 1.0
    tokens: float = 20.0
    last_checked: float = 0.0

    def record_success(self) -> None:
        self.tokens = min(self.capacity, self.tokens + self.refill_per_success)

    def try_consume_retry(self) -> bool:
        self.last_checked = time.monotonic()
        if self.tokens < self.retry_cost:
            return False
        self.tokens -= self.retry_cost
        return True
```

### TypeScript Pattern: Lazy Sandbox Provisioner + Out-of-Band Tool Kill Switch

```ts
export interface SandboxHandle {
  readonly id: string;
  exec(toolName: string, input: Record<string, unknown>, signal: AbortSignal): Promise<string>;
  dispose(): Promise<void>;
}

export interface KillSwitchStore {
  isToolDisabled(qualifiedToolName: string, tenantId: string): boolean;
}

export class LazyHandsDispatcher {
  private sandbox: SandboxHandle | null = null;
  private provisioning: Promise<SandboxHandle> | null = null;
  private disposed = false;
  private readonly provisionSandbox: () => Promise<SandboxHandle>;
  private readonly killSwitch: KillSwitchStore;

  constructor(provisionSandbox: () => Promise<SandboxHandle>, killSwitch: KillSwitchStore) {
    this.provisionSandbox = provisionSandbox;
    this.killSwitch = killSwitch;
  }

  private async ensureSandbox(): Promise<SandboxHandle> {
    if (this.disposed) {
      throw new Error("LazyHandsDispatcher has been disposed.");
    }
    if (this.sandbox) return this.sandbox;
    if (!this.provisioning) {
      const pending: Promise<SandboxHandle> = this.provisionSandbox()
        .then(async (handle) => {
          if (this.disposed) {
            await handle.dispose();
            throw new Error("LazyHandsDispatcher was disposed during sandbox provisioning.");
          }
          this.sandbox = handle;
          return handle;
        })
        .finally(() => {
          if (this.provisioning === pending) {
            this.provisioning = null;
          }
        });
      this.provisioning = pending;
    }
    return this.provisioning;
  }

  public async execute(
    tenantId: string,
    toolName: string,
    input: Record<string, unknown>,
    timeoutMs: number,
  ): Promise<string> {
    // Check kill switch deterministically BEFORE provisioning or executing (ASI04/ASI10)
    if (this.killSwitch.isToolDisabled(toolName, tenantId)) {
      return JSON.stringify({
        ok: false,
        error: `Tool '${toolName}' is disabled by security policy. Choose an approved alternative or escalate.`,
      });
    }
    const handle = await this.ensureSandbox(); // Lazy provisioning on first real tool call
    const signal = AbortSignal.timeout(timeoutMs);
    return handle.exec(toolName, input, signal);
  }

  public async cleanup(): Promise<void> {
    this.disposed = true;
    const pending = this.provisioning;
    const handle = this.sandbox;
    this.sandbox = null;
    this.provisioning = null;
    if (pending) {
      await pending.catch(() => undefined);
    }
    if (handle) {
      await handle.dispose();
    }
  }
}
```

---

## 8. Production Readiness Checklist

- [ ] **Brain / Session / Hands decoupled:** Session log lives outside context and containers; stateless workers recover via `wake(sessionId)`; sandboxes provision lazily on first execution tool call.
- [ ] **Tenant quotas & retry budgets active:** Hard per-tenant concurrency, spend, sandbox, and fan-out caps plus a single-layer token-bucket retry budget.
- [ ] **Declarative layered profiles:** Environment, model, and tenant overrides resolve into an immutable logged spec (`--dump-config`); `sdk-minimal` benchmark profile available.
- [ ] **Safe immutable session migrations:** Adjacent `vN → vN+1` migrations write-verify-publish atomically without mutating committed generations.
- [ ] **Progressive rollout verified:** Keyless snapshot replay + digital-twin policy replay + shadow/canary monitoring on cache-hit ratio, TTFT, error rate, and eval scores before 100% rollout.
- [ ] **Kill switches & revocation tested:** Out-of-band global/per-tenant tool & MCP kill switch and instant vault-proxy session token revocation verified in drills.
