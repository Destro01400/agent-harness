# Evaluation Harness Design & Statistical Rigor

> **Core Principle:** Evaluating an agent at `trials < 3` (especially `k=1`) hides catastrophic variance, while grading rigid tool sequences punishes better solutions. Build isolated multi-trial evals (`trials >= 3`) early with 20–50 real failure tasks, verify every task with a `--gold` reference solution, and report exact unbiased `pass@k`, `pass^k`, Wilson 95% confidence intervals, and clustered standard errors.

## Table of Contents

1. [Canonical Evaluation Object Model](#1-canonical-evaluation-object-model)
2. [Capability vs. Regression Suites & Graduation Workflow](#2-capability-vs-regression-suites--graduation-workflow)
3. [Zero-to-One Roadmap: 20–50 Real-Failure Tasks](#3-zero-to-one-roadmap-2050-real-failure-tasks)
4. [`--gold` Reference Solutions & the `0% pass@100` Diagnostic](#4---gold-reference-solutions--the-0-pass100-diagnostic)
5. [Balanced Positive & Negative Trigger Sets](#5-balanced-positive--negative-trigger-sets)
6. [Strict Per-Trial Isolation & Contamination Defenses](#6-strict-per-trial-isolation--contamination-defenses)
7. [Exact Statistical Math: `pass@k`, `pass^k`, Wilson CI & Clustered Stderr](#7-exact-statistical-math-passk-passk-wilson-ci--clustered-stderr)
8. [Benchmark Isolation & Canonical Suite Patterns](#8-benchmark-isolation--canonical-suite-patterns)
9. [Alignment with `validate_trace.py` & `AH016`](#9-alignment-with-validate_tracepy--ah016)
10. [Verification Checklist](#10-verification-checklist)

---

## 1. Canonical Evaluation Object Model

Anthropic (*Demystifying Evals for AI Agents*) and UK AISI Inspect AI standardize seven cleanly separated primitives:

| Primitive | Definition | Separation Rule |
|---|---|---|
| **Task** | Input prompt + isolated fixture + objective success criteria | Every grader-checked path, format, or constraint must be stated unambiguously in the prompt. |
| **Trial (Epoch)** | One independent stochastic execution of a Task | Run $n \ge 3$ trials per task (`k=1` fails static audit `AH016`). |
| **Transcript (Trajectory)** | Full serialized messages, reasoning blocks, tool calls, tool results, timings, and usage | Persisted to append-only JSONL so scoring can be re-run offline without re-paying inference. |
| **Outcome** | Final mutated environment state (DB rows, files, passing test suite, UI state) | **Grade outcomes, not rigid trajectories**, unless policy mandates an exact sequence (e.g., `verify_identity` before `process_refund`). |
| **Grader** | Deterministic code check, hardened LLM judge, or human SME rubric | Prefer deterministic code graders first; decouple inference from re-scoring (`--no-score` / `swebench report`). |
| **Agent Harness** | Model + prompts + tools + loop + compaction evaluated as a **joint unit** | Changing harness code or model weights produces a distinct evaluation target. |
| **Eval Harness** | Infrastructure that provisions clean trials, runs the Agent Harness, grades Outcomes, and aggregates statistics | Must remain strictly isolated from the agent's execution environment. |

---

## 2. Capability vs. Regression Suites & Graduation Workflow

Never merge exploratory frontier benchmarks and CI release gates into a single undifferentiated pass rate:

| Dimension | Capability Suite | Regression Suite |
|---|---|---|
| **Purpose** | Measure frontier headroom and guide harness/model hill-climbing. | Prevent silent regressions on every PR, prompt edit, tool change, or model upgrade. |
| **Target Pass Rate** | Low to mid (e.g., 20%–70%) so there is clear signal to improve. | **~100%** (strict CI gate). |
| **Primary Metric** | `pass@k` (can the agent solve it at all?) + `pass@1`. | `pass^k` (does it solve it *every time*?) + `pass@1` lower Wilson bound + per-task `pass_pow_k` baseline gate. |
| **Failure Mode to Watch** | **Eval Saturation:** Once a suite climbs past 85%–95% (e.g., SWE-bench Verified jumping 30–40% -> >80%), it loses sensitivity to real improvements. | **Flaky tasks / broken fixtures** causing engineers to ignore red CI builds, or aggregate-only gating masking a per-task `pass_pow_k` collapse. |

**Graduation Workflow:** When a capability task climbs reliably to near-100% across consecutive runs, **graduate** it into the CI regression suite and replace its capability slot with a harder real-world failure. In CI baseline comparisons (as in `eval-suite-standalone`'s `compare_baseline`), gate on **both** aggregate metrics and per-task `pass_at_1` + `pass_pow_k` drops so a consistency collapse on one task cannot hide behind a stable suite average.

---

## 3. Zero-to-One Roadmap: 20–50 Real-Failure Tasks

Do not wait for a 1,000-task benchmark before building an eval harness. Start immediately with **20–50 realistic tasks**:

1. **Source from reality, not synthetic toy prompts:** Harvest tasks directly from manual QA checklists, bug trackers, support escalations, and production failure traces.
2. **Enforce two-expert unanimity:** Two domain engineers reading only the task prompt and grading rubric must independently agree on pass/fail without guessing hidden requirements.
3. **Avoid one-shot bias:** Include multi-turn, multi-tool tasks requiring state mutation and verification (one-shot coding evals miss real gains on long-horizon tasks).
4. **Read raw transcripts regularly:** Aggregate metrics hide grading bugs, reward hacking, and subtle loop pathology; inspect failed—and randomly sampled passing—transcripts on every major harness change.

---

## 4. `--gold` Reference Solutions & the `0% pass@100` Diagnostic

Every task in an eval suite **must** ship with a verified `--gold` reference solution (patch, tool script, or expected final state) executed through the exact same grader in CI:

- **Proof of solvability:** Running `--gold` must pass 100% of graders in a clean trial environment before the task enters the suite.
- **The `0% pass@100` Diagnostic (Anthropic):** When frontier models score `0%` across many trials on a task, assume a **broken task spec, flawed grader, or over-constrained scaffold** first—not an incapable model.
- **Real-world evidence:**
  - **CORE-Bench (Anthropic, Jan 2026):** Claude Opus 4.5 initially scored **42%** until transcript inspection exposed rigid string matching rejecting `"96.12"` against `"96.124991..."`, ambiguous specs, and an over-constrained scaffold. Fixing those bugs raised Opus 4.5 from **42% -> 95% (+53 pts)**.
  - **METR Time-Horizon bug:** Task prompts asked agents to optimize *to* a target score, while the grader checked `>` instead of `>=`, penalizing instruction-following models.
  - **Terminal-Bench filepath bug:** Tasks asked agents to write a script without specifying the exact filepath asserted by the grading test.

---

## 5. Balanced Positive & Negative Trigger Sets

Testing only scenarios where a tool or skill *should* activate creates **class imbalance** that rewards hyper-aggressive over-triggering:

- Include **paired negative tasks** (at least 30%–50% of trigger evals) where the agent must *abstain* from calling a tool, refuse an out-of-scope action, or answer directly without unnecessary side effects.
- Grade negative tasks on both **outcome quality** and **zero forbidden tool invocations**.

---

## 6. Strict Per-Trial Isolation & Contamination Defenses

Trials must be statistically independent and free of answer leakage:

| Contamination Vector | Real-World Failure Observed | Mandatory Harness Defense |
|---|---|---|
| **Shared workspace / leftover `.git` history** | Anthropic caught an agent gaining unfair advantage in internal evals by inspecting leftover `.git` history from prior trials. | Provision a fresh ephemeral workspace/container/VM per trial; strip future/solution commits and tags before mounting. |
| **Colliding result cache keys** | SWE-bench warns that caching results only by `(run_id, instance_id)` silently skips re-evaluation when `run_id` is reused. | Key eval caches by `(run_id, instance_id, trial_index, harness_git_sha, model_id, prompt_sha256)`. |
| **Shared CPU/RAM throttling** | Contended hosts cause correlated timeouts across concurrent trials, violating statistical independence. | Cap concurrency (`max_sandboxes`, `max_samples`) and enforce per-container `cpus` + `mem_limit`. |
| **Retry distribution shift** | Auto-retrying errored trials indefinitely selectively re-rolls hard/slow tasks, artificially inflating apparent pass rates (Inspect AI). | Bound `--incomplete-max`, log retry counts explicitly, and exclude or flag high-error suites rather than silently re-rolling. |

---

## 7. Exact Statistical Math: `pass@k`, `pass^k`, Wilson CI & Clustered Stderr

Given $n$ independent scored trials (epochs) for a task, with $c$ passing trials ($0 \le c \le n$), and target $k$:

### 7.1 `pass@k` — Capability / Discovery (Chen et al. 2021, `arXiv:2107.03374`)

Probability that **at least 1** of $k$ randomly chosen trials succeeds (monotonically increases with $k$; returns `1.0` when $n - c < k$ and `NaN` when $n < k$):

$$\text{pass@}k = 1 - \frac{\binom{n - c}{k}}{\binom{n}{k}} = 1 - \prod_{i = n - c + 1}^{n} \left(1 - \frac{k}{i}\right)$$

### 7.2 `pass^k` — Production Consistency (Yao et al. 2024 τ-bench / Inspect AI `reducer.py`)

Probability that **all $k$** trials succeed consecutively without replacement (monotonically decreases with $k$; returns `0.0` when $c < k$ and `NaN` when $n < k$):

$$\text{pass}^k = \frac{\binom{c}{k}}{\binom{n}{k}} = \prod_{j = 0}^{k - 1} \frac{c - j}{n - j}$$

**Why `k=1` is dangerous:** At $k=1$, $\text{pass@}1 = \text{pass}^1 = c/n$. For an agent with 75% per-trial accuracy, `pass@3` looks impressive ($98.4\%$), while `pass^3` collapses to $0.75^3 \approx 42.2\%$ and `pass^10` approaches $5.6\%$. In τ-bench Airline, `claude-3-5-sonnet-20241022` dropped from `pass^1 = 0.460` to `pass^4 = 0.225`.

**Ordering invariant (verified by `scripts/validate_trace.py`):**

$$0 \le \text{pass}^k \le \text{pass@}1 \le \text{pass@}k \le 1$$

### 7.3 Wilson 95% Score Confidence Interval (`ci_wilson`)

For binary pass/fail rates on 20–50 task suites—especially near 0% or 100%—normal Wald intervals ($\hat{p} \pm z\sqrt{\hat{p}(1-\hat{p})/N}$) overshoot $[0, 1]$ and collapse to zero width at $\hat{p} \in \{0, 1\}$. Always use the **Wilson Score Interval** ($z = 1.959963984540054$ for 95% CI):

$$\text{center} = \frac{\hat{p} + \frac{z^2}{2N}}{1 + \frac{z^2}{N}}, \qquad \text{half} = \frac{z \sqrt{\frac{\hat{p}(1-\hat{p})}{N} + \frac{z^2}{4N^2}}}{1 + \frac{z^2}{N}}, \qquad \text{CI}_{95} = [\text{center} - \text{half},\; \text{center} + \text{half}]$$

### 7.4 Clustered Standard Errors (`stderr(cluster=...)`)

When multiple eval tasks share the same repository, database fixture, or domain cluster $g \in \{1, \dots, G\}$—**or when pooling repeated trials ($n \ge 3$) of the same task**—trial outcomes are correlated within clusters rather than i.i.d. draws. Pooled trial-level `wilson_ci_95` alone understates uncertainty and triggers false CI celebrations; always emit `clustered_stderr` (clustered by task or fixture/repo cluster) alongside `wilson_ci_95` (as implemented in `eval-suite-standalone`). Compute cluster-robust standard error over cluster totals $T_g = \sum_{i \in g} (x_i - \bar{x})$ with finite-sample correction $\frac{G}{G - 1}$:

$$\text{SE}_{\text{cluster}} = \sqrt{\frac{G}{G - 1} \cdot \frac{1}{N^2} \sum_{g=1}^{G} T_g^2}$$

### Python 3.11+ — Exact Unbiased `pass@k`, `pass^k`, Wilson CI & Clustered Stderr

```python
from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Sequence


def pass_at_k(n: int, c: int, k: int) -> float:
    """Exact unbiased pass@k (Chen et al. 2021)."""
    if k <= 0 or n < k:
        return math.nan
    if n - c < k:
        return 1.0
    prod = 1.0
    for i in range(n - c + 1, n + 1):
        prod *= 1.0 - (k / i)
    return 1.0 - prod


def pass_pow_k(n: int, c: int, k: int) -> float:
    """Exact unbiased draw-without-replacement pass^k (tau-bench / Inspect AI)."""
    if k <= 0 or n < k:
        return math.nan
    if c < k:
        return 0.0
    return math.comb(c, k) / math.comb(n, k)


def wilson_ci_95(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score 95% confidence interval bounded strictly inside [0, 1]."""
    if total <= 0:
        return (math.nan, math.nan)
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    half = (z * math.sqrt((p * (1.0 - p)) / total + z2 / (4.0 * total * total))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def clustered_stderr(scores: Sequence[float], clusters: Sequence[str]) -> float:
    """Cluster-robust standard error for tasks sharing repos, domains, or fixtures."""
    n = len(scores)
    if n == 0 or n != len(clusters):
        return math.nan
    mean = sum(scores) / n
    by_cluster: dict[str, float] = defaultdict(float)
    for score, cluster in zip(scores, clusters, strict=True):
        by_cluster[cluster] += score - mean
    g = len(by_cluster)
    if g < 2:
        return math.nan
    sum_sq = sum(total * total for total in by_cluster.values())
    return math.sqrt((g / (g - 1)) * sum_sq / (n * n))
```

### TypeScript (strict ESM) — Exact Unbiased `pass@k`, `pass^k`, Wilson CI & Clustered Stderr

```typescript
export function passAtK(n: number, c: number, k: number): number {
  if (!Number.isInteger(n) || !Number.isInteger(c) || !Number.isInteger(k)) return Number.NaN;
  if (k <= 0 || n < k || c < 0 || c > n) return Number.NaN;
  if (n - c < k) return 1.0;
  let prod = 1.0;
  for (let i = n - c + 1; i <= n; i += 1) {
    prod *= 1.0 - k / i;
  }
  return 1.0 - prod;
}

export function passPowK(n: number, c: number, k: number): number {
  if (!Number.isInteger(n) || !Number.isInteger(c) || !Number.isInteger(k)) return Number.NaN;
  if (k <= 0 || n < k || c < 0 || c > n) return Number.NaN;
  if (c < k) return 0.0;
  // Numerically stable product form of C(c, k) / C(n, k).
  let prod = 1.0;
  for (let j = 0; j < k; j += 1) {
    prod *= (c - j) / (n - j);
  }
  return prod;
}

export function wilsonCi95(
  successes: number,
  total: number,
  z = 1.959963984540054,
): readonly [number, number] {
  if (!Number.isFinite(successes) || !Number.isFinite(total) || total <= 0 || successes < 0 || successes > total) {
    return [Number.NaN, Number.NaN];
  }
  const p = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / total + z2 / (4 * total * total))) / denom;
  return [Math.max(0, center - half), Math.min(1, center + half)];
}

export function clusteredStderr(scores: readonly number[], clusters: readonly string[]): number {
  const n = scores.length;
  if (n === 0 || n !== clusters.length) return Number.NaN;
  const mean = scores.reduce((acc, v) => acc + v, 0) / n;
  const totals = new Map<string, number>();
  for (let i = 0; i < n; i += 1) {
    const key = clusters[i]!;
    totals.set(key, (totals.get(key) ?? 0) + (scores[i]! - mean));
  }
  const g = totals.size;
  if (g < 2) return Number.NaN;
  let sumSq = 0;
  for (const t of totals.values()) sumSq += t * t;
  return Math.sqrt((g / (g - 1)) * (sumSq / (n * n)));
}
```

---

## 8. Benchmark Isolation & Canonical Suite Patterns

### `sdk-minimal` Benchmark Isolation (DeepSeek Harness `dsh`)

Production desktop/web harnesses load dozens of UI, telemetry, and convenience plugins that add uncontrolled variance to benchmarks. Follow `dsh`'s **`sdk-minimal` benchmark profile** pattern:

- Compose a dedicated minimal profile (`dsh-sdk-minimal`) that strips UI/web plugins and exposes only the exact core loop, tool set, compaction policy, and sandbox under test.
- Dump the resolved config (`--dump-config`) alongside every eval summary so runs are 100% reproducible and ablatable.

### Canonical Benchmark Harness Architectures

| Benchmark | Environment Isolation | Outcome Grader Pattern | Key Design Lesson to Adopt |
|---|---|---|---|
| **SWE-bench** | Ephemeral per-instance Docker container; repo checked out at base commit. | Applies candidate patch, runs hidden `FAIL_TO_PASS` (fix verified) + `PASS_TO_PASS` (zero regressions) test suites. | Decouple generation from grading (`swebench report`); never reuse cache keys `(run_id, instance_id)` across config edits. |
| **τ-bench (Sierra)** | Deterministic tool APIs backed by an in-memory/clean mock database per trial + LLM user simulator. | Compares final canonical **DB state hash** against ground-truth outcome + policy compliance checks; reports **`pass^k`**. | Pair deterministic DB-state grading with post-hoc **fault attribution** (`user` \| `agent` \| `environment` and fault class). |
| **OSWorld** | Full isolated VM snapshot (KVM/VMware/Docker+VM) reset before every trial. | Deterministic post-run Python evaluators inspect real filesystem, app config, browser/SQLite state, or OS artifacts. | Never grade GUI agents by click coordinates; verify final OS/file/app state. |

---

## 9. Alignment with `validate_trace.py` & `AH016`

Integrate static auditing (`audit_harness.py`) and eval artifact validation (`validate_trace.py`) into CI:

```bash
# 1. Catch missing eval suites or hardcoded trials=1 (AH016)
python -B scripts/audit_harness.py ./my-agent --strict

# 2. Validate JSONL or JSON-array eval dataset (unique non-empty id, input/prompt, expected/graders)
python -B scripts/validate_trace.py ./evals/tasks.jsonl --mode dataset --strict

# 3. Validate eval summary JSON (trials_per_task >= 3, finite pass^k <= pass@1 <= pass@k, gold_verified on 0%-pass tasks)
python -B scripts/validate_trace.py ./evals/eval_summary.json --mode eval_summary --strict
```

### Minimal Valid `eval_summary.json` Schema

```json
{
  "run_id": "2026-11-23-harness-v4",
  "profile": "sdk-minimal",
  "trials_per_task": 5,
  "k": 3,
  "pass_at_1": 0.84,
  "pass_at_k": 0.96,
  "pass_pow_k": 0.62,
  "wilson_ci_95": [0.71, 0.92],
  "clustered_stderr": 0.048,
  "tasks": [
    {
      "id": "fix-cache-prefix-01",
      "cluster": "runtime-core",
      "trials": 5,
      "passed": 5,
      "pass_at_1": 1.0,
      "pass_at_k": 1.0,
      "pass_pow_k": 1.0,
      "gold_verified": true
    }
  ]
}
```

When comparing a candidate run against a saved `baseline.json` (as in `assets/templates/eval-suite-standalone`), enforce regression thresholds on **both** suite aggregates (`pass_at_1`, `pass_pow_k`) and **per-task `pass_at_1` and `pass_pow_k`** so consistency drops on individual tasks fail CI loudly.

---

## 10. Verification Checklist

- [ ] **Object model separation:** Inference transcripts are persisted independently from grading so scores can be recomputed offline.
- [ ] **Split suites:** Capability evals (headroom, monitored for saturation) and CI regression evals (~100% gate) are tracked separately with an explicit graduation workflow and per-task `pass_at_1` + `pass_pow_k` baseline gating.
- [ ] **Real-failure seed:** Suite starts with 20–50 unambiguous real-world tasks verified by two experts.
- [ ] **`--gold` verified:** Every task has a passing reference solution run in CI; any `0% pass@100` task triggers immediate spec/grader audit.
- [ ] **Balanced triggers:** Positive and negative trigger cases are balanced to catch over-triggering.
- [ ] **Strict per-trial isolation:** Fresh container/VM/workspace per trial, stripped future `.git` history, full cache keys `(run_id, instance_id, trial, sha, model)`, and bounded concurrency.
- [ ] **Statistical rigor (`AH016`):** Multi-trial (`trials >= 3`) runs report finite, exact unbiased `pass@k`, `pass^k`, `wilson_ci_95`, and `clustered_stderr` alongside per-task metrics, passing `validate_trace.py --mode eval_summary --strict`.
- [ ] **Benchmark profile isolation:** Core harness benchmarks execute under a stripped `sdk-minimal` profile with full resolved config dumped.
