# Coding Agent Harness Patterns & Outer-Harness Engineering

Software engineering agents sit inside an executable, richly verifiable environment—meaning **outer-harness engineering** (ergonomic edit/view/search ACI, repository legibility, git worktree isolation, live bootable runtimes, architectural linters, and continuous garbage collection) routinely delivers larger gains than prompt tuning alone.

## Table of Contents

1. [High-Leverage Coding ACI (Edit, View, Search & Stateless Bash)](#1-high-leverage-coding-aci-edit-view-search--stateless-bash)
2. [Repository Legibility: `AGENTS.md` Map & Indexed `docs/`](#2-repository-legibility-agentsmd-map--indexed-docs)
3. [Git Worktree Isolation & Ephemeral Bootable Runtimes](#3-git-worktree-isolation--ephemeral-bootable-runtimes)
4. [Mechanical Invariants: Custom Layer Linters with Remediation Errors](#4-mechanical-invariants-custom-layer-linters-with-remediation-errors)
5. [Background Garbage Collection & Doc-Gardening Agents](#5-background-garbage-collection--doc-gardening-agents)
6. [Implementation Patterns (Python & TypeScript)](#6-implementation-patterns-python--typescript)
7. [Coding Harness Delivery Checklist](#7-coding-harness-delivery-checklist)

---

## 1. High-Leverage Coding ACI (Edit, View, Search & Stateless Bash)

Three empirical benchmarks define the coding ACI frontier—holding model weights completely fixed:

### A. Anchored Editing: Hashline (`line:hash|`) vs. `apply_patch` vs. `str_replace`
Can Bölük / Stencil (Feb 2026) benchmarked **16 LLMs** (180 React edit tasks × 3 runs) changing **only the edit tool**:
- `str_replace` fails constantly on exact whitespace/indentation reproduction.
- Raw `apply_patch` produced **46.2%–50.7% patch failure rates** on models not post-trained on OpenAI diffs (`GLM-4.7`, `Grok 4 Fast`).
- **Hashline** tags every line returned by `read`/`grep` with a short 2–3 hex character content hash (e.g., via `blake2` or `sha256`: `42:f1|  return value;`). To edit, the model cites only anchor tags (`replace(start="42:f1", end="45:a9", new_lines=...)`) without reproducing existing text. If the file shifted since reading, the hash check **optimistically rejects stale edits** before corrupting code.
- **Measured impact:** **+15 pts average** over `patch` across 16 models (`14/16` improved; `Grok Code Fast 1` **6.7% → 68.3% / 10×, −49% tokens**; `Grok 4 Fast` **+17.4 pts, −61% output tokens**; `Claude Sonnet 4.5` **+14.4 pts, −24% tokens**).
- **Model-coupling caveat:** `DeepSeek V3.2` dropped **−5 pts vs `patch` / −8.3 pts vs `str_replace`**—proving edit-tool format MUST live in a declarative per-model **`HarnessProfile`** (LangChain τ²-bench lifted `GPT-5.3 Codex` **+20 pts** by swapping `edit_file → apply_patch` + `execute → shell_command`).

### B. SWE-agent ACI Ablations (`arXiv:2405.15793`)
Replacing raw Linux shell with a custom ACI on `GPT-4 Turbo` lifted SWE-bench Lite from **11.0% → 18.0% (+7.0 pts)**—and component ablations revealed exact design rules:
- **100-line windowed file viewer (`18.0%`):** Peaked at 100 lines. Shrinking to 30 lines dropped to **14.3% (−3.7)** (too fragmented); dumping full files dropped to **12.7% (−5.3)** (context dilution).
- **Lint-gated range edit (`edit <start>:<end>`):** Runs fast syntax/lint check (`ast.parse`/`flake8`/`tsc`) *before committing*; if syntax fails, **reverts the edit immediately** and returns the exact lint error + context. Removing the linter dropped **−3.0 pts** (cascading edit errors caused 23.4% of all unresolved runs).
- **Summarized search capped at $\le 50$ hits (`18.0%`):** IDE-style iterative `next`/`prev` search scored **12.0% (−6.0)**—**worse than having no search tool at all (15.7%)**—because agents exhaustively stepped through matches and blew their step budget. Return counts per file and steer the agent to narrow queries over 50 hits.
- **Explicit empty-output message:** Never return `""` when a command succeeds silently; return `"Command succeeded with no output (exit code 0)"` so the model does not assume a hang.
- **Mandatory absolute paths:** Anthropic's SWE-bench experience showed requiring absolute filepaths eliminated navigation errors after working-directory changes.

### C. The Minimalist Pole: `mini-swe-agent` Stateless Bash
When targeting modern frontier models (>74% SWE-bench Verified), Princeton/Stanford's `mini-swe-agent` proved a **~100 LOC Python loop** executing **stateless per-command `subprocess.run` / `docker exec`** (no persistent interactive PTY/shell session to hang or leak `cd`/env state!) with linear message history is a strong baseline. Start minimal and add ACI abstractions only when evals show concrete mechanical failures.

---

## 2. Repository Legibility: `AGENTS.md` Map & Indexed `docs/`

OpenAI's *Harness Engineering* (Feb 2026 — shipping **~1M LOC** and **~1,500 merged PRs** across 5 months with 3→7 engineers at **3.5 PRs/engineer/day**) and Vercel's `d0` study (Dec 2025) converged on a fundamental law: **simple harnesses only succeed over legible environments.**

Why monolithic `AGENTS.md` / `CLAUDE.md` manuals fail:
1. Context is a finite attention budget—stuffing 1,000 lines of prose into Turn 0 triggers Context Rot.
2. When everything is marked `CRITICAL`, nothing has priority.
3. Monolithic manuals rot immediately and cannot be mechanically verified in CI.

**The Map-Not-Encyclopedia Architecture (OpenAI Pattern):**
- Keep root `AGENTS.md` to **~100 lines**: a crisp table of contents pointing into versioned, indexed `docs/`:
  ```text
  AGENTS.md                 # ~100-line map: build/test commands, invariants, doc pointers
  docs/
  ├── ARCHITECTURE.md       # Domain map + strict layer dependency graph
  ├── DESIGN.md             # Core design decisions & boundary contracts
  ├── exec-plans/           # Active & completed execution plans (durable off-context specs)
  ├── quality/              # Per-domain quality grades & known tech-debt tracker
  └── runbooks/             # Local boot, debugging, and observability queries
  ```
- **Progressive disclosure:** Agents read `AGENTS.md` on boot, then open only the `docs/*.md` files relevant to their active slice.
- **Startup onboarding hook (`LocalContext`):** Inject a concise, bounded workspace snapshot (git status, top-level directory tree, available runtimes/test runners) once at session start so the agent stops wasting 3–5 exploratory turns discovering Python/Node versions.

---

## 3. Git Worktree Isolation & Ephemeral Bootable Runtimes

Give every coding agent task an isolated **workspace** and **live runtime observability** so it verifies real end-to-end behavior instead of trusting unit mocks or self-report:

1. **Per-Task `git worktree` Isolation:**
   ```bash
   git worktree add -b agent/fix-auth ../worktrees/fix-auth origin/main
   # Clean up after merge/abort:
   git worktree remove --force ../worktrees/fix-auth
   ```
   Prevents concurrent agents from stomping on each other's working trees, `.git/index`, or build caches, and makes rollback an instant branch discard.
2. **Ephemeral Per-Worktree Bootable App (`init.sh`):**
   Every worktree must boot cleanly on isolated dynamic ports (`PORT=0` / worktree-derived offset) with an ephemeral local database and `init.sh` smoke-check script. Anthropic's long-running harness runs `init.sh` at the **start** of every session to detect inherited breakage before adding new changes.
3. **Live Browser & Telemetry Sensors (CDP / Playwright + LogQL / PromQL):**
   - **Browser verification:** Wire Chrome DevTools Protocol (CDP) or Playwright MCP so the agent clicks real UI flows, inspects console errors, checks DOM state, and captures screenshots. Anthropic proved unit tests + `curl` routinely missed broken web UIs and native alert modals.
   - **Ephemeral observability stack:** OpenAI wired each worktree with an ephemeral local **LogQL / PromQL** stack so agents directly query logs, metrics, and trace latencies—making non-functional requirements (`"startup < 800ms"`, `"zero HTTP 500 spans"`) mechanically verifiable.
4. **Long-Horizon Shift-Work State:** For multi-window builds, pair a structured **JSON** checklist (`feature_list.json`—models corrupt/falsely check off Markdown far more often than JSON), a short `progress.md`, and **atomic per-feature git commits**.

---

## 4. Mechanical Invariants: Custom Layer Linters with Remediation Errors

> *"When documentation falls short, we promote the rule into code. Enforce boundaries centrally, allow autonomy locally."* — OpenAI *Harness Engineering* (2026)

Instead of writing prose rules hoping the model obeys architectural boundaries, enforce strict unidirectional domain layering via fast mechanical linters and structural tests:

```text
Types → Config → Repo → Service → Runtime → UI
                       ↑
                   Providers (explicit cross-cutting entry only)
```

**The Secret Weapon — Remediation-Injecting Error Messages:**
Write custom linter errors as **direct instructions to the coding agent** naming the violated invariant, exact file/line, and the exact fix pattern:

```text
ARCH001 [src/repo/orders.py:14]: Layer violation — 'repo' imported 'service.billing'.
Allowed imports for 'repo': ['types', 'config', 'providers'].
Remediation: Move shared DTOs to 'src/types/' or invert control by passing a callback/protocol from 'service'.
```

Every lint failure becomes **executable attention** that guides self-correction on the very next turn without human review.

---

## 5. Background Garbage Collection & Doc-Gardening Agents

High-throughput coding agents replicate whatever patterns already exist in a codebase—if minor drift accumulates, agents amplify it exponentially. OpenAI previously lost **20% of every engineering week (all of Friday)** manually cleaning AI slop until replacing manual cleanup with **continuous background GC agents**:

1. **Encode Golden Principles once** (small, verifiable rules: boundary validation at edges, no hand-rolled duplicate helpers, strict layering, doc-link validity).
2. **Schedule recurring lightweight cleanup agents:**
   - **Doc-gardening agent:** Verifies every file path, CLI flag, and symbol referenced in `AGENTS.md` and `docs/` still exists in code; opens tiny PRs fixing drift.
   - **Entropy / refactoring agent:** Scans for duplicated utilities, dead modules, or quality-grade regressions and opens focused PRs **reviewable in <1 minute**.
3. **Agent-to-agent PR review loops:** Before human review, run an automated reviewer agent against diff + CI + architectural tests until zero mechanical findings remain.

---

## 6. Implementation Patterns (Python & TypeScript)

### Python Pattern: Hashline Reader & Syntax-Gated Atomic Editor

```python
import ast
import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


def _line_hash(line: str) -> str:
    """Short 2-3 hex char content hash (blake2/sha256); keep algorithm & width identical across read/edit."""
    return hashlib.blake2s(line.encode("utf-8"), digest_size=2).hexdigest()[:2]


def read_hashline_window(path: Path, *, start_line: int = 1, window: int = 100) -> str:
    """100-line SWE-agent window tagged with Hashline anchors (line:hash|content)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    total = len(lines)
    start = max(1, min(start_line, max(1, total)))
    end = min(total, start + window - 1)
    rendered = [f"{i}:{_line_hash(lines[i - 1])}|{lines[i - 1]}" for i in range(start, end + 1)]
    header = f"# {path.name} (lines {start}-{end} of {total})"
    return "\n".join([header, *rendered])


@dataclass(frozen=True)
class EditOutcome:
    ok: bool
    message: str


def _atomic_write_text(path: Path, content: str) -> None:
    """Write via same-directory temp file + fsync + os.replace() (cross-platform, crash-safe)."""
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def apply_hashline_edit(
    path: Path,
    *,
    start_anchor: str,
    end_anchor: str,
    replacement_lines: list[str],
) -> EditOutcome:
    """Optimistically verifies line hashes, syntax-checks Python via ast.parse, and writes atomically."""
    original = path.read_text(encoding="utf-8").splitlines()
    s_num_str, s_hash = start_anchor.split(":", 1)
    e_num_str, e_hash = end_anchor.split(":", 1)
    s_idx, e_idx = int(s_num_str) - 1, int(e_num_str) - 1

    if not (0 <= s_idx <= e_idx < len(original)):
        return EditOutcome(False, f"Invalid line range {start_anchor}..{end_anchor} (file has {len(original)} lines).")
    if _line_hash(original[s_idx]) != s_hash or _line_hash(original[e_idx]) != e_hash:
        return EditOutcome(False, "Stale line hash detected. Re-read the target window before editing.")

    updated = [*original[:s_idx], *replacement_lines, *original[e_idx + 1 :]]
    candidate_text = "\n".join(updated) + "\n"

    if path.suffix == ".py":
        try:
            ast.parse(candidate_text, filename=str(path))
        except SyntaxError as exc:
            return EditOutcome(
                False,
                f"Edit reverted — syntax error on line {exc.lineno}: {exc.msg}\nFix syntax and retry.",
            )

    _atomic_write_text(path, candidate_text)
    return EditOutcome(True, read_hashline_window(path, start_line=max(1, s_idx - 5), window=40))
```

### TypeScript Pattern: Custom Layer Linter with Remediation Message

```ts
export interface LayerRule {
  readonly layer: string;
  readonly allowedImports: readonly string[];
}

export interface LintFinding {
  readonly code: "ARCH001";
  readonly file: string;
  readonly line: number;
  readonly message: string;
}

const LAYER_RULES: readonly LayerRule[] = [
  { layer: "types", allowedImports: ["types"] },
  { layer: "config", allowedImports: ["types", "config"] },
  { layer: "repo", allowedImports: ["types", "config", "providers", "repo"] },
  { layer: "service", allowedImports: ["types", "config", "providers", "repo", "service"] },
  { layer: "runtime", allowedImports: ["types", "config", "providers", "service", "runtime"] },
];

const IMPORT_RE = /^\s*import\s+.*?\s+from\s+["']\.\.?\/([a-z-]+)\//;

export function lintLayerBoundaries(filePath: string, source: string): LintFinding[] {
  const match = filePath.replaceAll("\\", "/").match(/src\/([a-z-]+)\//);
  const currentLayer = match?.[1];
  const rule = LAYER_RULES.find((r) => r.layer === currentLayer);
  if (!rule) return [];

  const findings: LintFinding[] = [];
  source.split(/\r?\n/).forEach((text, idx) => {
    const imp = text.match(IMPORT_RE);
    const targetLayer = imp?.[1];
    if (targetLayer && !rule.allowedImports.includes(targetLayer)) {
      findings.push({
        code: "ARCH001",
        file: filePath,
        line: idx + 1,
        message:
          `Layer '${rule.layer}' cannot import '${targetLayer}'. ` +
          `Allowed: [${rule.allowedImports.join(", ")}]. ` +
          `Remediation: Move shared contracts into 'src/types/' or inject via 'src/providers/'.`,
      });
    }
  });
  return findings;
}
```

---

## 7. Coding Harness Delivery Checklist

- [ ] **Ergonomic, profile-driven ACI:** 100-line file viewer, anchored edits (Hashline or lint-gated range edit / `apply_patch` per model profile), summarized search ($\le 50$ hits), absolute paths, and explicit empty-output messages.
- [ ] **Legible repo map:** Root `AGENTS.md` stays concise (~100 lines) linking into indexed, CI-checked `docs/`.
- [ ] **Isolated worktrees & bootable smoke tests:** Each agent task runs in an isolated `git worktree` with `init.sh` smoke verification and live E2E/browser/telemetry sensors where applicable.
- [ ] **Mechanical layer & style invariants:** Architectural boundaries are enforced by linters whose error messages include concrete remediation steps.
- [ ] **Continuous entropy control:** Automated doc-gardening and small-PR cleanup loops prevent accumulated AI drift.
