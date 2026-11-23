# Agent Harness Engineering (`agent-harness`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stack: Python 3.11+ & TypeScript ESM](https://img.shields.io/badge/Stack-Python%203.11%2B%20%7C%20TypeScript%20Node%2024%2B-3776AB.svg)](#)

An agent skill for full-lifecycle **AI agent harness engineering** (`Agent = Model + Harness`) across **runtime harnesses** and **evaluation harnesses** in **Python 3.11+** and **TypeScript (Node 24+ ESM)**. Grounded in primary engineering research from Anthropic, OpenAI Codex, DeepSeek Harness (`dsh`), Princeton SWE-agent, UK AISI Inspect AI, OpenHands, Google ADK, LangChain, OWASP Agentic Top 10 (2026), and OpenTelemetry GenAI Semantic Conventions.

It ships **15 reference guides**, **3 zero-dependency starter templates** with a CLI scaffolder, a **SARIF 2.1.0 static auditor (`AH001`–`AH016`)** for GitHub Code Scanning, and a **JSONL trace & eval validator**.

*(Versão em Português abaixo / [Portuguese README](#versão-em-português-br))*

---

## What This Skill Covers

| Area | Guide |
|---|---|
| Brain/Session/Hands 3-way decoupling, `Model-visible ⟺ logged`, thin provider seam, DeepSeek `dsh` Cordis seams, Codex/Managed Agents/ADK/mini-SWE-agent | [`harness-architecture.md`](references/harness-architecture.md) |
| Empirical strong vs. weak harnesses, 6 defining properties, 6-species Boundary Matrix, Capability-Frontier Economics, Bitter Lesson ablation | [`strong-vs-weak-harnesses.md`](references/strong-vs-weak-harnesses.md) |
| Canonical turn/step loop, orthogonal budgets (`turn`, `token`, `cost`, `working_limit` + `time_limit`), doom-loop guards, exit verification, `HarnessProfile`s | [`agent-loop-and-budgets.md`](references/agent-loop-and-budgets.md) |
| Poka-yoke ACI, workflow consolidation, namespacing, `input_examples`, `response_format`, output truncation + disk spill, actionable errors, idempotency | [`tool-contracts-and-execution.md`](references/tool-contracts-and-execution.md) |
| Context Rot (4 failure modes), KV-cache prefix invariance, reasoning preservation (`reasoning_content`/`thinking`/`encrypted_content`), 5-tier compaction, `ASI06` | [`context-and-memory.md`](references/context-and-memory.md) |
| Append-only `session.vN.jsonl`, transient streaming vs. settled commits, missing tool-result repair, Initializer+Worker (`feature_list.json`), 5-decision `ApprovalPolicy` | [`state-and-checkpoints.md`](references/state-and-checkpoints.md) |
| OWASP Agentic Top 10 2026 (`ASI01`–`ASI10`), Least Agency, Lethal Trifecta, Dual-Boundary Rule (FS + egress proxy), OS/Docker sandboxing, zero-credential sandboxes | [`sandboxing-and-security.md`](references/sandboxing-and-security.md) |
| OpenTelemetry GenAI Semantic Conventions (`invoke_agent`, `plan`, `chat`, `execute_tool`), inclusive token accounting, `NO_CONTENT`, `*_ref`, keyless replay | [`observability-and-traces.md`](references/observability-and-traces.md) |
| Connect+read timeouts, capped exponential backoff + jitter, single-layer retry rule, retry budgets, keeping errors in context, cancellation, sync-I/O offloading | [`resilience-and-streaming.md`](references/resilience-and-streaming.md) |
| Task/Trial/Outcome model, Capability vs. Regression suites, `--gold` checks, per-trial isolation, unbiased `pass@k` & `pass^k`, Wilson 95% CI, `sdk-minimal` | [`eval-harness-design.md`](references/eval-harness-design.md) |
| Outcome-over-trajectory grading, code graders first, `{grader_nonce}` judge hardening, order-swapping, strict-majority panels, Krippendorff's α, τ-bench attribution | [`graders-and-regression.md`](references/graders-and-regression.md) |
| MCP token-bloat math, `defer_loading` + Tool Search Tool, Programmatic Tool Calling / Code Mode (PII tokenization), Tool Poisoning / Rug Pull / Shadowing defense | [`mcp-and-dynamic-tools.md`](references/mcp-and-dynamic-tools.md) |
| When NOT to use multi-agent (Cognition's 2 laws, UC Berkeley MAST, 15× cost), valid topologies, `as_tool` vs. `handoff`, artifact handoff, scoped limits, `ASI03`/`ASI07`/`ASI08` | [`multi-agent-orchestration.md`](references/multi-agent-orchestration.md) |
| Coding ACI (Hashline, 100-line viewer, lint-gated edit, ≤50-hit search, stateless bash), ~100-line `AGENTS.md` map, git worktrees, CDP/LogQL/PromQL, GC agents | [`coding-agent-patterns.md`](references/coding-agent-patterns.md) |
| Brain/Session/Hands independent scaling (lazy sandboxes), async queues, tenant quotas, declarative layered profiles (`dsh`), `v0→vN` migrations, digital-twin replay, kill switches | [`production-deployment.md`](references/production-deployment.md) |

### Starter Templates (`assets/templates/`)

| Template | Stack |
|---|---|
| `python-runtime-eval` | Python 3.11+ zero-deps (`asyncio`, `unittest`): `Model-visible ⟺ logged` JSONL session/trace, checkpoints, spill, `ApprovalPolicy`, budgets, deletable hooks, multi-trial `pass@k`/`pass^k` eval runner |
| `typescript-runtime-eval` | TypeScript ESM (Node 24+ native type stripping, `node --test`, zero deps): `AbortSignal` timeouts, checkpoints, spill, trace redaction, budgets, deletable hooks, multi-trial `pass@k`/`pass^k` eval runner |
| `eval-suite-standalone` | Python 3.11+ zero-deps standalone eval harness: `AgentAdapter`, deterministic outcome graders, `{grader_nonce}`-hardened judge contract, `--gold` verification, unbiased `pass@k`/`pass^k`, Wilson 95% CI, CI regression gate |

---

## Repository Structure

```text
agent-harness/
├── SKILL.md                                         # Core instructions, Zero-Step Gate, 1-hop decision tree & routing table
├── README.md                                        # Documentation (EN / PT-BR)
├── LICENSE                                          # MIT License
├── .gitignore
├── assets/
│   └── templates/
│       ├── python-runtime-eval/                     # Python 3.11+ zero-deps runtime + eval starter
│       ├── typescript-runtime-eval/                 # TypeScript Node 24+ zero-deps runtime + eval starter
│       └── eval-suite-standalone/                   # Python 3.11+ standalone multi-trial eval harness
├── references/
│   ├── harness-architecture.md                      # Brain/Session/Hands, Model-visible<=>logged, dsh/Codex/Managed Agents
│   ├── strong-vs-weak-harnesses.md                  # Empirical evidence, 6 properties, Boundary Matrix, Bitter Lesson
│   ├── agent-loop-and-budgets.md                    # Turn/step loop, orthogonal budgets, doom-loop & pre-exit hooks, profiles
│   ├── tool-contracts-and-execution.md              # Poka-yoke ACI, consolidation, input_examples, spill, idempotency
│   ├── context-and-memory.md                        # Context Rot, KV-cache invariance, reasoning preservation, compaction
│   ├── state-and-checkpoints.md                     # Durable session.vN.jsonl, atomic commits, Initializer+Worker, HITL
│   ├── sandboxing-and-security.md                   # OWASP ASI01-ASI10, Lethal Trifecta, dual OS/Docker sandbox, vault proxy
│   ├── observability-and-traces.md                  # OTel GenAI semantic conventions, NO_CONTENT, JSONL traces, replay
│   ├── resilience-and-streaming.md                  # Timeouts, jittered single-layer retries, error retention, cancellation
│   ├── eval-harness-design.md                       # Capability vs. regression, --gold, isolation, pass@k, pass^k, Wilson CI
│   ├── graders-and-regression.md                    # Outcome graders, nonce-hardened LLM judges, panels, τ-bench, Swiss Cheese
│   ├── mcp-and-dynamic-tools.md                     # MCP bloat math, defer_loading, Code Mode/PTC, Tool Poisoning/Rug Pulls
│   ├── multi-agent-orchestration.md                 # MAST/Cognition limits, valid topologies, as_tool/handoff, artifact handoff
│   ├── coding-agent-patterns.md                     # Hashline/SWE-agent ACI, AGENTS.md map, worktrees, linters, GC agents
│   └── production-deployment.md                     # Lazy sandboxes, queues, tenant quotas, dsh profiles, v0->vN, kill switches
└── scripts/
    ├── scaffold_harness.py                          # Template scaffolder (--list/--template/--name/--out/--description/--force)
    ├── audit_harness.py                             # Static auditor (AH001-AH016; --strict/--json/--sarif/--ignore-dir)
    ├── validate_trace.py                            # Trace/dataset/eval validator (--mode/--strict/--json/--max-tool-chars)
    ├── test_scaffold.py                             # Scaffolder unit tests (unittest)
    ├── test_audit_harness.py                        # Auditor unit tests (unittest)
    └── test_validate_trace.py                       # Trace validator unit tests (unittest)
```

---

## Installation

### Skills CLI / Antigravity / Claude Code / Codex / OpenCode

```bash
# Skills CLI
npx skills add Destro01400/agent-harness

# Project-scoped (Antigravity)
git clone https://github.com/Destro01400/agent-harness.git .agent/skills/agent-harness

# Project-scoped (Claude Code)
git clone https://github.com/Destro01400/agent-harness.git .claude/skills/agent-harness

# Project-scoped (Codex)
git clone https://github.com/Destro01400/agent-harness.git .agents/skills/agent-harness

# Project-scoped (OpenCode)
git clone https://github.com/Destro01400/agent-harness.git .opencode/skills/agent-harness
```

## Usage

### Scaffold a starter harness or eval suite

```bash
python scripts/scaffold_harness.py --list
python scripts/scaffold_harness.py --template python-runtime-eval --name AcmeAgent --out ./AcmeAgent
python scripts/scaffold_harness.py --template typescript-runtime-eval --name AcmeAgent --out ./AcmeAgentTS
python scripts/scaffold_harness.py --template eval-suite-standalone --name AcmeEvals --out ./AcmeEvals
```

### Audit an agent harness (Text / JSON / SARIF 2.1.0)

```bash
python scripts/audit_harness.py path/to/your-agent                 # human-readable findings (AH001-AH016)
python scripts/audit_harness.py path/to/your-agent --strict        # exit 1 on ERROR/WARN
python scripts/audit_harness.py path/to/your-agent --json          # machine-readable JSON
python scripts/audit_harness.py path/to/your-agent --sarif         # SARIF 2.1.0 (excludes --json)
```

### Validate JSONL traces, eval datasets, and eval summaries

```bash
python scripts/validate_trace.py path/to/traces/ --strict
python scripts/validate_trace.py path/to/session.jsonl --mode trace --json
python scripts/validate_trace.py path/to/eval_summary.json --mode eval_summary --strict
```

### GitHub Code Scanning (CI)

```yaml
# .github/workflows/agent-harness-audit.yml
name: agent-harness-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - name: Audit Agent Harness (SARIF)
        run: python .agent/skills/agent-harness/scripts/audit_harness.py . --sarif > harness-audit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: harness-audit.sarif }
```

### Run the unit tests

```bash
python -B -m unittest discover -s scripts -p "test_*.py" -v
```

---

<a id="versão-em-português-br"></a>

## Versão em Português (BR)

Skill completa de engenharia para **harnesses de agentes de IA** (`Agent = Model + Harness`) em **Python 3.11+** e **TypeScript (Node 24+ ESM)** — cobrindo tanto **harnesses de execução (runtime)** quanto **harnesses de avaliação (evals)**. Inclui **15 guias de referência**, **3 templates iniciais sem dependências externas** com gerador por linha de comando, um **auditor estático em Python (`AH001`–`AH016`)** com saída **SARIF 2.1.0** para o GitHub Code Scanning e um **validador de traces JSONL e relatórios de eval**.

### O que esta Skill inclui

- **Arquitetura, fronteiras e harness forte vs. fraco ([`harness-architecture.md`](references/harness-architecture.md), [`strong-vs-weak-harnesses.md`](references/strong-vs-weak-harnesses.md)):** separação Brain/Session/Hands, invariante `Model-visible ⟺ logged`, matriz de 6 espécies (quando *não* usar harness e preferir wrapper simples ou workflow determinístico), DeepSeek Harness (`dsh`), Claude Managed Agents, OpenAI Codex e SWE-agent.
- **Loop de execução, ferramentas (ACI) e resiliência ([`agent-loop-and-budgets.md`](references/agent-loop-and-budgets.md), [`tool-contracts-and-execution.md`](references/tool-contracts-and-execution.md), [`resilience-and-streaming.md`](references/resilience-and-streaming.md)):** orçamentos ortogonais (passos, tokens, custo, tempo ativo e relógio), detecção de loop infinito, verificação pré-saída, `input_examples`, truncamento com spill em disco, erros acionáveis, idempotência e retry em camada única com backoff + jitter.
- **Contexto, cache de prefixo, estado e checkpoints ([`context-and-memory.md`](references/context-and-memory.md), [`state-and-checkpoints.md`](references/state-and-checkpoints.md)):** prevenção de Context Rot, invariância de KV-cache, preservação de blocos de raciocínio (`reasoning_content`/`thinking`/`encrypted_content`), escada de compactação em 5 níveis, log append-only `session.vN.jsonl`, Initializer+Worker e política de aprovação humana (5 decisões + disjuntor de 3 rejeições).
- **Segurança, sandboxing e MCP ([`sandboxing-and-security.md`](references/sandboxing-and-security.md), [`mcp-and-dynamic-tools.md`](references/mcp-and-dynamic-tools.md)):** OWASP Agentic Top 10 2026 (`ASI01`–`ASI10`), defesa contra a Lethal Trifecta, regra da fronteira dupla (sistema de arquivos + proxy de rede), sandbox sem credenciais, `defer_loading` + busca de ferramentas, Code Mode / PTC e proteção contra Tool Poisoning, Rug Pulls (pinagem SHA-256) e Shadowing.
- **Observabilidade, evals e graders ([`observability-and-traces.md`](references/observability-and-traces.md), [`eval-harness-design.md`](references/eval-harness-design.md), [`graders-and-regression.md`](references/graders-and-regression.md)):** OpenTelemetry GenAI Semantic Conventions, `NO_CONTENT` por padrão, suítes de capacidade vs. regressão, `--gold`, `pass@k` vs. `pass^k`, intervalo de Wilson 95%, juízes LLM protegidos por `{grader_nonce}`, troca de ordem e painéis multi-família.
- **Multi-agente, agentes de código e produção ([`multi-agent-orchestration.md`](references/multi-agent-orchestration.md), [`coding-agent-patterns.md`](references/coding-agent-patterns.md), [`production-deployment.md`](references/production-deployment.md)):** quando evitar multi-agente (MAST/Cognition), topologias válidas com handoff por artefatos em disco, edição ancorada (Hashline / linter pré-gravação), `AGENTS.md` enxuto, worktrees Git, provisionamento preguiçoso de sandboxes, perfis em camadas, migrações imutáveis `v0→vN` e kill switches.
- **Templates e scripts:** `assets/templates/` (`python-runtime-eval`, `typescript-runtime-eval`, `eval-suite-standalone`), [`scaffold_harness.py`](scripts/scaffold_harness.py), [`audit_harness.py`](scripts/audit_harness.py), [`validate_trace.py`](scripts/validate_trace.py) e testes `test_*.py`.

### Como instalar no seu projeto

```bash
# Via Skills CLI
npx skills add Destro01400/agent-harness

# No Antigravity (dentro da pasta do projeto)
git clone https://github.com/Destro01400/agent-harness.git .agent/skills/agent-harness

# No Claude Code (dentro da pasta do projeto)
git clone https://github.com/Destro01400/agent-harness.git .claude/skills/agent-harness

# No Codex (dentro da pasta do projeto)
git clone https://github.com/Destro01400/agent-harness.git .agents/skills/agent-harness

# No OpenCode (dentro da pasta do projeto)
git clone https://github.com/Destro01400/agent-harness.git .opencode/skills/agent-harness
```

### Como usar

```bash
# Gerar um harness inicial a partir de um template
python scripts/scaffold_harness.py --template python-runtime-eval --name MeuAgente --out ./MeuAgente

# Auditar um projeto (use --strict no CI e --sarif para o GitHub Code Scanning)
python scripts/audit_harness.py caminho/do/seu-agente --strict
python scripts/audit_harness.py caminho/do/seu-agente --sarif > harness-audit.sarif

# Validar traces JSONL, datasets ou relatórios de eval
python scripts/validate_trace.py caminho/dos/traces --strict
```

O exemplo de workflow do GitHub Actions acima (seção *GitHub Code Scanning*) funciona igualmente para projetos em português.

---

## License

Released under the [MIT License](LICENSE).
