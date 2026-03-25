<p align="center">
  <img src="vuln-scout.png" alt="VulnScout" width="280">
</p>

<h1 align="center">VulnScout</h1>

<p align="center"><strong>AI-powered whitebox penetration testing for Claude Code.</strong></p>

One command. Full audit. Any codebase.

```
/whitebox-pentest:full-audit /path/to/code
```

---

VulnScout is a Claude Code plugin that turns Claude into an autonomous security reviewer. It brings battle-tested pentesting methodology (HTB Academy, OffSec AWAE/OSWE) into your terminal with STRIDE threat modeling, evidence-first findings, and support for 9 languages including Solidity smart contracts.

## Why VulnScout?

Traditional SAST tools find patterns. VulnScout **understands your application**.

- **Threat models first, then hunts** -- STRIDE analysis identifies what matters before scanning
- **Traces data flow, not just patterns** -- follows user input from source to sink across files and services
- **Handles massive codebases** -- language-aware compression (Go: 97% reduction, Python: 90%) lets it audit million-token monorepos
- **Chains vulnerabilities** -- finds SSRF-to-SSTI-to-RCE attack chains that single-pattern scanners miss
- **Polyglot-native** -- audits Go + Python + TypeScript microservices as one interconnected system

## Quick Start

```bash
# Option 1: Symlink into your project's plugin directory
mkdir -p .claude/plugins
ln -s /path/to/vuln-scout/whitebox-pentest .claude/plugins/whitebox-pentest

# Option 2: Copy into your project
cp -r /path/to/vuln-scout/whitebox-pentest .claude/plugins/whitebox-pentest

# Run a full audit
/whitebox-pentest:full-audit .

# Or start with threat modeling
/whitebox-pentest:threats
```

## What You Get

### 9 Commands

| Command | What it does |
|---------|-------------|
| `/whitebox-pentest:full-audit` | **One command does everything** -- scopes, threat models, audits, reports |
| `/whitebox-pentest:threats` | STRIDE threat modeling with data flow diagrams |
| `/whitebox-pentest:sinks` | Find dangerous functions across 9 languages |
| `/whitebox-pentest:trace` | Follow data from source to sink |
| `/whitebox-pentest:scan` | Run Semgrep, CodeQL, and Joern branches into a shared findings artifact |
| `/whitebox-pentest:scope` | Handle large codebases with smart compression |
| `/whitebox-pentest:propagate` | Found one bug? Find every instance of the pattern |
| `/whitebox-pentest:verify` | CPG-based false positive elimination |
| `/whitebox-pentest:report` | Render Markdown, JSON, or SARIF from the shared findings artifact |

### 7 Autonomous Agents

Agents run independently and return detailed analysis:

- **app-mapper** -- Maps architecture and trust boundaries
- **threat-modeler** -- STRIDE analysis and data flow diagrams
- **code-reviewer** -- Proactive vulnerability identification
- **local-tester** -- Dynamic testing guidance
- **poc-developer** -- Proof of concept development
- **patch-advisor** -- Specific remediation with code patches
- **false-positive-verifier** -- Evidence-based verification

### 27 Auto-Activated Skills

Skills activate automatically when relevant -- no configuration needed:

**Core Analysis**: dangerous-functions, vuln-patterns, data-flow-tracing, cpg-analysis, exploit-techniques

**OWASP Mapping**: security-misconfiguration, cryptographic-failures, logging-failures, exception-handling, sensitive-data-leakage, business-logic

**Advanced**: threat-modeling, vulnerability-chains, cross-component, cache-poisoning, postmessage-xss, sandbox-escapes, framework-patterns, nextjs-react

**Infrastructure**: workspace-discovery, mixed-language-monorepos, owasp-2025, secret-scanning

**New Coverage**: ai-ml-attacks, owasp-api-top10, cloud-native, compliance-mapping

## Supported Languages

| Language | Token Reduction | Static Analysis |
|----------|----------------|-----------------|
| Go | 95-97% fewer tokens | Semgrep, Joern |
| TypeScript/JS | ~80% fewer tokens | Semgrep, CodeQL |
| Python | 85-90% fewer tokens | Semgrep, Joern |
| Java | 80-85% fewer tokens | Semgrep, CodeQL |
| Rust | 85-90% fewer tokens | Semgrep |
| PHP | 80-85% fewer tokens | Semgrep |
| C#/.NET | 80-85% fewer tokens | Semgrep, CodeQL |
| Ruby | 85-90% fewer tokens | Semgrep |
| Solidity | 70-80% fewer tokens | Semgrep, Slither |

## OWASP Top 10 Mapping

VulnScout reports against the official OWASP Top 10 naming, while the legacy `owasp-2025` skill directory is retained for compatibility with existing skill references.

| # | OWASP Top 10 | Coverage | Primary Skills |
|---|---------------|----------|----------------|
| A01 | Broken Access Control | Covered | `business-logic` |
| A02 | Cryptographic Failures | Covered | `cryptographic-failures` |
| A03 | Injection | Covered | `vuln-patterns`, `dangerous-functions` |
| A04 | Insecure Design | Covered | `business-logic`, `threat-modeling` |
| A05 | Security Misconfiguration | Covered | `security-misconfiguration` |
| A06 | Vulnerable and Outdated Components | Out of scope | -- |
| A07 | Identification and Authentication Failures | Covered | `vuln-patterns` |
| A08 | Software and Data Integrity Failures | Covered | `vuln-patterns` |
| A09 | Security Logging and Monitoring Failures | Covered | `logging-failures`, `sensitive-data-leakage` |
| A10 | Server-Side Request Forgery | Covered | `vuln-patterns`, `framework-patterns`, `vulnerability-chains` |

**9/10 categories covered.** A06 is intentionally out of scope because VulnScout focuses on source review and exploitability inside your codebase, not dependency inventory.

## Findings Artifact and CI Workflow

`/scan`, `/verify`, and `/full-audit` now share one contract: `.claude/findings.json`.

- `schema_version` identifies the artifact version.
- `kind` separates reportable `finding` entries from audit `hotspot` pivots.
- `stable_key` gives each entry a suppression-safe identifier.
- `source_tool` and `evidence` are required on every entry.
- Severity summaries count only unsuppressed entries where `kind == "finding"`.

CI-focused flags are available across the workflow:

- `--since-commit <sha>` scopes analysis to recent code changes.
- `--suppressions <path>` applies stable-key suppressions from `.vuln-scout-ignore`.
- `--fail-on <severity>` returns exit code `2` when blocking findings remain.
- `--format sarif|json|md` emits machine-readable or human-readable output.

## How It Works

```
/full-audit automatically:

1. Measures codebase    -->  Too big? Compresses with language-aware strategy
2. Detects frameworks   -->  Next.js, Flask, Spring, Rails, Solidity...
3. Threat models        -->  STRIDE analysis, DFDs, trust boundaries
4. Ranks modules        -->  Auth first, then APIs, then everything else
5. Deep-dive audits     -->  Sinks, data flow tracing, pattern matching
6. Chains findings      -->  Connects SSRF + SSTI + RCE across services
7. Reports              -->  Markdown + JSON with remediation
```

### Polyglot Monorepos

Got a Go gateway, Python ML service, and TypeScript frontend? VulnScout handles it:

```
/whitebox-pentest:full-audit ~/code/platform

Polyglot detected: Go (450 files) + Python (380) + TypeScript (420)

Findings by Service:
  auth-service (Go):        2 CRITICAL, 1 HIGH
  api-gateway (Go):         1 HIGH, 2 MEDIUM
  ml-pipeline (Python):     1 CRITICAL, 2 HIGH
  web-frontend (TypeScript): 3 MEDIUM

Cross-Service Findings:
  Auth token not validated in ml-pipeline (CRITICAL)
  Error messages leak from Python to Gateway (MEDIUM)
```

## Vulnerability Coverage

- **Injection**: SQL, Command, LDAP, Template (SSTI)
- **Authentication**: Bypass, Session attacks, JWT flaws
- **Access Control**: IDOR, Privilege escalation
- **Business Logic**: Workflow bypass, state manipulation, trust boundary violations
- **Cryptography**: Weak algorithms, hardcoded secrets
- **Deserialization**: Java, PHP, Python, .NET gadgets
- **Race Conditions**: TOCTOU, double-spend attacks
- **Data Leakage**: Credentials in logs, error exposure
- **Smart Contracts**: Reentrancy, flash loans, oracle manipulation, access control

## Prerequisites

**Required:**
```bash
npm install -g repomix    # Codebase compression for large repos
```

**Recommended (enhances scanning):**
```bash
pip install semgrep                                         # Pattern matching
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" | bash  # CPG analysis
```

**For Solidity:**
```bash
pip install slither-analyzer  # Smart contract analysis
```

## Methodology

VulnScout implements methodologies from:
- **HTB Academy** -- Whitebox Pentesting Process (4-phase)
- **OffSec AWAE** -- Advanced Web Attacks and Exploitation (WEB-300)
- **NahamSec** -- Deep application understanding and business logic focus

> "Understanding the application deeply will always beat automation."

The plugin supports two complementary approaches:
1. **Sink-First** -- Find dangerous functions, trace data flow backward
2. **Understanding-First** -- Map the application, then hunt with context

Both work together. Understanding reveals business logic bugs that sink scanning misses.

## Diff-Aware Scanning

Scope audits to recent changes or PR diffs for fast CI feedback:

```bash
# Scan only files changed since a known base
/whitebox-pentest:full-audit . --since-commit origin/main

# Prioritize modules with recent changes
/whitebox-pentest:full-audit . --recent 7

# Headless PR gate: diff scan, JSON output, no prompts
/whitebox-pentest:full-audit . --since-commit origin/main --quick --json --no-interactive

# Incremental Semgrep scan of changed files
/whitebox-pentest:scan . --since-commit origin/main --format sarif --fail-on high
```

`--diff-base` remains as a backward-compatible alias for older automation.

## Dynamic Verification

Optionally execute generated PoC scripts to confirm exploitability:

```bash
# Audit with dynamic PoC verification (requires explicit approval per PoC)
/whitebox-pentest:full-audit . --verify-dynamic
```

Safety-first: PoCs run in `--dry-run` mode by default, require user confirmation, have a 30s timeout, and must include cleanup functions.

## Project Structure

```
whitebox-pentest/
  .claude-plugin/plugin.json   # Plugin manifest
  agents/                       # 7 autonomous security analysts
  commands/                     # 9 slash commands
  hooks/                        # 4 background automation hooks
  skills/                       # 27 auto-activated knowledge modules
  scripts/                      # Helper scripts (Joern queries, etc.)
```

## License

[MIT](LICENSE)
