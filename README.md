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

**Tested end-to-end on OWASP Juice Shop v17.1.1** -- 62 findings across SQL injection, XSS, path traversal, SSTI, SSRF, hardcoded secrets, and more.

## Why VulnScout?

Traditional SAST tools find patterns. VulnScout **understands your application**.

- **Automated scan pipeline** -- Semgrep + Joern CPG + secret scanning in one command, with SARIF and Markdown output
- **Threat models first, then hunts** -- STRIDE analysis identifies what matters before scanning
- **Traces data flow, not just patterns** -- follows user input from source to sink across files and services
- **15 CPG verification scripts** -- proves exploitability through Code Property Graph analysis, not just pattern matching
- **CVSS 3.1 auto-scoring** -- every finding gets a CVSS vector and numeric score
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

> **Note**: `.claude/plugins/` is relative to your project root. Claude Code automatically discovers plugins in this directory.

## Standalone Scan Pipeline

VulnScout includes Python scripts that run independently of Claude Code:

```bash
# Scan with Semgrep + secret scanning
python3 scripts/scan_orchestrator.py /path/to/code --tools semgrep --secrets --format sarif

# Create a Joern CPG (cached by content hash)
python3 scripts/create_cpg.py /path/to/code

# Batch-verify findings with Joern CPG analysis
python3 scripts/batch_verify.py --findings .claude/findings.json --cpg .joern/*.cpg

# Render HTML or Markdown from an existing findings artifact
python3 scripts/report.py .claude/findings.json --format html --output security-report.html

# CI gate: fail on high-severity findings
python3 scripts/scan_orchestrator.py . --tools semgrep --fail-on high --format sarif --output findings.sarif
```

## What You Get

### 13 Commands

| Command | What it does |
|---------|-------------|
| `/whitebox-pentest:full-audit` | **One command does everything** -- scopes, threat models, audits, reports |
| `/whitebox-pentest:threats` | STRIDE threat modeling with data flow diagrams |
| `/whitebox-pentest:sinks` | Find dangerous functions across 9 languages |
| `/whitebox-pentest:trace` | Follow data from source to sink |
| `/whitebox-pentest:scan` | Run Semgrep, CodeQL, and Joern into a shared findings artifact |
| `/whitebox-pentest:scope` | Handle large codebases with smart compression |
| `/whitebox-pentest:propagate` | Found one bug? Find every instance of the pattern |
| `/whitebox-pentest:verify` | CPG-based false positive elimination |
| `/whitebox-pentest:report` | Render Markdown, JSON, SARIF, or HTML from the shared findings artifact |
| `/whitebox-pentest:diff` | Compare security posture between git refs and highlight regressions |
| `/whitebox-pentest:auto-fix` | Auto-remediate verified findings with generated patches |
| `/whitebox-pentest:create-rule` | Generate a custom Semgrep rule from a confirmed vulnerability pattern |
| `/whitebox-pentest:mutate` | Mutation-test security controls to find detection gaps |

### 8 Autonomous Agents

Agents run independently and return detailed analysis:

- **app-mapper** -- Maps architecture and trust boundaries
- **threat-modeler** -- STRIDE analysis and data flow diagrams (consumes app-mapper output)
- **code-reviewer** -- Proactive vulnerability identification
- **local-tester** -- Dynamic testing guidance (hands off to poc-developer)
- **poc-developer** -- Proof of concept development
- **patch-advisor** -- Specific remediation with code patches
- **false-positive-verifier** -- Evidence-based verification with NEEDS_REVIEW resolution path
- **attack-researcher** -- Autonomous attack vector exploration beyond pattern matching

### 15 Joern CPG Verification Scripts

Each script proves or disproves a vulnerability through Code Property Graph data flow analysis:

| Script | What it verifies |
|--------|-----------------|
| verify-sqli | SQL injection (parameterization, binding APIs) |
| verify-cmdi | Command injection (shell vs array execution) |
| verify-xss | Cross-site scripting (encoding, Content-Type) |
| verify-path | Path traversal (strong vs weak normalization) |
| verify-ssrf | Server-side request forgery (URL validation, allowlists) |
| verify-xxe | XML external entity injection (entity disabling) |
| verify-ssti | Server-side template injection (filesystem vs user templates) |
| verify-deser | Unsafe deserialization (SafeLoader, ObjectInputFilter) |
| verify-ldap | LDAP injection (filter escaping) |
| verify-randomness | Insecure randomness (crypto alternatives) |
| verify-reentrancy | Solidity reentrancy (CEI pattern) |
| verify-overflow | Solidity integer overflow (SafeMath, Solidity >=0.8) |
| verify-access-control | Solidity missing access control (onlyOwner, tx.origin) |
| verify-delegatecall | Solidity delegatecall risks (proxy patterns, EIP-1967) |
| verify-generic | Fallback for types without a dedicated script |

### 27 Auto-Activated Skills

Skills activate automatically when relevant -- no configuration needed:

**Core Analysis**: dangerous-functions, vuln-patterns, data-flow-tracing, cpg-analysis, exploit-techniques

**OWASP Mapping**: security-misconfiguration, cryptographic-failures, logging-failures, exception-handling, sensitive-data-leakage, business-logic

**Advanced**: threat-modeling, vulnerability-chains, cross-component, cache-poisoning, postmessage-xss, sandbox-escapes, framework-patterns, nextjs-react

**Infrastructure**: workspace-discovery, mixed-language-monorepos, owasp-2025, secret-scanning

**Extended Coverage**: ai-ml-attacks, owasp-api-top10, cloud-native, compliance-mapping

### Framework Security Patterns

Dedicated detection patterns for:
- **Django** -- ORM bypass, template injection, CSRF exemptions, settings exposure
- **Rails** -- Mass assignment, SQL interpolation, ERB injection, Marshal.load
- **Spring Security** -- SpEL injection, CORS/CSRF misconfiguration, actuator exposure
- **GraphQL** -- Introspection, depth/complexity limits, batching, nested auth bypass
- **Next.js/React** -- Server Actions SSRF, middleware bypass, Server Component data exposure
- **Flask/Twig/Blade** -- SSTI, filter callbacks, sandbox escapes

## Supported Languages

| Language | Token Reduction | Static Analysis | CPG Verification |
|----------|----------------|-----------------|------------------|
| Go | 95-97% fewer tokens | Semgrep, Joern | Yes |
| TypeScript/JS | ~80% fewer tokens | Semgrep, CodeQL | Yes |
| Python | 85-90% fewer tokens | Semgrep, Joern | Yes |
| Java | 80-85% fewer tokens | Semgrep, CodeQL | Yes |
| PHP | 80-85% fewer tokens | Semgrep | Yes |
| Ruby | 85-90% fewer tokens | Semgrep | Yes |
| Rust | 85-90% fewer tokens | Semgrep | -- |
| C#/.NET | 80-85% fewer tokens | Semgrep, CodeQL | -- |
| Solidity | 70-80% fewer tokens | Semgrep, Slither | Yes (4 scripts) |

## OWASP Top 10 Mapping

| # | OWASP Top 10 | Coverage | Primary Skills |
|---|---------------|----------|----------------|
| A01 | Broken Access Control | Covered | `business-logic`, `owasp-api-top10` |
| A02 | Cryptographic Failures | Covered | `cryptographic-failures` |
| A03 | Injection | Covered | `vuln-patterns`, `dangerous-functions` |
| A04 | Insecure Design | Covered | `business-logic`, `threat-modeling` |
| A05 | Security Misconfiguration | Covered | `security-misconfiguration`, `cloud-native` |
| A06 | Vulnerable and Outdated Components | Out of scope | -- |
| A07 | Identification and Authentication Failures | Covered | `vuln-patterns` |
| A08 | Software and Data Integrity Failures | Covered | `vuln-patterns`, `ai-ml-attacks` |
| A09 | Security Logging and Monitoring Failures | Covered | `logging-failures`, `sensitive-data-leakage` |
| A10 | Server-Side Request Forgery | Covered | `vuln-patterns`, `framework-patterns`, `cloud-native` |

**9/10 categories covered.** A06 is intentionally out of scope -- VulnScout focuses on source review and exploitability, not dependency inventory.

## Findings Artifact and CI Workflow

`/scan`, `/verify`, and `/full-audit` share one contract: `.claude/findings.json`.

- `schema_version` identifies the artifact version.
- `kind` separates reportable `finding` entries from audit `hotspot` pivots.
- `stable_key` gives each entry a suppression-safe identifier.
- `source_tool` and `evidence` are required on every entry.
- `cvss_vector` and `cvss_score` provide CVSS 3.1 scoring.
- Severity summaries count only unsuppressed entries where `kind == "finding"`.

CI-focused flags:

```bash
--since-commit <sha>     # Scope to recent changes
--suppressions <path>    # Apply .vuln-scout-ignore suppressions
--fail-on <severity>     # Exit code 2 when blocking findings remain
--format sarif|json|md   # Machine-readable or human-readable output
--secrets                # Enable gitleaks/trufflehog secret scanning
```

## How It Works

```
/full-audit automatically:

1. Measures codebase    -->  Too big? Compresses with language-aware strategy
2. Detects frameworks   -->  Next.js, Flask, Spring, Rails, Django, Solidity...
3. Threat models        -->  STRIDE analysis, DFDs, trust boundaries
4. Ranks modules        -->  Auth first, then APIs, then everything else
5. Scans (Semgrep)      -->  Pattern matching + taint analysis
6. Verifies (Joern)     -->  CPG data flow proof per finding
7. Chains findings      -->  Connects SSRF + SSTI + RCE across services
8. Reports              -->  Markdown, JSON, or SARIF with CVSS scores
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

- **Injection**: SQL, Command, LDAP, Template (SSTI), XXE
- **Authentication**: Bypass, Session attacks, JWT flaws
- **Access Control**: IDOR, Privilege escalation, BOLA (API)
- **Business Logic**: Workflow bypass, state manipulation, trust boundary violations
- **Cryptography**: Weak algorithms, hardcoded secrets, insecure randomness
- **Deserialization**: Java, PHP, Python, .NET, ML pipeline (joblib/torch.load)
- **API Security**: GraphQL depth attacks, mass assignment, gRPC reflection
- **Cloud Native**: IMDS endpoints, S3 misconfiguration, K8s RBAC, serverless env leakage
- **Race Conditions**: TOCTOU, double-spend attacks
- **Data Leakage**: Credentials in logs, error exposure, secret scanning (git history)
- **Smart Contracts**: Reentrancy, integer overflow, access control, delegatecall, flash loans
- **Compliance**: PCI-DSS, HIPAA, SOC 2, NIST CSF mapping

## Prerequisites

**Required:**
```bash
npm install -g repomix    # Codebase compression for large repos
```

**Recommended (enhances scanning):**
```bash
pip install semgrep       # Pattern matching + taint analysis
```

**Optional (deepens analysis):**
```bash
# Joern CPG analysis (data flow verification)
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" | bash

# Secret scanning (git history)
brew install gitleaks     # or: pip install trufflehog

# Solidity analysis
pip install slither-analyzer
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
  scripts/
    scan_orchestrator.py        # Main scan pipeline
    run_semgrep.py              # Semgrep wrapper + normalizer
    run_secrets.py              # Secret scanner (gitleaks/trufflehog)
    create_cpg.py               # Joern CPG creation + caching
    batch_verify.py             # Batch CPG verification
    bundle_joern.py             # Script bundler for Joern compatibility
    markdown_report.py          # Report generator
    artifact_utils.py           # Findings schema, SARIF, CVSS, dedup
    tool_runners/               # Modular tool runner package
    joern/                      # 15 CPG verification scripts
```

## License

[MIT](LICENSE)
