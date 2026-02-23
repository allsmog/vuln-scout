# VulnScout

**AI-powered whitebox penetration testing for Claude Code.**

One command. Full audit. Any codebase.

```
/whitebox-pentest:full-audit /path/to/code
```

---

VulnScout is a Claude Code plugin that turns Claude into an autonomous security researcher. It brings battle-tested pentesting methodology (HTB Academy, OffSec AWAE/OSWE) into your terminal -- with STRIDE threat modeling, OWASP 2025 coverage, and support for 9 languages including Solidity smart contracts.

## Why VulnScout?

Traditional SAST tools find patterns. VulnScout **understands your application**.

- **Threat models first, then hunts** -- STRIDE analysis identifies what matters before scanning
- **Traces data flow, not just patterns** -- follows user input from source to sink across files and services
- **Handles massive codebases** -- language-aware compression (Go: 97% reduction, Python: 90%) lets it audit million-token monorepos
- **Chains vulnerabilities** -- finds SSRF-to-SSTI-to-RCE attack chains that single-pattern scanners miss
- **Polyglot-native** -- audits Go + Python + TypeScript microservices as one interconnected system

## Quick Start

```bash
# Install the plugin
claude plugin add /path/to/vuln-scout/whitebox-pentest

# Run a full audit
/whitebox-pentest:full-audit .

# Or start with threat modeling
/whitebox-pentest:threats
```

## What You Get

### 9 Commands

| Command | What it does |
|---------|-------------|
| `/full-audit` | **One command does everything** -- scopes, threat models, audits, reports |
| `/threats` | STRIDE threat modeling with data flow diagrams |
| `/sinks` | Find dangerous functions across 9 languages |
| `/trace` | Follow data from source to sink |
| `/scan` | Run Semgrep, CodeQL, or Joern |
| `/scope` | Handle large codebases with smart compression |
| `/propagate` | Found one bug? Find every instance of the pattern |
| `/verify` | CPG-based false positive elimination |
| `/report` | Generate findings report with remediation |

### 7 Autonomous Agents

Agents run independently and return detailed analysis:

- **app-mapper** -- Maps architecture and trust boundaries
- **threat-modeler** -- STRIDE analysis and data flow diagrams
- **code-reviewer** -- Proactive vulnerability identification
- **local-tester** -- Dynamic testing guidance
- **poc-developer** -- Proof of concept development
- **patch-advisor** -- Specific remediation with code patches
- **false-positive-verifier** -- Chain-of-thought verification

### 22 Auto-Activated Skills

Skills activate automatically when relevant -- no configuration needed:

**Core Analysis**: dangerous-functions, vuln-patterns, data-flow-tracing, cpg-analysis, exploit-techniques

**OWASP 2025 Coverage**: security-misconfiguration, cryptographic-failures, logging-failures, exception-handling, sensitive-data-leakage, business-logic

**Advanced**: threat-modeling, vulnerability-chains, cross-component, cache-poisoning, postmessage-xss, sandbox-escapes, framework-patterns, nextjs-react

**Infrastructure**: workspace-discovery, mixed-language-monorepos, owasp-2025

## Supported Languages

| Language | Compression | Static Analysis |
|----------|-------------|-----------------|
| Go | 95-97% | Semgrep, Joern |
| TypeScript/JS | ~80% | Semgrep, CodeQL |
| Python | 85-90% | Semgrep, Joern |
| Java | 80-85% | Semgrep, CodeQL |
| Rust | 85-90% | Semgrep |
| PHP | 80-85% | Semgrep |
| C#/.NET | 80-85% | Semgrep, CodeQL |
| Ruby | 85-90% | Semgrep |
| Solidity | 70-80% | Semgrep, Slither |

## OWASP Top 10 2025 Coverage

| # | Category | Status |
|---|----------|--------|
| A01 | Broken Access Control | Covered |
| A02 | Security Misconfiguration | Covered |
| A03 | Software Supply Chain | Out of scope |
| A04 | Cryptographic Failures | Covered |
| A05 | Injection | Covered |
| A06 | Insecure Design | Covered |
| A07 | Authentication Failures | Covered |
| A08 | Data Integrity Failures | Covered |
| A09 | Logging & Alerting | Covered |
| A10 | Exception Mishandling | Covered |

**9/10 categories covered.** A03 (Supply Chain) excluded by design -- VulnScout focuses on your code, not your dependencies.

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

## Project Structure

```
whitebox-pentest/
  .claude-plugin/plugin.json   # Plugin manifest
  agents/                       # 7 autonomous security analysts
  commands/                     # 9 slash commands
  hooks/                        # 4 background automation hooks
  skills/                       # 22 auto-activated knowledge modules
  scripts/                      # Helper scripts (Joern queries, etc.)
```

## License

[MIT](LICENSE)
