# VulnScout Plugin

VulnScout is a Claude Code plugin for whitebox security review. This directory is the canonical plugin root used by `claude --plugin-dir ./vuln-scout` from the repository root.

Manifest: `vuln-scout/.claude-plugin/plugin.json`

## Canonical Commands

| Command | Maturity | Key flags |
|---|---|---|
| `/vuln-scout:full-audit` | stable | `[path]`, `--quick`, `--since-commit`, `--scope`, `--suppressions`, `--fail-on`, `--no-semantic-analysis` |
| `/vuln-scout:verify` | stable | `<file:line>`, `--type`, `--all-critical`, `--from`, `--json` |
| `/vuln-scout:report` | stable | `[output_file]`, `--format md|json|sarif|html|pr-comment|bundle`, `--suppressions`, `--fail-on` |
| `/vuln-scout:scope` | stable | `<path>`, `--list`, `--include`, `--exclude`, `--compress`, `--name` |
| `/vuln-scout:diff` | stable | `<base-ref>`, `[head-ref]`, `--tools`, `--format`, `--fail-on-regression` |

### Commands (15 total)

| Command | Maturity | Purpose |
|---|---|---|
| `/vuln-scout:scan` | beta | Run quick, deep, or audit scanner profiles |
| `/vuln-scout:mobile-audit` | beta | Audit decompiled Android targets (jadx_out + apktool_out merged) |
| `/vuln-scout:threats` | beta | Application understanding and STRIDE modeling |
| `/vuln-scout:sinks` | beta | Search for dangerous functions and output sinks |
| `/vuln-scout:trace` | beta | Trace source-to-sink evidence |
| `/vuln-scout:propagate` | beta | Find related vulnerable patterns |
| `/vuln-scout:create-rule` | experimental | Create custom Semgrep rules from confirmed patterns |
| `/vuln-scout:org-memory-compile` | experimental | Compile human-reviewed org memory |
| `/vuln-scout:mutate` | experimental | Mutation-test security controls |
| `/vuln-scout:auto-fix` | experimental | Generate patches for verified findings |

## Skills

### Skills (35 Auto-Activated)

| Group | Count | Purpose |
|---|---:|---|
| Task skills | 5 | Front-door workflows for audit, PR review, finding verification, evidence packaging, and scoping |
| Knowledge skills | 30 | Vulnerability classes, frameworks, CPG analysis, threat modeling, compliance, language-specific patterns, mobile Android + iOS audit, mobile payment tokenization |

Task skills live in `skills/tasks/`:

| Skill | Trigger intent |
|---|---|
| `start-audit` | Start a full security audit |
| `review-pr` | Review a pull request or diff |
| `verify-finding` | Confirm one finding |
| `package-evidence` | Export reports and bundle artifacts |
| `scope-repo` | Decide audit boundaries for large repos |

## Agents

| Agent | Role |
|---|---|
| `app-mapper` | Map architecture, entry points, trust boundaries, and high-risk modules |
| `threat-modeler` | Build STRIDE threat models from app understanding |
| `code-reviewer` | Review high-risk code paths and findings |
| `false-positive-verifier` | Triage exploitability and controls |
| `local-tester` | Run safe local verification |
| `poc-developer` | Draft PoCs where explicitly safe |
| `patch-advisor` | Recommend remediations |
| `attack-researcher` | Research exploit paths and chaining |
| `mobile-auditor` | Triage `findings.json` from decompiled Android/iOS targets and rank chains |

## Hooks

| Hook | Purpose |
|---|---|
| `session-init` | Load audit state, `audit-plan.md`, and `review-ledger.json` |
| `large-codebase-check` | Suggest scoping for large or monorepo targets |
| `suggest-next-phase` | Recommend next audit command |
| `poc-safety-check` | Gate risky dynamic validation |

## Findings Contract

The shared artifact contract is `references/findings.schema.json`. Reports and bundles consume `.claude/findings.json`, with schema v1.2.0 adding optional trust metadata and older artifacts auto-migrated by `scripts/report.py`.

Audit orchestration also writes:

- `.claude/audit-plan.md`
- `.claude/review-ledger.json`

## MCP Server

`scripts/mcp_server.py` is the local stdio MCP bridge for scanner, report, artifact, and Joern CPG workflows. It exposes `vulnscout_scan`, `vulnscout_report`, `vulnscout_create_cpg`, `vulnscout_joern_query`, `vulnscout_joern_discover`, `vulnscout_verify_findings`, `vulnscout_read_artifact`, and `vulnscout_doctor`.

## Local Development

```bash
python3 scripts/check_consistency.py
python3 scripts/validate_evals.py
python3 scripts/first_run_smoke.py
```

For repo-root execution:

```bash
python3 vuln-scout/scripts/check_consistency.py
python3 vuln-scout/scripts/validate_evals.py
python3 vuln-scout/scripts/first_run_smoke.py
```
