# VulnScout - Development Guide

A Claude Code plugin for whitebox penetration testing, supporting 9 languages including Solidity smart contracts.

## Project Structure

```
vuln-scout/
├── .claude-plugin/plugin.json  # Plugin manifest
├── agents/                      # Autonomous security analysts
├── commands/                    # Slash commands (/full-audit, /scope, etc.)
├── hooks/                       # Background automation
├── skills/                      # Auto-activated knowledge modules
└── scripts/                     # Helper scripts (Joern queries, etc.)
```

## Key Commands

- `/vuln-scout:full-audit` - Main entry point for security audits
- `/vuln-scout:scope` - Handle large codebases with compression
- `/vuln-scout:threats` - STRIDE threat modeling
- `/vuln-scout:sinks` - Find dangerous functions
- `/vuln-scout:verify` - CPG-based false positive verification

## Development Notes

- Skills are in `skills/` with a `SKILL.md` and optional `references/` folder
- Agents are markdown files in `agents/` with frontmatter
- Commands are markdown files in `commands/` with YAML frontmatter
- Hooks are in `hooks/` for event-driven automation
- Prompt-first orchestration artifacts live in `.claude/audit-plan.md` and `.claude/review-ledger.json`
- Prompt eval definitions live in `vuln-scout/evals/`; validate with `python3 vuln-scout/scripts/validate_evals.py`

## Supported Languages

Go, TypeScript/JS, Python, Java, Rust, PHP, C#/.NET, Ruby, Solidity

## External Tools

- **Semgrep** - Fast pattern matching
- **Joern** - Code Property Graph analysis
- **Slither** - Solidity static analysis
- **repomix** - Codebase compression for large repos

## Release Checklist

Before tagging a release, verify:

- [ ] `python3 vuln-scout/scripts/check_consistency.py` passes
- [ ] Skill count matches across root README, vuln-scout/README.md, and filesystem (`ls skills/`)
- [ ] Agent and command counts match across both READMEs
- [ ] OWASP mapping language uses official OWASP Top 10 names in public docs
- [ ] Every skill directory has a `SKILL.md` entry point
- [ ] Every command's `argument-hint` includes all flags documented in its body
- [ ] No stale command references (bare `/audit`, `/scan` without `whitebox-pentest:` prefix)
- [ ] `references/findings.schema.json` is the shared source of truth for `/scan`, `/verify`, and `/full-audit`
- [ ] `.claude/audit-plan.md` sections match the prompt-orchestration contract in `scripts/prompt_artifacts.py`
- [ ] `.claude/review-ledger.json` shape matches `scripts/prompt_artifacts.py`
- [ ] `findings.json` field conventions are consistent across scan.md, verify.md, full-audit.md, and report.md
- [ ] `stable_key`, `kind`, `source_tool`, and `evidence` are present anywhere findings are documented
- [ ] `hotspot` vs `finding` semantics are consistent across commands, agents, and examples
- [ ] `--since-commit`, `--suppressions`, `--fail-on`, and `--format` are documented wherever supported
- [ ] `whitebox-pentest-state.json` schema matches between full-audit.md and session-init.md
- [ ] `python3 vuln-scout/scripts/validate_evals.py` passes before running prompt benchmarks
