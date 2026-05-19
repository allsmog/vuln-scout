# VulnScout - Development Guide

Primary runtime target: a Claude Code plugin for whitebox penetration testing, supporting 9 languages including Solidity smart contracts. Codex usage in this repository is for development workflow only, not a separate packaged plugin format.

## Project Structure

```
vuln-scout/
├── .claude-plugin/plugin.json  # Plugin manifest
├── agents/                      # Autonomous security analysts
├── commands/                    # Slash commands (/full-audit, /scope, etc.)
├── hooks/                       # Background automation
├── skills/                      # Auto-activated knowledge modules
├── references/                  # Shared artifact schemas and examples
└── scripts/                     # Helper scripts (Joern queries, artifact tooling)
```

## Key Commands

- `/whitebox-pentest:full-audit` - Main entry point for security audits
- `/whitebox-pentest:scope` - Handle large codebases with compression
- `/whitebox-pentest:threats` - STRIDE threat modeling
- `/whitebox-pentest:sinks` - Find dangerous functions
- `/whitebox-pentest:verify` - CPG-based false positive verification

## Development Notes

- Skills are in `skills/` with a `SKILL.md` and optional `references/` folder
- Agents are markdown files in `agents/` with frontmatter
- Commands are markdown files in `commands/` with YAML frontmatter
- Hooks are in `hooks/` for event-driven automation
- Shared findings contract lives in `vuln-scout/references/findings.schema.json`
- Prompt-first orchestration artifacts live in `.claude/audit-plan.md` and `.claude/review-ledger.json`
- Prompt eval definitions live in `vuln-scout/evals/`; validate with `python3 vuln-scout/scripts/validate_evals.py`
- Use `kind: finding` for reportable issues and `kind: hotspot` for sink-only or framework-pivot leads
- `python3 vuln-scout/scripts/check_consistency.py` is the release gate for doc/schema drift

## Supported Languages

Go, TypeScript/JS, Python, Java, Rust, PHP, C#/.NET, Ruby, Solidity

## External Tools

- **Semgrep** - Fast pattern matching
- **Joern** - Code Property Graph analysis
- **Slither** - Solidity static analysis
- **repomix** - Codebase compression for large repos
