# VulnScout - Development Guide

A Claude Code plugin for whitebox penetration testing, supporting 9 languages including Solidity smart contracts.

## Project Structure

```
whitebox-pentest/
├── .claude-plugin/plugin.json  # Plugin manifest
├── agents/                      # Autonomous security analysts
├── commands/                    # Slash commands (/full-audit, /scope, etc.)
├── hooks/                       # Background automation
├── skills/                      # Auto-activated knowledge modules
└── scripts/                     # Helper scripts (Joern queries, etc.)
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

## Supported Languages

Go, TypeScript/JS, Python, Java, Rust, PHP, C#/.NET, Ruby, Solidity

## External Tools

- **Semgrep** - Fast pattern matching
- **Joern** - Code Property Graph analysis
- **Slither** - Solidity static analysis
- **repomix** - Codebase compression for large repos
