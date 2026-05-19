---
name: scope-repo
description: Decide audit boundaries for large or monorepo targets and write audit-plan.md.
---

# Scope Repo

Use this task skill when the user asks to scope this repo, decide where to focus, decide what to audit first, or handle a large codebase.

## Workflow

1. Trigger `large-codebase-check` when repository size or monorepo structure is unclear.
2. Run `/vuln-scout:scope --list` for workspace discovery when applicable.
3. Run `/vuln-scout:scope <path> --compress --name <scope-name>` for the selected boundary.
4. Call `app-mapper` to produce `.claude/app-understanding.md`.
5. Write or update `.claude/audit-plan.md` with scope name, workspace list, entry points, trust boundaries, and high-risk modules.

## Produces

- `.claude/audit-plan.md`
- workspace list
- scope name

## When NOT To Trigger

Do not trigger for STRIDE-only modeling, dangerous-function lookup, framework pattern questions, or vulnerability-specific education unless the user asks for audit scoping.
