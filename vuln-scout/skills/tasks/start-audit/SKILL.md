---
name: start-audit
description: Guided first-run security audit: doctor, scope, threats, scan, verify, report.
---

# Start Audit

Use this task skill when the user asks to start a security audit, audit this repo, perform a security review of a codebase, or review this codebase for vulnerabilities.

## Workflow

1. Run `python3 vuln-scout/scripts/doctor.py --strict` or ask the user to address missing quick-profile dependencies.
2. Trigger `session-init` and `large-codebase-check` hooks when the target is a repo or monorepo.
3. Run `/vuln-scout:scope` to establish boundaries and write `.claude/audit-plan.md`.
4. Call `app-mapper`, then `/vuln-scout:threats`, then `threat-modeler`.
5. Run `/vuln-scout:scan --profile quick` first; use `deep` only when optional analyzers are installed or requested.
6. Call `code-reviewer` on prioritized findings.
7. Run `/vuln-scout:verify` per finding that needs confirmation.
8. Finish with `/vuln-scout:report --format bundle --output evidence-bundle`.

## Produces

- `.claude/audit-plan.md`
- `.claude/review-ledger.json`
- `.claude/findings.json`
- `report.html`
- `evidence-bundle/`

## When NOT To Trigger

Do not trigger for knowledge-only questions about STRIDE, OWASP, dangerous functions, framework patterns, compliance mapping, exploit techniques, or vulnerability classes. Let those knowledge skills answer directly unless the user asks to audit a target.
