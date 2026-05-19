---
name: review-pr
description: Diff-aware PR security review with verified findings and PR comment payload.
---

# Review PR

Use this task skill when the user asks to review this PR, scan a PR, run a diff scan, or check a pull request for vulnerabilities.

## Workflow

1. Identify the base ref, defaulting to `origin/main` when the user does not specify one.
2. Run `/vuln-scout:diff <base>` to produce changed-code findings.
3. Call `code-reviewer` on new or changed findings only.
4. Run `/vuln-scout:verify --from .claude/diff-findings.json` for findings that affect the PR.
5. Call `false-positive-verifier` for high-impact or ambiguous results.
6. Trigger `poc-safety-check` before any dynamic validation or PoC work.
7. Render `/vuln-scout:report --format md` for the PR comment payload.
8. Optionally render `/vuln-scout:report --format bundle` for evidence handoff.

## Produces

- `.claude/diff-findings.json`
- `pr-comment.md`
- optional `bundle.zip`

## When NOT To Trigger

Do not trigger for general git diff questions, style-only code review, STRIDE threat modeling, or framework-specific vulnerability education without a PR review request.
