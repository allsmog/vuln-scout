---
name: verify-finding
description: Drive a single finding through CPG verification and false-positive triage.
---

# Verify Finding

Use this task skill when the user asks to verify `VSCOUT-*`, asks whether a finding is exploitable, or asks to confirm a specific finding.

## Workflow

1. Locate the finding by ID, stable key, or `file:line` in `.claude/findings.json`.
2. Run `/vuln-scout:trace` on the source-to-sink path.
3. Run `/vuln-scout:verify` for CPG-backed confirmation.
4. Call `false-positive-verifier` when controls, sanitizers, or reachability are unclear.
5. Call `local-tester` only when dynamic validation is explicitly safe and useful.
6. Run `/vuln-scout:propagate` when a confirmed pattern may repeat.
7. Update `.claude/review-ledger.json` with the final verification state.

## Produces

- Updated `.claude/review-ledger.json` entry
- optional trace artifact

## When NOT To Trigger

Do not trigger for broad scans, PR review, generic exploitability education, dangerous-function lists, or CPG query syntax questions that do not name a finding.
