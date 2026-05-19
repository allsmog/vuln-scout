---
name: package-evidence
description: Bundle findings, reports, audit plan, and ledger into one evidence zip.
---

# Package Evidence

Use this task skill when the user asks to package evidence, export a bundle, create a deliverable, or share findings.

## Workflow

1. Confirm `.claude/findings.json` exists and validates.
2. Run `/vuln-scout:report --format sarif`.
3. Run `/vuln-scout:report --format html`.
4. Run `/vuln-scout:report --format bundle`.
5. Confirm the bundle contains `findings.json`, `findings.sarif`, `vex.json`, `attestation.json`, `report.html`, and `README.md`.

## Produces

- `evidence-bundle.zip`

## When NOT To Trigger

Do not trigger for starting a new audit, investigating a single finding, compliance mapping, report formatting preferences, or questions about evidence theory without a deliverable request.
