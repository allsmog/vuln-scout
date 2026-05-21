# Full Audit Artifact Contract

The full-audit workflow must write:

- `.claude/audit-plan.md`
- `.claude/review-ledger.json`
- `.claude/audit-report.md`
- `.claude/findings.json`
- `.claude/vuln-scout-state.json`

Findings must follow `vuln-scout/references/findings.schema.json`.
Only unsuppressed entries with `kind: "finding"` affect severity totals,
`--fail-on`, and release gates. Sink-only and framework-pivot leads stay as
`kind: "hotspot"` until reachability and impact are proven.
