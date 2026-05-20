# Org Memory Layout

VulnScout writes organization-specific memory inside the audited repository:

```text
.vuln-scout/org-memory/
  accepted-suppressions.yaml
  confirmed-findings.yaml
  custom-rules/
    semgrep/
    joern/
  review-patterns.yaml
  manifest.json
```

The files are YAML where human review is expected and JSON only for the manifest:

- `accepted-suppressions.yaml` records ratified suppressions with rationale, reviewer, and stable keys.
- `confirmed-findings.yaml` records canonical vulnerability patterns the organization wants promoted.
- `custom-rules/semgrep/` contains generated Semgrep rules with `schema: vuln-scout.org.v1`.
- `custom-rules/joern/` is reserved for future CPGQL rules.
- `review-patterns.yaml` records deterministic demotion hints from repeated human-reviewed false positives.
- `manifest.json` records compiler version, privacy mode, update timestamp, and file hashes.

Default plugin behavior treats `.vuln-scout/org-memory/` as local, private state unless a repository owner explicitly opts in to committing it.
