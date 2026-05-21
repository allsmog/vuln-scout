# VulnScout 5-Minute Demo Target

This tiny app is intentionally vulnerable. Use it to validate that VulnScout can
run the deterministic `quick` scan profile without Semgrep registry access.

```bash
python3 ../../vuln-scout/scripts/doctor.py --strict
python3 ../../vuln-scout/scripts/scan_orchestrator.py . --profile quick --format md --output report.md
python3 ../../vuln-scout/scripts/report.py .claude/findings.json --format html --output report.html
```

Expected quick-profile findings:

| Rule | Severity | File |
|------|----------|------|
| `vuln-scout.local.python.sql-fstring-execute` | high | `app.py` |
| `vuln-scout.local.python.shell-true` | high | `app.py` |
| `vuln-scout.local.javascript.inner-html-assignment` | medium | `public/app.js` |
| `vuln-scout.local.javascript.express-open-redirect` | medium | `server.js` |

The exact `stable_key` values are intentionally not documented because they are
derived from normalized finding locations.
