# First Run

This five-minute path verifies the local runtime, scans the bundled vulnerable app, and renders an HTML report.

```bash
python3 vuln-scout/scripts/doctor.py --strict
python3 vuln-scout/scripts/scan_orchestrator.py demo/vulnerable-app --profile quick --output /tmp/vuln-scout-demo-findings.json
python3 vuln-scout/scripts/report.py /tmp/vuln-scout-demo-findings.json --format html --output report.html
```

The quick profile must produce exactly four demo findings:

- high: SQL injection
- high: command injection
- medium: XSS
- medium: open redirect

Claude Code users can run the canonical workflow directly:

```text
/vuln-scout:full-audit demo/vulnerable-app
```
