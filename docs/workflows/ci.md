# CI Workflow

Use the stable quick profile for deterministic CI smoke scans and fail on blocking severities.

```yaml
name: VulnScout

on:
  pull_request:
  push:
    branches: [main]

jobs:
  vuln-scout:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python3 vuln-scout/scripts/doctor.py --strict
      - run: python3 vuln-scout/scripts/scan_orchestrator.py . --profile quick --format sarif --output findings.sarif --fail-on high
      - run: python3 vuln-scout/scripts/report.py .claude/findings.json --format bundle --output evidence-bundle.zip
      - uses: actions/upload-artifact@v4
        with:
          name: vuln-scout-evidence
          path: |
            findings.sarif
            evidence-bundle.zip
```
