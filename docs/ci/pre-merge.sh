#!/usr/bin/env bash
set -euo pipefail

python3 vuln-scout/scripts/doctor.py --strict
python3 vuln-scout/scripts/scan_orchestrator.py . --profile quick --format sarif --output findings.sarif
python3 vuln-scout/scripts/report.py .claude/findings.json --fail-on high
