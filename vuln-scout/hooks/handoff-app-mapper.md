---
name: handoff-app-mapper
description: Writes typed handoff payload after app-mapper produces app understanding
event: SubagentStop
match_subagent: app-mapper
---

# App Mapper Handoff

When `app-mapper` stops, create a deterministic typed handoff for downstream threat modeling.

## Contract

1. Delete any existing `.claude/handoff-app-mapper.json` before doing new work.
2. Verify `.claude/app-understanding.md` exists. If missing, fail soft with a warning and do not leave a stale handoff file.
3. Validate `.claude/app-understanding.md` has these sections from `APP_UNDERSTANDING_REQUIRED_SECTIONS`:
   - Application Overview
   - Trust Boundaries
   - Entry Points
   - Frameworks and Dependencies
   - High-Risk Modules
4. Extract structured data into `.claude/handoff-app-mapper.json`:
   - `entry_points`
   - `trust_boundaries`
   - `frameworks`
   - `high_risk_modules`
5. Append a `.claude/review-ledger.json` `subjects[]` entry:
   - `subject_type: "app-understanding"`
   - `subject_id: ".claude/app-understanding.md"`
   - `round: 1`
   - `reviewers: ["app-mapper"]`
   - `status: "UNRESOLVED"`
   - `notes: ["[REVIEWER NOTE: unresolved] app understanding ready for threat-modeler handoff"]`
6. Suggest `/vuln-scout:threats` as the next command in one sentence.

## Atomic Write

Use a temp file in `.claude/` and rename it into place:

```bash
python3 - <<'PY'
import json
import os
import re
from pathlib import Path
import sys

sys.path.insert(0, "vuln-scout/scripts")
from prompt_artifacts import default_review_ledger, validate_app_understanding

claude = Path(".claude")
claude.mkdir(exist_ok=True)
handoff = claude / "handoff-app-mapper.json"
handoff.unlink(missing_ok=True)

source = claude / "app-understanding.md"
if not source.exists():
    print("warning: .claude/app-understanding.md missing; no app-mapper handoff written")
    raise SystemExit(0)

text = source.read_text()
errors = validate_app_understanding(text)
if errors:
    print("warning: " + "; ".join(errors))
    raise SystemExit(0)

def section(name):
    pattern = rf"^#+\\s+{re.escape(name)}\\s*$"
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(pattern, line, re.I):
            start = index + 1
            break
    if start is None:
        return []
    values = []
    for line in lines[start:]:
        if line.startswith("#"):
            break
        cleaned = line.strip().lstrip("-*").strip()
        if cleaned:
            values.append(cleaned)
    return values

payload = {
    "schema_version": "1.0.0",
    "source": str(source),
    "entry_points": section("Entry Points"),
    "trust_boundaries": section("Trust Boundaries"),
    "frameworks": section("Frameworks and Dependencies"),
    "high_risk_modules": section("High-Risk Modules"),
}
tmp = handoff.with_suffix(".json.tmp")
tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\\n")
os.replace(tmp, handoff)

ledger_path = claude / "review-ledger.json"
ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else default_review_ledger()
ledger.setdefault("subjects", []).append({
    "subject_type": "app-understanding",
    "subject_id": ".claude/app-understanding.md",
    "round": 1,
    "reviewers": ["app-mapper"],
    "status": "UNRESOLVED",
    "notes": ["[REVIEWER NOTE: unresolved] app understanding ready for threat-modeler handoff"],
})
ledger_tmp = ledger_path.with_suffix(".json.tmp")
ledger_tmp.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\\n")
os.replace(ledger_tmp, ledger_path)
print("Run `/vuln-scout:threats` next to convert app understanding into a threat model.")
PY
```
