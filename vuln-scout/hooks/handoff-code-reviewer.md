---
name: handoff-code-reviewer
description: Writes typed next-action payload after code-reviewer completes
event: SubagentStop
match_subagent: code-reviewer
---

# Code Reviewer Handoff

When `code-reviewer` stops, read `.claude/findings.json`, compute deterministic counts, and write `.claude/handoff-code-reviewer.json`.

## Branching Rules

- If any `critical` or `high` findings exist, prioritize top findings for `false-positive-verifier`.
- If only `medium` or `low` findings exist, write `suggested_action: "expand-scope"`.
- If no reportable findings exist, write `suggested_action: "report"`.

## Atomic Write

Always delete the prior handoff file first and write via temp file plus rename.

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path

claude = Path(".claude")
handoff = claude / "handoff-code-reviewer.json"
handoff.unlink(missing_ok=True)

findings_path = claude / "findings.json"
if not findings_path.exists():
    print("warning: .claude/findings.json missing; no code-reviewer handoff written")
    raise SystemExit(0)

artifact = json.loads(findings_path.read_text())
findings = [
    f for f in artifact.get("findings", [])
    if f.get("kind") == "finding" and not f.get("suppressed")
]
counts = {
    "critical": sum(1 for f in findings if f.get("severity") == "critical"),
    "high": sum(1 for f in findings if f.get("severity") == "high"),
    "verified": sum(1 for f in findings if f.get("verdict") == "verified"),
    "needs_review": sum(1 for f in findings if f.get("verdict") == "needs_review"),
}
priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
prioritized = sorted(findings, key=lambda f: (priority.get(f.get("severity"), 5), f.get("id", "")))

if counts["critical"] or counts["high"]:
    suggested_action = "false-positive-verifier"
    stable_keys = [f.get("stable_key") for f in prioritized[:5] if f.get("stable_key")]
elif findings:
    suggested_action = "expand-scope"
    stable_keys = []
else:
    suggested_action = "report"
    stable_keys = []

payload = {
    "schema_version": "1.0.0",
    "source": str(findings_path),
    "counts": counts,
    "suggested_action": suggested_action,
    "prioritized_stable_keys": stable_keys,
}
tmp = handoff.with_suffix(".json.tmp")
tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
os.replace(tmp, handoff)

if suggested_action == "false-positive-verifier":
    print("Invoke false-positive-verifier on the prioritized stable keys in .claude/handoff-code-reviewer.json.")
elif suggested_action == "expand-scope":
    print("Suggested action: expand scope before final reporting.")
else:
    print("Suggested action: generate the report.")
PY
```
