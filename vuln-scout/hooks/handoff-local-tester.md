---
name: handoff-local-tester
description: Graduates dynamically verified findings after local-tester completes
event: SubagentStop
match_subagent: local-tester
---

# Local Tester Handoff

When `local-tester` stops, read `.claude/local-test-results.json`, update successful PoC findings in `.claude/findings.json`, and write `.claude/handoff-local-tester.json`.

## Rules

For every successful result with a `stable_key`:

- Set `verification_level = 4`
- Set `dynamic_verified = true`
- Set `verdict = "verified"`
- Set `confidence = "verified"`
- Set `trust_metadata.provenance.origin = "dynamic_verified"`
- Set `trust_metadata.exploitability_status = "confirmed"`

## Atomic Write

Delete the prior handoff file first. Write both findings and handoff through temp files plus rename.

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, "vuln-scout/scripts")
from migrate_artifact import build_trust_metadata

claude = Path(".claude")
handoff = claude / "handoff-local-tester.json"
handoff.unlink(missing_ok=True)

results_path = claude / "local-test-results.json"
findings_path = claude / "findings.json"
if not results_path.exists() or not findings_path.exists():
    print("warning: local test results or findings missing; no local-tester handoff written")
    raise SystemExit(0)

results = json.loads(results_path.read_text())
artifact = json.loads(findings_path.read_text())
successful = {
    item.get("stable_key")
    for item in results.get("results", results if isinstance(results, list) else [])
    if item.get("stable_key") and (item.get("ok") is True or item.get("status") in {"passed", "success", "confirmed"})
}

ready = []
for finding in artifact.get("findings", []):
    if finding.get("stable_key") not in successful:
        continue
    finding["dynamic_verified"] = True
    finding["verification_level"] = 4
    finding["verdict"] = "verified"
    finding["confidence"] = "verified"
    finding["trust_metadata"] = build_trust_metadata(finding)
    finding["trust_metadata"]["provenance"]["origin"] = "dynamic_verified"
    finding["trust_metadata"]["exploitability_status"] = "confirmed"
    ready.append(finding.get("stable_key"))

findings_tmp = findings_path.with_suffix(".json.tmp")
findings_tmp.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
os.replace(findings_tmp, findings_path)

payload = {
    "schema_version": "1.0.0",
    "source": str(results_path),
    "ready_for_poc_developer": ready,
}
tmp = handoff.with_suffix(".json.tmp")
tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
os.replace(tmp, handoff)
print("Local tester handoff written for stable keys ready for poc-developer.")
PY
```
