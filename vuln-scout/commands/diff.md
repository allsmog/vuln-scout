---
name: diff
description: Compare security posture between two git refs to find new/fixed vulnerabilities and track regression
argument-hint: "<base-ref> [<head-ref>] [--tools semgrep] [--format md|json] [--fail-on-regression]"
allowed-tools:
  - Bash
  - Glob
  - Read
  - Write
---

# Differential Security Analysis

Compare security findings between two git refs. Shows new vulnerabilities introduced, vulnerabilities fixed, and severity changes.

## Usage

```
/whitebox-pentest:diff HEAD~5
/whitebox-pentest:diff v1.0.0 v2.0.0
/whitebox-pentest:diff main feature/auth --fail-on-regression
```

## Flags

| Flag | Effect |
|------|--------|
| `base-ref` | Git ref to compare against (required) |
| `head-ref` | Git ref to compare (default: HEAD) |
| `--tools` | Scanning tools to use (default: semgrep) |
| `--format` | Output format: `md` or `json` |
| `--fail-on-regression` | Exit 2 if regression score > 0 (more new findings than fixed) |

## Workflow

### Step 1: Scan baseline

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/run_diff.py" \
  --base <base-ref> \
  --head <head-ref> \
  --tools <tools> \
  --project-root .
```

The script handles git checkout, scanning both refs, and computing the diff.

### Step 2: Display results

Show the diff report:
- **New findings**: vulnerabilities introduced since the baseline
- **Fixed findings**: vulnerabilities that no longer appear
- **Changed findings**: same location but different severity/verdict
- **Regression score**: positive = worse, negative = better
- **New/removed endpoints**: attack surface changes

### Step 3: Exit code

- `0`: no regression (fixed >= new, or `--fail-on-regression` not set)
- `2`: regression detected (with `--fail-on-regression`)
