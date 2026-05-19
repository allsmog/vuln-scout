---
name: auto-fix
description: Auto-remediate verified findings by generating patches and optionally creating a PR
argument-hint: "[--finding VSCOUT-XXXX] [--all-verified] [--severity critical,high] [--dry-run] [--create-pr]"
allowed-tools:
  - Bash
  - Glob
  - Grep
  - Read
  - Write
  - Task
  - AskUserQuestion
---

# Auto-Fix Security Findings

Automatically generate and apply patches for verified security findings. Uses the `patch-advisor` agent to create context-aware fixes.

## Usage

```
/whitebox-pentest:auto-fix --finding VSCOUT-0003
/whitebox-pentest:auto-fix --all-verified --severity critical,high
/whitebox-pentest:auto-fix --all-verified --dry-run
/whitebox-pentest:auto-fix --all-verified --create-pr
```

## Flags

| Flag | Effect |
|------|--------|
| `--finding` | Fix a specific finding by ID |
| `--all-verified` | Fix all verified findings |
| `--severity` | Filter to specific severities (comma-separated) |
| `--dry-run` | Show proposed patches without applying |
| `--create-pr` | Create a git branch and open a PR with the fixes |

## Safety

- Only operates on `verdict: verified` findings (never patches unverified code)
- Always shows the proposed change before applying (unless `--create-pr` in batch mode)
- Never auto-merges PRs -- always requires human review
- Re-scans after patching to verify the fix eliminated the finding

## Workflow

### Step 1: Load findings

Read `.claude/findings.json`. Filter to `verdict: "verified"` findings matching the specified criteria.

### Step 2: Generate fixes

For each selected finding:
1. Read the vulnerable code context (file + surrounding lines)
2. Use the `patch-advisor` agent's remediation knowledge to generate a fix
3. Show the before/after diff to the user

### Step 3: Apply patches

If not `--dry-run`:
1. Apply the code change using the Write tool
2. Re-run scan on the modified file to verify the finding is resolved
3. If the finding persists, warn the user and revert

### Step 4: Create PR (if `--create-pr`)

```bash
BRANCH="vuln-scout/auto-fix-$(date +%Y%m%d-%H%M%S)"
git checkout -b "$BRANCH"
git add <modified-files>
git commit -m "fix(security): remediate <finding-ids> [vuln-scout auto-fix]"
gh pr create --title "Security: Auto-fix <N> findings" --body "<details>"
```
