---
name: org-memory-compile
description: "[experimental] Compile human-reviewed scan history into local organization memory"
argument-hint: "[--privacy open|hashed|strict] [--dry-run] [--allow-commit] [--force]"
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
---

# Compile Org Memory

Compile repeated human-reviewed verdicts into `.vuln-scout/org-memory/` so future scans can reuse organization-specific suppressions, confirmed patterns, and reviewer heuristics.

## Usage

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/org_memory_compiler.py" \
  --project-root . \
  --privacy hashed
```

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/org_memory_compiler.py" \
  --project-root . \
  --privacy strict \
  --dry-run
```

## Inputs

- `.claude/scan-history/*.json`
- `.claude/rule-stats.json`
- `.claude/review-ledger.json`
- Human-reviewed findings where `verdict` is `verified` or `false_positive`

## Outputs

- `.vuln-scout/org-memory/accepted-suppressions.yaml`
- `.vuln-scout/org-memory/confirmed-findings.yaml`
- `.vuln-scout/org-memory/custom-rules/semgrep/*.yaml`
- `.vuln-scout/org-memory/review-patterns.yaml`
- `.vuln-scout/org-memory/manifest.json`

## Flags

| Flag | Effect |
|------|--------|
| `--privacy open` | Store paths and excerpts verbatim |
| `--privacy hashed` | Store SHA-256 hashes for paths and excerpts |
| `--privacy strict` | Store only rule IDs, verdict counts, and CWE metadata |
| `--dry-run` | Print proposed memory without writing files |
| `--force` | Allow overwriting strict memory with open privacy |
| `--allow-commit` | Do not add `.vuln-scout/org-memory/` to `.gitignore` |

## Review Policy

Only human-reviewed provenance can graduate into org memory:

- Confirmed findings require at least 3 verified samples and a verified rate of at least 50%.
- Accepted suppressions require the same stable key to be manually suppressed at least twice.
- Demotion hints reuse `MIN_SAMPLES_FOR_DEMOTE` from `feedback_collector.py` to avoid single-sample overfit.

By default the compiler adds `.vuln-scout/org-memory/` to the target repository `.gitignore`. Use `--allow-commit` only when the repository owner has decided the generated memory is safe to commit.
