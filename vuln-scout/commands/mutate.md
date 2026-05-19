---
name: mutate
description: Security mutation testing -- weaken security controls and check if the scanner detects the resulting vulnerability
argument-hint: "[path] [--dry-run] [--format md|json]"
allowed-tools:
  - Bash
  - Glob
  - Read
  - Write
---

# Security Mutation Testing

Identifies security controls (sanitizers, auth middleware, parameterized queries) in your code, temporarily removes them, and checks if the scanning pipeline detects the resulting vulnerability. Undetected mutations represent **detection gaps** in your security tooling.

## Usage

```
/whitebox-pentest:mutate
/whitebox-pentest:mutate src/ --dry-run
```

## Flags

| Flag | Effect |
|------|--------|
| `path` | Directory to scan for mutations (default: current directory) |
| `--dry-run` | List possible mutations without applying them |
| `--format` | Output format: `md` or `json` |

## Mutation Types

| Type | What It Removes |
|------|----------------|
| `remove-parameterization` | SQL parameter binding → string concatenation |
| `remove-auth-middleware` | Authentication middleware from route handlers |
| `remove-csrf-check` | CSRF token validation |
| `enable-shell` | Changes `shell=False` to `shell=True` in subprocess calls |
| `remove-sanitizer` | Input sanitization/validation function calls |
| `remove-rate-limit` | Rate limiting middleware |

## Workflow

### Step 1: Discover mutations

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/run_mutations.py" \
  <path> \
  --dry-run
```

Lists all security-weakening mutations found in the codebase.

### Step 2: Test mutations (unless `--dry-run`)

For each mutation:
1. Apply the mutation (replace the security control with the weakened version)
2. Re-scan the mutated file with Semgrep
3. Check if the mutation was detected as a vulnerability
4. Revert the mutation

### Step 3: Report

- **Detected mutations**: scanner caught the weakened code (good)
- **Undetected mutations**: scanner missed the vulnerability (detection gap)
- **Kill rate**: detected / total (higher is better)

Undetected mutations indicate places where removing a security control would go unnoticed by your scanning pipeline.
