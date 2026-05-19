---
name: create-rule
description: Create a custom Semgrep detection rule from a confirmed vulnerability pattern
argument-hint: "<finding-id | file:line> [--output dir] [--test]"
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Grep
---

# Create Custom Detection Rule

Generate a Semgrep YAML rule from a confirmed vulnerability pattern. The rule captures the anti-pattern so future scans detect similar issues across the codebase.

## Usage

```
/whitebox-pentest:create-rule VSCOUT-0003
/whitebox-pentest:create-rule src/api/users.ts:42
/whitebox-pentest:create-rule VSCOUT-0003 --output .semgrep/rules/ --test
```

## Flags

| Flag | Effect |
|------|--------|
| `finding-id` | Finding ID from `.claude/findings.json` to generate a rule for |
| `file:line` | Alternative: specify the vulnerable code location directly |
| `--output` | Directory to save the rule (default: `.claude/custom-rules/`) |
| `--test` | Run the generated rule against the codebase to verify it works |

## Workflow

### Step 1: Extract the vulnerability pattern

If a finding ID is provided, load it from `.claude/findings.json` and read the evidence code excerpts.
If a file:line is provided, read the surrounding code context.

Identify:
- The **dangerous sink** (the function call that is vulnerable)
- The **unsafe pattern** (how user input reaches the sink)
- The **language** of the code

### Step 2: Generate the Semgrep rule

Create a YAML rule with:
- `id`: `vuln-scout.custom.<descriptive-name>`
- `pattern` or `pattern-either`: captures the anti-pattern
- `pattern-not`: excludes safe variants (parameterized queries, etc.)
- `message`: explains the vulnerability and how to fix it
- `severity`: ERROR for exploitable, WARNING for potential
- `languages`: detected from the source file
- `metadata`: `category: security`, `cwe`, `confidence`
- `fix` (optional): auto-fix pattern if applicable

### Step 3: Test the rule (if `--test`)

```bash
semgrep --config <generated-rule-file> --json <target-path>
```

Verify:
- The rule catches the original finding
- False positive rate is acceptable (< 20%)
- The rule works on the correct language

### Step 4: Save

Write the rule to the output directory. Report the file path so it can be committed and used in future scans.

The scan orchestrator's `rule_generator.py` will automatically pick up rules from `.claude/custom-rules/` on subsequent scans.
