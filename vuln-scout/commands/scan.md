---
name: scan
description: "[beta] Run quick, deep, or audit scan profiles and emit a shared findings artifact"
argument-hint: "[path] [--profile quick|deep|audit] [--tools semgrep,codeql,joern] [--rules ruleset] [--workspace name] [--since-commit sha] [--diff-base ref] [--exclude patterns] [--suppressions path] [--format json|sarif|md|html|pr-comment|badge] [--fail-on severity] [--output file] [--json] [--secrets] [--require-tools] [--custom-rules] [--extended-detectors] [--incremental] [--generate-pocs] [--no-filter] [--no-semantic-analysis]"
allowed-tools:
  - Bash
  - Glob
  - Read
  - Write
  - TodoWrite
---

# Security Scan

Run automated static analysis and write the results to `.claude/findings.json`.

## Flags

| Flag | Effect |
|------|--------|
| `--profile` | Use `quick` (local deterministic rules), `deep` (installed analyzers), or `audit` (deterministic baseline for Claude-driven review) |
| `--tools` | Run `semgrep`, `codeql`, `joern`, or a comma-separated combination |
| `--rules` | Semgrep ruleset override |
| `--workspace` | Resolve a monorepo workspace before scanning |
| `--since-commit` | Scan files changed since a commit SHA |
| `--diff-base` | Backward-compatible alias for diff scans against a git ref |
| `--exclude` | Extra exclusions |
| `--suppressions` | Apply `.vuln-scout-ignore` after aggregation |
| `--format` | Emit `json`, `sarif`, `md`, `html`, `pr-comment`, or `badge` at the end |
| `--fail-on` | Exit `2` when unsuppressed `finding` entries exist at or above the severity |
| `--output` | Save the final emitted artifact to a file. In Claude plugin workflows, resolve relative output paths under the target workspace when the scan target is not the current directory. |
| `--json` | Shortcut for `--format json` |
| `--secrets` | Run secret scanning (gitleaks/truffleHog) alongside static analysis |
| `--require-tools` | Fail if any requested tool is unavailable |
| `--custom-rules` | Generate target-specific Semgrep rules in addition to profile rules |
| `--extended-detectors` | Run regex-based VulnScout detectors in addition to scanner tools |
| `--incremental` | Use file-hash cache to skip unchanged files |
| `--generate-pocs` | Generate proof-of-concept scripts for verified findings |
| `--no-filter` | Keep low-confidence Semgrep audit results as hotspots instead of dropping them |
| `--no-semantic-analysis` | Compatibility flag for callers that share `/full-audit` options; the standalone CLI does not run a Claude semantic analysis phase |

The `audit` profile does not invoke Claude during the scan phase; semantic review is performed afterward by `/vuln-scout:verify` or `/vuln-scout:full-audit`.

## Shared artifact contract

All tool branches must write the same artifact shape to `.claude/findings.json`.

Source of truth:
- `vuln-scout/references/findings.schema.json`

Required top-level fields:
- `schema_version`
- `scan_id`
- `project_path`
- `completed_at`
- `source_tool`
- `summary`
- `findings`

Required finding fields:
- `id`
- `stable_key`
- `kind`
- `severity`
- `type`
- `title`
- `file`
- `line`
- `verdict`
- `confidence`
- `source_tool`
- `message`
- `evidence`

### `kind` rules

- `finding`: reportable issue; contributes to severity totals
- `hotspot`: risky sink or framework pivot; does **not** contribute to severity totals

If a scan branch only proves that a dangerous pattern exists, record a `hotspot`.

## Step 1: Resolve scope

Default target is the current directory.

Static scans always run against a **source directory**. Saved `.claude/scope-*.md` snapshots are useful context for Claude-side review and threat modeling, but they are not direct input to Semgrep, Joern, or CodeQL.

When invoking `scripts/scan_orchestrator.py` from this command and the user
supplies a scan target other than `.`, convert relative `--output` paths to live
under that target. For example:

```bash
python3 /path/to/vuln-scout/scripts/scan_orchestrator.py /tmp/app \
  --profile quick \
  --output /tmp/app/.claude/plugin-findings.json
```

Do not write relative output artifacts into the plugin repository unless the
plugin repository is the explicit scan target.

If `--since-commit <sha>` is passed:

```bash
CHANGED_FILES=$(git diff --name-only <sha>...HEAD -- [path])
printf '%s\n' "$CHANGED_FILES" > /tmp/vuln-scout-targets.txt
```

If `--diff-base <ref>` is passed:
- treat it as an alias for `--since-commit <ref>`

## Step 2: Apply baseline exclusions

Always exclude:

```bash
node_modules
vendor
dist
build
coverage
__pycache__
*.min.js
*.map
```

## Step 3: Run selected tool branches

### Semgrep branch

```bash
semgrep --config "${RULESET:-vuln-scout/rules/vuln-scout-local.yml}" --json [targets...]
```

Classify:
- direct Semgrep matches with actionable evidence -> `finding`
- framework pivots and sink-only matches -> `hotspot`

### CodeQL branch

Create a database for each detected language, then analyze it explicitly.

```bash
codeql database create .codeql-db --language=<language> --source-root [path]
codeql database analyze .codeql-db \
  <language>-security-and-quality.qls \
  --format=sarif-latest \
  --output /tmp/codeql-results.sarif
```

Map CodeQL results into the shared findings artifact:
- taint or data-flow backed results -> `finding`
- broad query matches without exploit proof -> `hotspot`

### Joern branch

Joern is verification-oriented, so its standalone scan branch should be conservative.

1. Generate or reuse a cached CPG keyed by target hash plus detected language.
2. Run language-aware hotspot queries or batch verification.

```bash
TARGET_HASH=$(git ls-files -z [path] | xargs -0 shasum | shasum | awk '{print $1}')
LANGUAGE=<detected-language>
CPG_FILE=".joern/${TARGET_HASH}-${LANGUAGE}.cpg"

if [ ! -f "$CPG_FILE" ]; then
  joern-parse [path] --output "$CPG_FILE"
fi

joern --script "${CLAUDE_PLUGIN_ROOT}/scripts/joern/batch-verify.sc" \
  --params cpgFile="$CPG_FILE",findingsFile=".claude/findings.json"
```

Classification:
- verified source-to-sink proof -> `finding`
- sink or pivot without exploit proof -> `hotspot`
- unsupported language -> `verdict: na_cpg`

## Step 4: Merge and normalize

After all selected branches:

1. Deduplicate on `stable_key`
2. Preserve the strongest evidence block
3. Recompute `summary`
4. Apply suppressions if `--suppressions` is provided

Severity summary rules:
- count only unsuppressed entries where `kind == "finding"`
- do not count `hotspot` entries in `critical/high/medium/low/info`

## Step 5: Write `.claude/findings.json`

Use the shared schema in `vuln-scout/references/findings.schema.json`.

Example:

```json
{
  "schema_version": "1.2.0",
  "scan_id": "uuid-v4",
  "project_path": ".",
  "completed_at": "2026-03-24T00:00:00Z",
  "source_tool": "multi",
  "summary": {
    "total_findings": 2,
    "total_hotspots": 1,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "id": "VSCOUT-001",
      "stable_key": "semgrep:sql-injection:src/api/users.ts:42",
      "kind": "finding",
      "severity": "critical",
      "type": "sql-injection",
      "title": "SQL injection in getUser",
      "file": "src/api/users.ts",
      "line": 42,
      "verdict": "unverified",
      "confidence": "high",
      "source_tool": "semgrep",
      "message": "User-controlled input is interpolated into SQL.",
      "evidence": [
        {
          "type": "code",
          "label": "interpolated query",
          "path": "src/api/users.ts",
          "line": 42,
          "excerpt": "db.query(`SELECT ... ${userId}`)"
        }
      ]
    }
  ]
}
```

## Step 5.5: Claude Semantic Analysis (unless `--no-semantic-analysis`)

After writing `findings.json`, use Claude's reasoning to both verify static findings AND discover vulnerabilities the tools missed.

### Phase A: Verify static tool findings

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/prepare_claude_batch.py" \
  .claude/findings.json \
  --output .claude/claude-analysis-batch.json
```

If the batch is non-empty, read `.claude/claude-analysis-batch.json`. For each entry:
1. Read the `prompt` field (structured analysis question about a specific finding)
2. **Read the actual source file** referenced in the finding (use Read tool)
3. Reason about source controllability, sanitizer effectiveness, and exploitability
4. Respond with the JSON verdict block as specified in the prompt
5. Store as `{"finding_id": "...", "response_text": "..."}` in a results array

Write all results to `.claude/claude-analysis-results.json`, then apply:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/apply_claude_analysis.py" \
  .claude/findings.json \
  .claude/claude-analysis-results.json
```

### Phase B: Manual code review (find what tools missed)

The static pipeline provides a map of the codebase. Use it to prioritize which files to read:

1. **Read `.claude/findings.json`** -- the `entry_points` array lists every HTTP endpoint with auth status. Start with unauthenticated endpoints.
2. **For each entry point file**, use Read to read the source code. Trace user input to dangerous sinks. Check for missing auth, IDOR, CSRF, stored XSS, file inclusion.
3. **Check files with static findings** -- read the surrounding code for context. A file with one vuln often has more.
4. **Apply the `dangerous-functions` skill knowledge** -- search for sinks the static tools missed (language-specific patterns).

Write any new findings to `.claude/manual-findings.json` as:
```json
[{"type": "sql-injection", "file": "path", "line": N, "verdict": "verified", "kind": "finding", "reasoning": "..."}]
```

**Do not skip this phase.** Static tools miss business logic flaws, cross-file data flows, missing security controls, and framework-specific issues. Your manual review is what makes VulnScout different from every other scanner.

## Step 6: Emit requested format

### `--format json` or `--json`
- emit `.claude/findings.json`

### `--format sarif`

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/findings_to_sarif.py" \
  .claude/findings.json \
  --suppressions <path> \
  --output <output_file>
```

### `--format md`
- emit a compact markdown summary

## Exit codes

- `0`: success, no blocking unsuppressed findings at or above `--fail-on`
- `1`: tool failure, parse failure, or schema mismatch
- `2`: unsuppressed `finding` entries exist at or above `--fail-on`

## Notes

- `hotspot` is the default when the scan only proves a risky pattern or audit pivot.
- Use `/vuln-scout:verify` to promote or dismiss `hotspot` and `unverified` entries.
- Keep `source_tool` and `evidence` populated on every finding entry.
