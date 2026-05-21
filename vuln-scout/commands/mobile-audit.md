---
name: mobile-audit
description: "[beta] Audit a decompiled Android target — scans jadx_out/sources + apktool_out together and merges findings"
argument-hint: "<target> [--profile quick|deep|audit] [--output FILE] [--suppressions FILE] [--format json|md] [--diff-against FILE] [--top-chains N] [--no-chains] [--list-chain-patterns] [--list-chain-patterns-format text|json] [--validate-suppressions FILE]"
allowed-tools:
  - Bash
  - Glob
  - Read
  - Write
  - TodoWrite
---

# Mobile Audit

End-to-end mobile audit driver for Android targets. Most Android bug-bounty
work involves a decompiled APK that's been split into two directories:

| Directory | Holds | What we scan for |
|---|---|---|
| `jadx_out/sources/` | Java/Kotlin pseudocode | WebView JS injection, remote-controlled URLs, insecure crypto, sensitive SharedPreferences, hardcoded secrets, @JavascriptInterface exposure |
| `apktool_out/` | AndroidManifest.xml, res/xml/network_security_config.xml, native libs | Exported components, NSC pinning gaps, debuggable builds, allowBackup, deeplink hosts |

Pointing the regular `/vuln-scout:scan` at the target root misses one or the
other. This command auto-discovers both, runs the orchestrator on each, and
writes a single merged `findings.json` to the target's `.claude/`.

## Usage

```
/vuln-scout:mobile-audit ~/bug-bounty/<target>
```

```
/vuln-scout:mobile-audit ~/bug-bounty/target --profile deep --output /tmp/out.json
```

```
# Apply a previously-triaged FP allowlist
/vuln-scout:mobile-audit ~/bug-bounty/target --suppressions ~/bug-bounty/target/.vuln-scout-ignore
```

The driver also auto-discovers `<target>/.vuln-scout-ignore` if `--suppressions`
is not given.

```
# Limit CI output to the two highest-impact chains
/vuln-scout:mobile-audit ~/bug-bounty/target --top-chains 2
```

```
# Ultra-quick smoke scan — skip chain detection entirely
/vuln-scout:mobile-audit ~/bug-bounty/target --no-chains
```

```
# Discover the chain pattern slugs to use in .vuln-scout-ignore rules
/vuln-scout:mobile-audit --list-chain-patterns
```

```
# Same, but emit JSON for tooling integration
/vuln-scout:mobile-audit --list-chain-patterns --list-chain-patterns-format json
```

```
# Lint a .vuln-scout-ignore file — warns on unknown chain slugs,
# invalid severity levels, and empty patterns. Exits non-zero on issues.
# Accepts either a file path or a target directory (auto-finds the
# .vuln-scout-ignore inside it).
/vuln-scout:mobile-audit --validate-suppressions ~/bug-bounty/target/.vuln-scout-ignore
/vuln-scout:mobile-audit --validate-suppressions ~/bug-bounty/target
```

`.vuln-scout-ignore` supports finding stable_keys, severity floors, file globs, and chain-pattern rules:
```
# Per-finding suppression
vscout:abcd1234ef56  legacy code, accepted risk

# Severity floor — silences everything at-or-below the given level
severity:low  CI only fails on medium+ findings

# Path-glob suppression (fnmatch syntax)
file:*/test/*  test code, not shipped
file:build/generated/*  auto-generated stubs

# Suppress an entire chain class (exact)
chain_pattern:mobile-debuggable-secret  test build only

# Suppress a chain family (wildcard — fnmatch globs supported)
chain_pattern:ios-*  Android-only target
chain_pattern:*-webview-*  silence all WebView chains
```

Priority order (first match wins): stable_key → legacy_key → severity → file-glob → chain_pattern.

## What it produces

`<target>/.claude/findings.json` containing:

- All `vuln-class-detector` findings from the Java/Kotlin code tree.
- All manifest / network-security-config / resource findings from the apktool
  tree.
- A merged `summary` (counts unified across both trees, plus `total_chains`,
  `chains_by_pattern`, `chains_by_severity`, `suppressed_chains`).
- A `chains[]` array — each chain carries `pattern`, `severity`, `confidence`,
  `cvss_estimate`, `cwes`, `stable_key`.
- Findings carry `chain_id` (primary), `chain_pattern`, `chain_role`, plus a
  `chain_participations[]` list for multi-chain findings, and aggregated
  `chain_cwes`.
- A `merged_from` array recording which intermediate artifacts were combined.

Hotspots and findings are deduplicated by `stable_key` (falling back to
`file:line:type` when missing), and overlapping evidence is appended.

### Troubleshooting

If a chain pattern crashes during a scan, the failure is captured in
`scan_metadata.chain_pattern_failures = [{pattern, error}]` rather than
killing the whole pipeline. Greppable log marker: `[chain-pattern-failure]`.
The same audit-trail field exists for sub-detector failures via
`tool_statuses['vuln-class-detector'].detector_failures` (log marker
`[detector-failure]`).

## Execution

The command shells out to `vuln-scout/scripts/mobile_scan.py`. Re-run as
needed; intermediate artifacts are temporary, only the merged result is
persisted.

```bash
python3 vuln-scout/scripts/mobile_scan.py "$ARG_TARGET" \
  --profile "${ARG_PROFILE:-quick}" \
  ${ARG_OUTPUT:+--output "$ARG_OUTPUT"}
```

The driver:

1. Probes the target root for the conventional sub-paths
   (`jadx_out/sources`, `jadx_out2/sources`, `jadx/sources`,
   `decompiled/sources`, `android-decompiled/sources`, `src/main/java`)
   and the resource roots (`apktool_out`, `apktool`, `res`).
2. Runs `scan_orchestrator.py --extended-detectors --tools api-spec --format
   json` on each.
3. Merges results into a single artifact obeying the standard
   `references/findings.schema.json` shape.

## When **not** to use this

If you only have a Java/Kotlin source tree (no apktool output), use the
regular `/vuln-scout:scan` or `/vuln-scout:full-audit`. The mobile-audit
driver is shape-specific — it expects the decompilation convention.

## Findings contract

Same shared schema as the rest of VulnScout — see
`vuln-scout/references/findings.schema.json`. Required finding fields
remain `id`, `stable_key`, `kind`, `severity`, `type`, `title`, `file`,
`line`, `verdict`, `confidence`, `source_tool`, `message`, `evidence`.
