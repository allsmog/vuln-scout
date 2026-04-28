# VulnScout Improvement Design: Detection Engine + Output Differentiation

**Date:** 2026-03-25
**Status:** Approved (spec review passed, pending user review)
**Goal:** Fix detection quality (reduce FP from 30-40% to <12%, find 30-50% more real vulns) and create shareable, differentiating output (HTML report, attack chain visualization, rich SARIF).

---

## Context

VulnScout has expert-level pentesting knowledge (27 skills, 7 agents) but the automated scan pipeline underdelivers:

- `semgrep --config auto` with zero tuning produces 30-40% false positives
- Joern verification silently fails on Python/Java/Go/PHP/Ruby (only works for JS/TS)
- CodeQL integration is a stub returning `[]`
- Framework-specific knowledge in skills is unused during automated scanning
- Output is a flat markdown list with 200-char code excerpts -- attack chains (the biggest differentiator) are invisible

The improvements span two pillars: **Pillar A** (detection engine) and **Pillar B** (output/differentiation).

---

## Pillar A: Detection Engine Upgrades

### Phase A1: Semgrep Confidence Filtering

**Problem:** `semgrep --config auto` returns everything including low-confidence audit rules. No filtering.

**Changes:**

**`scripts/tool_runners/semgrep_runner.py`:**
- Add `--severity WARNING` minimum to drop INFO-level noise
- Implement three-tier classification:
  - **Tier 1 (finding):** Taint-mode results (`dataflow_trace` present) OR metadata `subcategory: ["vuln"]` AND `confidence: HIGH`
  - **Tier 2 (hotspot):** Pattern-only matches, or `confidence: LOW/MEDIUM` without CWE tags
  - **Tier 3 (drop):** `subcategory: ["audit"]` AND `confidence: LOW` AND no CWE
- Propagate Semgrep's `confidence` field into findings instead of hardcoding

**`scripts/run_semgrep.py`:**
- Apply same confidence filtering to standalone script
- Add subcategory check to `classify_kind` function

**Behavioral change:** Tier 3 dropping is more aggressive than current behavior. Add a `--no-filter` flag to opt into raw Semgrep output for users who want all results.

**`run_semgrep.py` divergence:** The standalone `run_semgrep.py` has a simpler `classify_kind` than `semgrep_runner.py`. Unify the filtering logic into a shared function in `artifact_utils.py` to avoid maintaining two divergent implementations.

**Impact:** ~15-20% false positive reduction.

---

### Phase A2: Fix Joern Verification for All Languages

**Problem:** Source patterns in `common.sc` use `cpg.fieldAccess.code(...)` which only matches JS/TS patterns. Python/Java/Go/PHP/Ruby use different CPG representations (method calls, annotations, globals).

**Changes:**

**`scripts/joern/common.sc`:**

Add `Sources.callPattern()` for method-call-based sources:
```scala
private val callPatterns = Map(
  Languages.python -> Map(
    "http" -> "^(get|getlist|to_dict|get_json)$"
  ),
  Languages.java -> Map(
    "http" -> "^(getParameter|getHeader|getQueryString|getRequestURI|getPathInfo|getInputStream|getReader)$"
  ),
  Languages.go -> Map(
    "http" -> "^(FormValue|PostFormValue|ParseForm|ParseMultipartForm|ReadAll|ReadBody)$"
  ),
  Languages.php -> Map(
    "http" -> "^(input|get|post|request|cookie|header|query|all|file)$"
  ),
  Languages.ruby -> Map(
    "http" -> "^(params|permit|require|fetch)$"
  )
)
```

Add `Sources.globalAccessPattern()` for Python Flask globals and PHP superglobals.

**Also:** Add Ruby to the `supportedLanguages` default case in `common.sc` (lines 79-88), which currently only lists JS, TS, Python, Go, Java, PHP. Without this, Ruby findings get `NA_CPG` verdicts.

Add language-specific sink patterns:
- Python SQL: `execute|executemany|raw|extra|cursor`
- Java SQL: `executeUpdate|executeQuery|createQuery|createNativeQuery`
- Go SQL: `QueryRow|Exec|QueryContext|ExecContext`
- PHP SQL: `mysql_query|mysqli_query|pg_query`
- Ruby SQL: `find_by_sql|where|joins|having|select`

Add helper function `findAttackerFlows(sink, language, focus)` with three-tier resolution:
```scala
def findAttackerFlows(sink: Call, language: String, focus: String = "http"): List[AnyRef] = {
  val paramSources = cpg.parameter.name(Sources.parameterPattern(language, focus))
  val fieldSources = cpg.fieldAccess.code(Sources.fieldPattern(language, focus))
  val callSources = cpg.call.name(Sources.callPattern(language, focus))
  val globalSources = cpg.identifier.name(Sources.globalAccessPattern(language))
  (sink.argument.reachableBy(paramSources).l
    ++ sink.argument.reachableBy(fieldSources).l
    ++ sink.argument.reachableBy(callSources).l
    ++ sink.argument.reachableBy(globalSources).l).distinct
}
```

**The 10 verify scripts that use the two-tier parameterFlows/fieldFlows pattern** (verify-sqli, verify-xss, verify-ssrf, verify-cmdi, verify-path, verify-ssti, verify-deser, verify-xxe, verify-ldap, verify-generic). Legacy Solidity-specific scripts are not routed by VulnScout; Solidity verification is Slither-owned and Joern returns `na_cpg`.

Replace the two-tier source resolution pattern:
```scala
// OLD (JS/TS only):
val sources = cpg.parameter.name(Sources.parameterPattern(language, "http"))
val parameterFlows = sink.argument.reachableBy(sources).l
val fieldFlows = sink.argument.reachableBy(cpg.fieldAccess.code(Sources.fieldPattern(language, "http"))).l
val anyFlows = if (parameterFlows.nonEmpty) parameterFlows else fieldFlows
```

With the unified helper:
```scala
// NEW (all languages):
val anyFlows = findAttackerFlows(sink, language, "http")
```

**Impact:** Joern verification works for all 9 languages instead of 2. Eliminates systematic false negatives on non-JS codebases.

---

### Phase A3: Framework-Aware Semgrep Rules

**Problem:** Skills contain expert-level framework knowledge (Django, Rails, Spring, Flask, Next.js) but the scan pipeline ignores it.

**Changes:**

**New file: `scripts/framework_detector.py`:**
- Detect frameworks from package manifests (`package.json`, `requirements.txt`, `Gemfile`, `pom.xml`, `go.mod`, `composer.json`)
- Return detected frameworks with their Semgrep rulesets:
  ```python
  FRAMEWORK_RULESETS = {
      "flask": ["p/flask", "p/python"],
      "django": ["p/django", "p/python"],
      "express": ["p/express", "p/nodejs"],
      "nextjs": ["p/nextjs", "p/react", "p/nodejs"],
      "spring": ["p/spring", "p/java"],
      "rails": ["p/rails", "p/ruby"],
      "laravel": ["p/laravel", "p/php"],
  }
  ```

**`scripts/tool_runners/semgrep_runner.py`:**
- Accept `frameworks` parameter in `run()`
- Supplement `--config auto` with framework-specific rulesets via multiple `--config` flags

**`scripts/scan_orchestrator.py`:**
- Add framework detection between language detection and tool invocation

**Impact:** Framework-specific taint rules have higher precision and catch framework-specific vulnerabilities.

---

### Phase A4: Implement Real CodeQL Integration

**Problem:** `codeql_runner.py` is a 29-line stub returning `[]`.

**Changes:**

**`scripts/tool_runners/codeql_runner.py`:**
- Full implementation: database creation, security query analysis, SARIF parsing
- Language mapping: JS/TS, Python, Java, Go, Ruby, C#
- Result normalization: `pathProblem` -> finding, `problem` -> hotspot
- Extract CWE tags, severity, codeFlows from CodeQL SARIF
- Set `source_tool: "codeql"` on all findings
- **Timeout:** Database creation timeout of 600s (10 min). If exceeded, skip that language and log a warning.
- **Extractor fallback:** If CodeQL extractors are not installed for a detected language, skip silently (same pattern as Joern when unavailable). Log which languages were skipped.
- **Caching:** Cache CodeQL databases in `.codeql/` alongside Joern's `.joern/` cache. Use content-hash-based invalidation (same approach as `create_cpg.py`).
- **Disk management:** Log database size after creation. Do not auto-delete; let users manage via `.gitignore`.

**Impact:** CodeQL's interprocedural taint tracking finds cross-function vulnerabilities Semgrep misses. Best-in-class for Java, C#, Go.

---

### Phase A5: Semantic Deduplication

**Problem:** `stable_key` includes `source_tool` and `rule_id`, so the same SQLi found by Semgrep and CodeQL produces two findings.

**Changes:**

**`scripts/artifact_utils.py`:**
- Change `stable_key_for()` to use semantic key: `hash(type + file + line)` (tool-agnostic)
- Keep legacy key in `_legacy_stable_key` for suppression backward compatibility
- `apply_suppressions()` checks both semantic and legacy keys
- `validate_findings_artifact()` must accept both old-format and new-format stable keys. Detection logic: computed keys use `vscout:` prefix; any key not starting with `vscout:` is treated as hand-written/legacy and skips the consistency check. Existing fixture `stable_key` values remain unchanged since they use explicit keys that bypass `stable_key_for()`.

**Impact:** Cross-tool findings merge into single finding with combined evidence.

---

### Phase A6: Secret Scanning Config

**Problem:** gitleaks/trufflehog runs with zero config, flags test fixtures.

**Changes:**

**`scripts/tool_runners/secrets_runner.py`:**
- Exclude `tests/`, `fixtures/`, `examples/`, `docs/`, `*.example`, `*.sample`
- Entropy-based filtering: low-entropy matches become `hotspot`
- trufflehog: `Verified: true` -> finding, unverified -> hotspot

**`scripts/run_secrets.py`:**
- Same exclusions, add `--strict` flag to override

**Impact:** Eliminates most common secret scanning false positives.

---

### Phase A7: Joern as Discovery Engine

**Problem:** Joern only verifies existing Semgrep findings, never discovers new ones.

**Changes:**

**New files (initial set of 4): `scripts/joern/discover-sqli.sc`, `discover-cmdi.sc`, `discover-ssrf.sc`, `discover-path.sc`:**
- Scan entire CPG for SQL sinks reachable from HTTP sources without sanitization
- Same for command execution, HTTP clients, and file operations
- XSS/SSTI/deser/XXE discovery scripts are deferred to a follow-up iteration -- these are lower-priority because Semgrep already has reasonable coverage for pattern-based detection of these types

**`scripts/tool_runners/joern_runner.py`:**
- Add `discover()` function alongside existing `run()` (verification)

**`scripts/scan_orchestrator.py`:**
- Run Joern discovery in parallel with Semgrep. Note: CPG creation (from `create_cpg.py`) must complete before discovery starts. The CPG is shared between discovery and verification -- create once, use twice. Sequence: `create_cpg` -> then parallel `[semgrep, joern discover]` -> then `joern verify` on combined findings.
- Run Joern verification after all discovery tools complete

**Impact:** Finds cross-function dataflow vulnerabilities that Semgrep can't detect.

---

### Phase A8: Calibrated Confidence Scores

**Changes:**

**`scripts/joern/common.sc`:**
- Add `Confidence` object with named constants. All values represent "confidence in the verdict" -- e.g., `FP_PARAMETERIZED_QUERY = 0.92` means 92% confident the verdict is FALSE_POSITIVE:
  ```scala
  object Confidence {
    // Confidence in VERIFIED verdict
    val VERIFIED_TAINT_WITH_CONCAT = 0.95   // Dataflow + string concat into sink
    val VERIFIED_TAINT_NO_SANITIZER = 0.90  // Dataflow reaches sink, no sanitizer

    // Confidence in FALSE_POSITIVE verdict
    val FP_PARAMETERIZED_QUERY = 0.92       // SQL: parameterized query detected
    val FP_SAFE_LOADER = 0.95               // Deser: safe loader detected
    val FP_TYPE_COERCION = 0.88             // Input is type-coerced
    val FP_NO_DATAFLOW = 0.80               // No formal dataflow found

    // Confidence in NEEDS_REVIEW verdict
    val NR_PARTIAL_SANITIZER = 0.55         // Some flows sanitized, some not
    val NR_WEAK_SANITIZER = 0.50            // Sanitizer known to be bypassable
    val NR_CONTEXT_UNCLEAR = 0.40           // Cannot determine security context
  }
  ```
- Replace all hardcoded values in verify scripts with named references

**Impact:** Centralized tuning, easier calibration.

---

## Pillar B: Output & Differentiation

### Phase B1: Schema Enrichment

**Problem:** Evidence items lack source/sink role annotations and findings aren't grouped into chains.

**Changes:**

**`references/findings.schema.json`:**
- Add optional `role` (enum: source, hop, sink, sanitizer, control) and `order` (integer) to evidence items
- Add optional `chain_id` and `chain_role` (entry, pivot, sink) to findings
- Add optional top-level `chains` array:
  ```json
  { "id": "...", "name": "...", "impact": "...", "finding_ids": [...], "flow_description": "..." }
  ```
- Bump `schema_version` to `"1.1.0"`, accept both `"1.0.0"` and `"1.1.0"`

**`scripts/artifact_utils.py`:**
- Update `SCHEMA_VERSION`, `validate_findings_artifact`
- `validate_findings_artifact()` must accept `schema_version in {"1.0.0", "1.1.0"}`. New optional fields (`role`, `order`, `chain_id`, `chain_role`, top-level `chains`) are only validated when `schema_version == "1.1.0"`. A `"1.0.0"` artifact must not be rejected for missing these fields.
- Add `chains_count` to summary

---

### Phase B2: Interactive HTML Report (Flagship)

**Problem:** Output is a flat markdown list. Nobody screenshots or shares it.

**New file: `scripts/html_report.py`:**

A `generate(artifact: dict) -> str` function returning self-contained HTML (zero external dependencies). Size estimate: ~50-100KB for typical scans (<50 findings). For large scans (100+ findings), the report may reach 500KB+; add a `max_findings` parameter (default 200) with a "N more findings omitted" footer when truncated.

**Layout (top to bottom):**

1. **Header bar:** VulnScout branding, scan metadata, overall security score (0-100)

2. **Severity donut chart:** Pure SVG generated via Python trigonometry. Five arcs colored by severity (critical=red, high=orange, medium=yellow, low=blue, info=gray). Center shows total count. Adjacent stat cards: verified count, needs-review count, chains detected.

3. **Attack chain graph:** Pure inline SVG. Nodes = findings (rectangles with severity color), edges = directed arrows with pivot descriptions. Left-to-right layout. Clickable nodes scroll to finding details. Hidden when no chains exist.

4. **Findings table:** Sortable by severity/verdict/file/CVSS. Columns: severity badge, title, file:line, verdict, CVSS, source tool. Clickable rows expand to detail cards.

5. **Expanded finding cards:**
   - Evidence timeline: vertical dots (green=source, blue=hop, red=sink) with syntax-highlighted code excerpts
   - CVSS breakdown bar (parsed from cvss_vector)
   - CWE link to mitre.org
   - Remediation panel (from finding data or built-in defaults)
   - Verification badge (Verified by Joern / Needs Review / Unverified)

6. **Hotspots section:** Separate muted table

7. **Coverage panel:** Files scanned, languages, tools, diff status

8. **Footer:** VulnScout attribution, timestamp

**Implementation:**
- HTML template as Python f-string
- ~200 lines inline CSS
- ~100 lines inline JS (table sort, expand/collapse, smooth scroll)
- SVG donut: `_donut_svg(summary)` using `math.sin`/`math.cos`
- SVG chain graph: `_chain_graph_svg(chains, findings)` with left-to-right layout
- Code highlighting: regex-based keyword wrapping (Python/JS/Go/Java/PHP keywords)

**Wiring:**

**`scripts/scan_orchestrator.py`:** Add `fmt == "html"` branch in `write_output`

**`commands/report.md` and `commands/scan.md`:** Add `html` to `--format` choices

**Default remediation mapping** in `html_report.py`:
```python
REMEDIATION_DEFAULTS = {
    "sql-injection": "Use parameterized queries or prepared statements...",
    "command-injection": "Avoid shell execution. Use language-native libraries...",
    "xss": "Apply context-appropriate output encoding...",
    "ssrf": "Validate and allowlist destination URLs...",
    "ssti": "Never pass user input to template rendering functions...",
    "path-traversal": "Resolve paths with realpath() and validate prefix...",
    "deserialization": "Never deserialize untrusted input. Use JSON...",
    "hardcoded-secret": "Move secrets to env vars or secrets manager...",
}
```

---

### Phase B3: Rich SARIF Output

**Changes to `scripts/artifact_utils.py` `to_sarif()`:**

- Add `codeFlows` when evidence items have `role`/`order` annotations
  - Map source/hop/sink to SARIF `threadFlowLocation` with appropriate `importance`
- Add `relatedLocations` for chain-linked findings
- Add `properties.tags` with CWE IDs in GitHub format (`external/cwe/cwe-89`)
- Add `properties.security-severity` as numeric CVSS score string

**Impact:** Findings become visible in GitHub Code Scanning and VS Code SARIF viewer with full dataflow context.

---

### Phase B4: Enhanced Markdown Report

**Rewrite `scripts/markdown_report.py`:**

1. **Executive summary:** Severity table + overall risk rating + tools used + scan scope + chain count

2. **Attack chains:** Mermaid diagrams in fenced code blocks (GitHub renders natively):
   ````markdown
   ```mermaid
   graph LR
       A[SSRF in api/proxy.ts:42] -->|reaches internal| B[SSTI in flask/render.py:18]
       B -->|executes| C[RCE via os.popen]
   ```
   ````

3. **All findings** (not just top 10): severity badge, CVSS, CWE link, evidence, remediation, verdict

4. **Full hotspot list** (not truncated at 20)

5. **Coverage panel:** Files scanned, tools, diff-aware status

---

### Phase B5: GitHub PR Comment Template

**New file: `scripts/pr_comment.py`:**

Compact format for PR comments (<65KB GitHub limit):
- Severity summary table
- Diff-aware findings highlighted prominently (`in_diff: true`)
- Attack chains surfaced in summary
- `<details>` tags for expandable full list
- Footer: "Scanned by VulnScout | X files | Y seconds"

---

### Phase B6: Security Score Badge

**New file: `scripts/badge.py`:**

SVG badge in shields.io format:
- Score: `100 - (critical*25 + high*10 + medium*3 + low*1)`
- Color: green (90-100), yellow-green (70-89), yellow (50-69), orange (30-49), red (0-29)
- Usage: `![VulnScout](./vuln-scout-badge.svg)` in READMEs

---

### Phase B7: Testing & Consistency

**Updated fixture:** `tests/fixtures/artifacts/sample-findings.json` with chains, role-annotated evidence, cvss_vector, remediation

**New tests** (all paths are repo-root-relative, using `unittest` framework to match existing tests):
- `tests/test_html_report.py`: Valid HTML, contains findings, renders chain SVG, self-contained (no external URLs), handles legacy schema (1.0.0 artifact without chains/roles)
- `tests/test_pr_comment.py`: Under 60KB raw markdown (accounting for GitHub's 65KB rendered limit), diff-aware highlighting, empty findings produce clean "no issues" message. Truncation strategy: if raw markdown exceeds 55KB, truncate findings list and append "N more findings omitted -- see full report".
- Extended `tests/test_sarif.py`: codeFlows present, relatedLocations, CWE tags, security-severity

**Note:** Each phase should include unit tests for its own changes rather than deferring all testing to B7. Phase B7 covers integration tests and the updated fixture; individual unit tests are part of each phase's implementation.

---

## Implementation Sequence

| Order | Phase | Effort | Impact |
|-------|-------|--------|--------|
| 1 | A1: Semgrep filtering | 2-3h | -15-20% FP |
| 2 | A6: Secret scan config | 1-2h | -3-5% FP |
| 3 | A2: Joern multilang fix | 8-12h | Fixes 7 languages |
| 4 | A3: Framework rules | 3-4h | Better precision + new findings |
| 5 | B1: Schema enrichment | 30min | Foundation for all output |
| 6 | B2: HTML report | 3-4h | Flagship differentiator |
| 7 | A5: Semantic dedup | 2-3h | Cross-tool dedup |
| 8 | A4: CodeQL integration | 6-8h | Major new findings |
| 9 | B3: Rich SARIF | 1-2h | GitHub Code Scanning |
| 10 | B4: Enhanced markdown | 1-1.5h | Better default output |
| 11 | B5: PR comment | 1h | Viral distribution |
| 12 | B6: Badge | 30min | README visibility |
| 13 | A7: Joern discovery | 8-10h | Cross-function findings |
| 14 | A8: Confidence calibration | 2-3h | Central tuning |
| 15 | B7: Testing | 1-1.5h | Quality gate |

**Total estimated effort:** ~40-55 hours

---

## Verification Plan

1. **Detection quality:** Run improved pipeline against OWASP Juice Shop v17.1.1 (baseline: 62 findings). Compare finding count, FP rate, and severity distribution before/after.
2. **Multi-language verification:** Run Joern verification on a Flask app, Spring Boot app, and Go HTTP service. Confirm verdicts are not all `NA_CPG`.
3. **HTML report:** Open generated HTML in browser. Verify: donut chart renders, chain graph shows if chains present, finding cards expand, no external URLs loaded.
4. **SARIF:** Import into VS Code SARIF viewer. Verify codeFlows display as source-to-sink traces.
5. **PR comment:** Post to a test PR. Verify renders correctly, under 65KB, diff-aware findings highlighted.
6. **Badge:** Embed in a test README. Verify renders on GitHub.
7. **Deduplication:** Run with `--tools semgrep,codeql`. Verify same-location findings merge.
8. **Backward compatibility:** Run with a `schema_version: "1.0.0"` artifact. Verify HTML report degrades gracefully (no chains section, flat evidence).

---

## Critical Files

All paths below are relative to `whitebox-pentest/` (the plugin root).

| File | Changes |
|------|---------|
| `scripts/joern/common.sc` | Multi-language sources, sinks, helper function, confidence constants |
| `scripts/tool_runners/semgrep_runner.py` | Confidence filtering, framework-aware rules |
| `scripts/tool_runners/codeql_runner.py` | Full implementation replacing stub |
| `scripts/tool_runners/joern_runner.py` | Discovery mode |
| `scripts/tool_runners/secrets_runner.py` | Exclusion patterns, entropy filtering |
| `scripts/scan_orchestrator.py` | Framework detection, Joern discovery, two-phase verify |
| `scripts/artifact_utils.py` | Semantic dedup, SARIF codeFlows, schema version |
| `scripts/markdown_report.py` | Full rewrite with Mermaid chains |
| `scripts/html_report.py` | **New** - flagship HTML report |
| `scripts/pr_comment.py` | **New** - PR comment template |
| `scripts/badge.py` | **New** - SVG badge generator |
| `scripts/framework_detector.py` | **New** - framework detection |
| `scripts/joern/discover-*.sc` | **New** - Joern discovery scripts |
| `scripts/joern/verify-*.sc` (all 15) | Use `findAttackerFlows` helper |
| `scripts/run_semgrep.py` | Confidence filtering |
| `scripts/run_secrets.py` | Exclusion patterns |
| `references/findings.schema.json` | Schema v1.1.0 with chains, evidence roles |
| `commands/report.md` | Add html, pr-comment, badge formats |
| `commands/scan.md` | Add html format |
