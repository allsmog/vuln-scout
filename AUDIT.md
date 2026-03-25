# vuln-scout Deep Audit

**Date**: 2026-03-24
**Version audited**: 1.3.0
**Auditor**: Claude Sonnet 4.6

---

## 1. Code Quality & Architecture

**What's good:** Clean separation across agents/commands/hooks/skills/scripts. The plugin.json manifest is minimal and correct. The `full-audit.md` pipeline diagram is clear and the state dual-file design (JSON + markdown) is thoughtful.

**Issues:**

**README version rot.** The README says "Skills (15 Auto-Activated)" but there are 22 skills in the actual plugin. Never updated from v1.0.0. Destroys user trust on first read.

**Scan.md has a missing step.** It goes `Step 1: Determine Scan Scope`, then `Step 3: Run Semgrep Scan` — Step 2 is absent.

**Kotlin and Swift sink files are dead content.** `skills/dangerous-functions/references/kotlin-sinks.md` and `swift-sinks.md` exist but these languages appear nowhere in the README, plugin.json, or any command. No activation path.

**OWASP numbering is wrong.** The `owasp-2025/SKILL.md` lists:
- A03 = "Software Supply Chain" (OWASP 2021 A03 is Injection; A06 is Vulnerable Components)
- A10 = "Mishandling of Exceptions" (OWASP 2021 A10 is SSRF)

This is a custom reordering, not the actual OWASP Top 10. Users relying on this for compliance reporting get wrong category labels.

**`nextjs-react/` skill and `framework-patterns/nextjs-patterns.md` overlap** with no clear differentiation in scope.

**The large-codebase-check session flag is a fiction.** `large-codebase-check.md` instructs the hook to set `_LARGE_CODEBASE_CHECKED=true` to prevent repeated checks, but there is no mechanism in the Claude Code hook system to persist an in-memory variable between separate tool-use events. The `find .` command runs on every single `**` Grep/Glob operation, every time.

---

## 2. Skill Coverage Gaps

**Against CWE Top 25 (2024):**

| CWE | Name | Coverage |
|-----|------|----------|
| CWE-787 | Out-of-bounds Write | None — no C/C++ |
| CWE-79 | XSS | Covered |
| CWE-89 | SQL Injection | Covered |
| CWE-416 | Use After Free | None — no C/C++ |
| CWE-78 | OS Command Injection | Covered |
| CWE-190 | Integer Overflow | None — critical for Solidity/Rust |
| CWE-125 | Out-of-bounds Read | None |
| CWE-22 | Path Traversal | Covered |
| CWE-476 | NULL Pointer Deref | None |
| CWE-502 | Unsafe Deserialization | Covered |

No C/C++ support at all. 5 of the CWE Top 10 have zero coverage. The "CWE Top 25" support in the Semgrep rulesets comes from Semgrep's own rules, not from vuln-scout's instrumentation.

**Against modern attack surfaces:**

**AI/ML: Completely absent.** No coverage of:
- Pickle/joblib deserialization in ML pipelines (extremely common RCE vector)
- Prompt injection in LLM-backed applications
- Jupyter notebook code injection
- Hugging Face model loading with untrusted models (`transformers.AutoModel.from_pretrained`)

**Supply chain: Explicitly excluded.** Listed as "Out of scope by design" for A06. Defensible for pure code review, but the plugin makes no attempt to detect dependency confusion attacks, typosquatting-prone package names, or suspicious post-install scripts in `setup.py`/`pyproject.toml`.

**Cloud-native: Shallow.** SSRF detection exists but there's no specific awareness of:
- AWS/GCP/Azure metadata endpoint probing (`169.254.169.254`, `fd00:ec2::254`)
- IMDSv1 vs IMDSv2 security
- S3 bucket misconfiguration detection
- Kubernetes RBAC / ServiceAccount token exposure
- Serverless function environment variable leakage

**OWASP API Top 10 (2023): Not covered.** The web app Top 10 and API Top 10 are different lists. Missing:
- BOLA (Broken Object Level Authorization)
- Mass Assignment / API parameter pollution
- GraphQL introspection abuse, batching attacks, depth attacks
- gRPC security
- Unrestricted resource consumption

**Integer overflow in Solidity:** The Solidity coverage lacks checks for arithmetic overflow/underflow (pre-0.8 without SafeMath). `verify-reentrancy.sc` exists but there's no `verify-overflow.sc`.

---

## 3. Agent Pipeline

**Role overlap between app-mapper and threat-modeler.** Both agents do technology decomposition, entry point identification, and trust boundary analysis. The threat-modeler's Phase 1 is nearly identical to app-mapper's entire function. In practice the first half of threat-modeler duplicates app-mapper's work. They should either be merged or threat-modeler should explicitly consume app-mapper's output rather than redoing discovery.

**No orchestrator agent.** All orchestration logic lives inside `full-audit.md` as a long prompt. There's no dedicated agent that can dynamically decide which agents to invoke based on findings, track cross-agent state, retry failed phases, or invoke agents in parallel. The result is a monolithic waterfall, not a true agent pipeline.

**false-positive-verifier has no tool access for dynamic verification.** It only has Read, Grep, Glob. It cannot execute Joern scripts — Joern execution happens externally in `/verify`, which then passes results as text to the agent. No structured input schema is enforced, so the agent's quality depends entirely on how well the calling context packages the Joern output.

**suggest-next-phase hook only triggers on code-reviewer SubagentStop.** Ad-hoc agent invocations outside of full-audit won't get phase transition prompts.

**local-tester and poc-developer role overlap.** The distinction between "confirming a vulnerability is exploitable" and "writing a PoC script" is blurry in practice. Many testers go directly from finding to PoC. These two agents could be merged with a flag.

**NEEDS_REVIEW verdict has no resolution path.** When `/verify` produces `NEEDS_REVIEW`, there is no defined next step — no agent escalation, no documentation of what specifically needs manual review, no way for an orchestrator to know the finding is unresolved.

---

## 4. False Positive Rate

**Joern scripts are JavaScript/TypeScript-only.** `common.sc` defines sources as `req|request|params|query|body|headers|cookies` (Express.js patterns). For Python Flask (`request.args`, `request.form`), Java Spring (`@RequestParam`, `@PathVariable`), or Go `net/http` (`r.URL.Query()`), there are no matching source patterns. The scripts would return `FALSE_POSITIVE` on most non-JS codebases — a systematic false negative problem disguised as confidence.

**`verify-sqli.sc` only checks `argument(1)` for parameterization.** `val queryArg = sink.argument(1)` assumes the query string is always the first argument. Knex.js uses `knex.raw(sql, bindings)` where bindings is argument 2. This produces false positives.

**Sanitizer matching is overly broad.** The sanitizer pattern includes `sanitize` as a keyword. A function called `sanitizeForDisplay()` (which HTML-escapes for output) would be counted as a SQL sanitizer, inflating false positive rates on SQL injection findings.

**The path traversal FP check incorrectly marks `path.resolve()` as safe.** `path.resolve('/var/www', userInput)` is NOT safe if `userInput` starts with `/`. The FP indicator list is incomplete here.

**Confidence scores are hardcoded arbitrary constants.** `FALSE_POSITIVE` confidence is `0.90` when parameterization is detected, `0.85` when no flow is found. These are not calibrated against real data. There is no feedback loop.

**What would improve it:**
1. Per-language source pattern files (Python, Java, Go, PHP) matching actual framework source APIs
2. Semantic sanitizer classification (SQL-safe vs XSS-safe vs command-safe) instead of name matching
3. A mechanism to record confirmed FP/TP verdicts to calibrate future runs
4. Correct path traversal FP logic (check if `path.resolve` result is prefix-validated)
5. Batch Joern analysis — one JVM startup per file rather than per finding

---

## 5. Tooling Dependencies

**repomix:** Fine for token compression, but `npx repomix` pulls the latest version from npm on each run, making results non-deterministic. Should pin a version. Also, the 95-97% token reduction claim for Go depends on codebases matching Go directory conventions (handlers/, svc/). Non-standard structures get no benefit. Better alternative: **tree-sitter** with language-aware AST extraction would give semantically meaningful compression that preserves function signatures and control flow, rather than directory filtering.

**Semgrep:** Right default choice, but:
- `semgrep --config auto` hits the Semgrep registry on every run — network-dependent and non-deterministic
- No mention of `p/secrets`, which is one of the highest-value rulesets
- No offline/airgap mode documented
- Pro features (taint tracking, join mode) would dramatically improve accuracy but are unmentioned
- Should pin ruleset versions for reproducibility

**Joern:** Most powerful for deep flow analysis but serious adoption friction:
- JVM-based, 500MB+ install
- Notorious compatibility issues on macOS ARM
- 30-60 second startup time per invocation, not batched
- Scripts only work for JS/TS (see §4)
- Better alternative for most use cases: **CodeQL** has official support for all 9 of the plugin's target languages, superior inter-procedural taint tracking, and GitHub-hosted runners require no local install. The plugin treats CodeQL as an afterthought but it is arguably better than Joern for the code review use cases here.

**CodeQL:** Listed as an option but has no dedicated scripts or integration beyond "run it and parse output." The Joern integration has 7 custom verification scripts. CodeQL gets nothing equivalent.

**Missing tools with real signal value:**
- **Bandit** — Python security linter, better precision than generic Semgrep for Python
- **gosec** — Go security checker, maintained by the Go ecosystem
- **Brakeman** — Ruby/Rails static analysis, far better than generic Semgrep for Rails
- **truffleHog/gitleaks** — Secret scanning in git history, entirely absent from the plugin
- **njsscan / eslint-plugin-security** — Node.js-specific checks

---

## 6. Missing Features

| Feature | Priority | Notes |
|---------|----------|-------|
| **SARIF output** | P1 | Industry standard. Enables GitHub Advanced Security, VS Code Security extension, SonarQube, Defect Dojo integration. The current custom JSON format is a dead end. |
| **CI/CD integration** | P1 | No GitHub Actions workflow, no pre-commit hook template, no exit code policy. Tool exits 0 even with critical findings. |
| **Finding suppression file** | P1 | No `.vuln-scout-ignore` mechanism. Confirmed false positives resurface on every scan, forcing re-verification. |
| **Secret scanning (git history)** | P1 | Credentials in git history are one of the most common real-world findings. Nothing in the plugin scans git history. |
| **Diff-aware scanning** | P1 | `--recent N` days is approximate. Needs `--since-commit SHA` mode that scans only changed files/functions. Required for PR-gating. |
| **CVSS scoring** | P2 | Impact × Likelihood (1-5) is not CVSS. No CVSS vector strings. Security teams need CVSS to prioritize and report to stakeholders. |
| **Compliance mapping** | P2 | No PCI-DSS, HIPAA, SOC2, NIST CSF mapping. OWASP is present but doesn't link to specific control requirements. |
| **Delta/baseline reports** | P2 | No way to diff two scan runs to see what's new, fixed, or regressed. Essential for remediation tracking. |
| **Finding deduplication** | P2 | When Semgrep + Joern both report the same finding, there's no dedup. Reports have duplicate entries. |
| **Remediation lifecycle** | P2 | Findings go UNVERIFIED → VERIFIED but there's no FIXED state, no re-verification that patches resolved findings. |
| **Parallel agent execution** | P3 | full-audit runs sequentially. Module audits could fan out once the threat model is done. |

---

## 7. Documentation & Onboarding

**Installation instructions are wrong.** `claude --plugin-dir /path/to/whitebox-pentest` is not how Claude Code plugins are installed. Plugins are referenced in `settings.json` or placed in `~/.claude/plugins/`. Someone following the README verbatim will fail immediately.

**No worked example.** No "try it on this vulnerable app" tutorial. Without a quickstart using DVWA, Juice Shop, or WebGoat, new users have no way to verify they set it up correctly.

**No Joern troubleshooting guide.** Joern is the hardest dependency to install — JVM-based, Scala dependencies, known issues on macOS ARM, requires specific JVM versions. None of this is documented.

**No CHANGELOG.** No record of what changed between v1.0.0 and v1.3.0. Users can't know if new skills/agents were added, breaking changes occurred, or bugs were fixed.

**CLAUDE.md development guide is skeletal.** It describes the file structure but gives no guidance on: how to add a new language, how to test skill activation, how to write a new Joern verification script, or how to bump the version.

**Methodology prerequisites are implicit.** The README attributes the methodology to "HTB Academy and OffSec AWAE" but doesn't state what background a user needs. Someone who's never done whitebox pentesting won't know what "Phase 2 - Local Testing" means in practice or whether they're using the tool correctly.

---

## 8. Performance

**`large-codebase-check` runs `find .` on every `**` search.** The session flag mechanism doesn't work (see §1). On a large monorepo, every broad Grep fires a recursive file count command. This adds latency to every search operation throughout the entire audit.

**Joern is restarted per finding.** Each `/verify` invocation starts a fresh JVM. With 30-60 second startup time and 10 findings to verify, that's 5-10 minutes of pure JVM startup. No batching, no persistent Joern server mode.

**`semgrep --config auto` downloads rules from the internet per run.** No caching, no offline mode, no version pinning. On a large codebase this can take several minutes just for rule fetching before any scanning begins.

**repomix is called via `npx`** which may download the package if not cached. Should use a globally-installed binary.

**full-audit pipeline is purely sequential.** Once modules are identified, their individual deep-dive audits could run in parallel but don't.

**`common.sc` escapeJson doesn't handle Unicode.** Code containing non-ASCII characters (common in internationalized applications, Python 3 Unicode variable names) will produce malformed JSON from the Joern scripts, silently corrupting verification output.

---

## Prioritized Improvements

### P0 — Fix before claiming production readiness

1. **Fix OWASP Top 10 category numbering.** The current mapping is wrong and will mislead security teams doing compliance work. A03 is not Supply Chain; A10 is not Exception Handling.
2. **Fix installation instructions.** `claude --plugin-dir` doesn't exist. Blocks every new user.
3. **Extend Joern scripts to cover Python/Java/Go sources.** Currently the CPG verification layer produces wrong results for ~6 of the 9 supported languages. It silently returns false negatives on non-JS codebases.
4. **Fix README skill count (15 → 22).** Minor but erodes trust immediately.

### P1 — Core features for a serious tool

5. **SARIF output.** Without it, findings can't flow into any downstream security tooling. Add `--format sarif` to `/scan` and `/report`.
6. **CI/CD integration.** Provide a GitHub Actions workflow template. Define exit codes (exit 1 on critical findings). This is the difference between a demo tool and one teams actually deploy.
7. **Finding suppression file.** Implement `.vuln-scout-ignore` so confirmed false positives aren't re-raised on every scan.
8. **Secret scanning in git history.** Integrate truffleHog or gitleaks. Near-certain finding in most real repos and completely absent from the plugin.
9. **Diff-aware scanning.** Add `--since-commit SHA` mode for PR-gating use cases.
10. **Fix `large-codebase-check` session flag.** Replace the in-memory fiction with a file-based flag (e.g., write `_large_codebase_checked: true` to `.claude/session-state.json` on first check).

### P2 — Coverage and quality improvements

11. **Per-language source patterns for Joern.** Create `sources-python.sc`, `sources-java.sc`, `sources-go.sc` to fix the false positive/false negative problem for non-JS codebases.
12. **Merge or clearly differentiate app-mapper and threat-modeler.** Have threat-modeler explicitly consume app-mapper output rather than redoing discovery work.
13. **Define a NEEDS_REVIEW resolution path.** Add a manual-review queue to the state file and surface unresolved findings for follow-up.
14. **Add CVSS scoring to reports.** Replace or augment the Impact × Likelihood grid with CVSS vector strings.
15. **Add AI/ML attack surface skill.** Pickle deserialization in ML pipelines, prompt injection, Jupyter injection — increasingly common in modern codebases.
16. **Add cloud-native awareness.** SSRF-to-metadata endpoint detection, S3 misconfiguration, K8s ServiceAccount token exposure.
17. **Add OWASP API Top 10 skill.** BOLA, mass assignment, GraphQL attacks are all absent.
18. **Semantic sanitizer classification.** Fix FP logic to distinguish SQL-safe vs XSS-safe vs command-safe sanitizers rather than matching on function name substring.

### P3 — Polish and ecosystem

19. **Add language-specific scanners.** Bandit (Python), gosec (Go), Brakeman (Ruby). Better precision than generic Semgrep for their respective ecosystems.
20. **Batch Joern verification.** One JVM startup per file rather than per finding.
21. **Add a worked quickstart example.** A 5-minute tutorial against Juice Shop or a bundled vulnerable target. Critical for adoption.
22. **Write a CHANGELOG.** Document what changed between v1.0.0 and v1.3.0.
23. **Compliance mapping.** PCI-DSS Req 6.3, HIPAA §164.312, SOC2 CC7.1.
24. **Parallel agent execution in full-audit.** Fan out per-module audits once modules are identified.
25. **Pin dependency versions.** `repomix@x.y.z` not `npx repomix`, specific Semgrep ruleset versions not `auto`.

---

## 9. Issues Resolved in v1.4.0

The following P0 issues identified in this audit were fixed in commit `5139e3e` (VulnScout v1.4.0):

1. **OWASP numbering** -- `owasp-2025/SKILL.md` now uses correct OWASP Top 10 2021 categories (A03=Injection, A10=SSRF).
2. **README skill count** -- Both READMEs now correctly state "22 Auto-Activated Skills".
3. **Installation instructions** -- READMEs now show the correct symlink/copy approach (`mkdir -p .claude/plugins && ln -s ...`), not the non-existent `claude --plugin-dir`.
4. **scan.md missing Step 2** -- Steps are now numbered sequentially (1 through 6) with Step 2 being "Apply baseline exclusions".

The following issues were fixed in the post-audit improvement pass:

5. **Version drift** -- `plugin.json` bumped from 1.3.0 to 1.4.0.
6. **Joern sanitizer false positives** -- All `.name()` patterns in Sanitizers and verify scripts anchored with `^(...)$` to prevent partial matches.
7. **path.resolve() FP logic** -- `verify-path.sc` now distinguishes strong normalizers (realpath/Clean) from weak ones (resolve). `resolve + prefix check` produces NEEDS_REVIEW, not FALSE_POSITIVE.
8. **Session flag fiction** -- `large-codebase-check.md` now uses file-based `.claude/session-state.json` instead of non-existent in-memory variables.
9. **Dead Kotlin/Swift sinks** -- Both files annotated with "Preview language" banners; references in SKILL.md marked as `*(preview)*`.

---

## Overall Verdict

The methodology is genuinely solid — the 4-phase approach, vulnerability chaining, CPG-based verification, and polyglot monorepo support are real differentiators that reflect actual pentesting experience. The problems are mostly in execution details: wrong OWASP labels, installation instructions that don't work, Joern scripts that silently fail on non-JS codebases, and missing ecosystem integration (SARIF, CI/CD, suppression). Fix P0 and P1 and this is a credible tool. As-is, the correctness issues with OWASP numbering and Joern scope would undermine trust in a professional engagement context.
