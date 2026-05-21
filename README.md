<p align="center">
  <img src="vuln-scout.png" alt="VulnScout" width="280">
</p>

<h1 align="center">VulnScout</h1>

<p align="center"><strong>Claude Code plugin for whitebox security review with deterministic quick scans, evidence-backed verification, and portable reports.</strong></p>

<p align="center">
  <a href="docs/feature-maturity.md"><img alt="stable quick scan" src="https://img.shields.io/badge/quick%20scan-stable-16a34a"></a>
  <a href="docs/feature-maturity.md"><img alt="deep analyzers beta" src="https://img.shields.io/badge/deep%20analyzers-beta-ca8a04"></a>
  <a href="docs/feature-maturity.md"><img alt="auto fix experimental" src="https://img.shields.io/badge/auto--fix-experimental-6b7280"></a>
</p>

Install: `claude plugin install vuln-scout`

Run: `/vuln-scout:full-audit /path/to/code`

VulnScout's stable promise is an offline quick scan, shared `findings.json` with stable keys and hotspot-aware findings, SARIF/Markdown/HTML/bundle reports, suppressions, and a CI fail-on gate. It writes `audit-plan.md` and `review-ledger.json` for reviewer-driven workflows and exposes parity to Claude Code and Kuzushi.

## 5-Minute Demo

```bash
python3 vuln-scout/scripts/doctor.py --strict
python3 vuln-scout/scripts/scan_orchestrator.py demo/vulnerable-app --profile quick --output /tmp/vuln-scout-demo.json
python3 vuln-scout/scripts/report.py /tmp/vuln-scout-demo.json --format html --output report.html
```

Expected quick-profile result: four findings from bundled local rules.

| Severity | Finding |
|---|---|
| high | Python SQL injection |
| high | Python command injection |
| medium | Browser XSS |
| medium | Express open redirect |

## Stable Promise

See [feature maturity](docs/feature-maturity.md) for the full stability matrix.

| Capability | Status |
|---|---|
| Offline quick scan with bundled rules | Stable |
| Shared `findings.json` schema and stable keys | Stable |
| SARIF, Markdown, HTML, and bundle reports | Stable |
| Suppressions and CI `--fail-on` gate | Stable |
| Kuzushi structured tool surface | Stable |
| Joern, CodeQL, Slither, Trivy, Checkov deep analyzers | Beta when installed |
| Auto-fix, PoC, and mutation workflows | Experimental |

## Install

Primary paths are documented in [docs/install.md](docs/install.md).

```bash
claude plugin install vuln-scout
claude --plugin-dir ./vuln-scout
npm install @kuzushi/vuln-scout
```

## Canonical Workflows

| Workflow | Command | Guide |
|---|---|---|
| Full audit | `/vuln-scout:full-audit` | [First run](docs/workflows/first-run.md) |
| Verify finding | `/vuln-scout:verify` | [PR review](docs/workflows/pr-review.md) |
| Report | `/vuln-scout:report` | [CI](docs/workflows/ci.md) |
| Scope repo | `/vuln-scout:scope` | [First run](docs/workflows/first-run.md) |
| Diff review | `/vuln-scout:diff` | [PR review](docs/workflows/pr-review.md) |

### Commands (14 total)

<details>
<summary>Advanced commands</summary>

| Command | Maturity | Purpose |
|---|---|---|
| `/vuln-scout:scan` | beta | Run quick, deep, or audit scan profiles |
| `/vuln-scout:threats` | beta | Build STRIDE threat models |
| `/vuln-scout:sinks` | beta | Find dangerous functions and output sinks |
| `/vuln-scout:trace` | beta | Trace source-to-sink data flow |
| `/vuln-scout:propagate` | beta | Find related instances of a confirmed pattern |
| `/vuln-scout:create-rule` | experimental | Generate custom Semgrep rules |
| `/vuln-scout:org-memory-compile` | experimental | Compile human-reviewed org memory |
| `/vuln-scout:mutate` | experimental | Mutation-test security controls |
| `/vuln-scout:auto-fix` | experimental | Generate patches for verified findings |

</details>

## Feature Maturity

| Surface | Stable | Beta | Experimental |
|---|---|---|---|
| Profiles | quick | deep, audit | custom-rules |
| Reports | SARIF, Markdown, HTML, bundle | PR comment | generated PoCs |
| Workflows | full-audit, verify, report, scope, diff | scan, threats, sinks, trace, propagate | create-rule, mutate, auto-fix |

## Kuzushi Integration

The npm package exports Kuzushi tools that return structured results:

```js
{ ok, output, artifacts, maturity, toolName }
```

The report tool supports `sarif`, `md`, `json`, `html`, and `bundle`.

## Project Structure

```text
vuln-scout/
  .claude-plugin/plugin.json
  agents/
  commands/
  hooks/
  skills/
  references/
  scripts/
```

### 32 Auto-Activated Skills

The plugin ships 27 knowledge skills plus 5 task skills under `vuln-scout/skills/tasks/`.

## Audit Artifacts

- `.claude/audit-plan.md` captures scope, module priority, attack surfaces, and verification strategy.
- `.claude/review-ledger.json` records adversarial review rounds and approvals.
- `.claude/findings.json` follows `vuln-scout/references/findings.schema.json`.

## Migration

Users upgrading from 3.x should read [docs/migration-3.x-to-3.2.md](docs/migration-3.x-to-3.2.md). `/whitebox-pentest:*` aliases remain as deprecated shim files for one release and are shipped as a legacy plugin root.

## License

MIT
