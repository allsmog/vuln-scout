# VulnScout Feature Maturity

Rubric: stable features are tested, documented, packaged, and useful in realistic
workflows. Beta features are functional but depend on local tool setup or manual
review. Experimental features are prompts or scripts that need reviewer control.

| Feature family | Status | What is ready | Known limits |
|----------------|--------|---------------|--------------|
| Claude plugin experience | Stable | 14 commands, 8 agents, 4 hooks, 27 skills, prompt state artifacts | Quality still depends on reviewer prompts and Claude Code context limits |
| Kuzushi/NPM integration | Stable | ESM package entrypoint, 14 exposed tools, common structured flags, package contents allowlist | Deep reviewer controls still live in Claude Code prompts |
| MCP integration | Beta | Local stdio server, scanner/report/artifact tools, Joern CPG creation, query, discovery, and verification bridge | Depends on MCP host wiring and local analyzer installation |
| Quick scan pipeline | Stable | Offline local Semgrep rules, SARIF/JSON/Markdown/HTML outputs, suppressions, fail-on gate | Requires Semgrep installed locally |
| Deep scan pipeline | Beta | CodeQL, Joern, Slither, Trivy, Checkov, and secret scanners run when available | External tool installation, project builds, and network access affect reliability |
| Finding lifecycle | Stable | Shared schema, stable keys, suppressions, deduplication, CVSS, tool status, report rendering | Verification levels are only as strong as the tool evidence present |
| Detection coverage | Beta | Common injection, XSS, SSRF, secrets, Solidity, API, cloud, and business-logic guidance | Broad coverage is not the same as benchmarked detection across every framework |
| Auto-fix and PoC workflows | Experimental | Commands, agents, safety hooks, and helper scripts exist | Must be reviewer-driven; not release criteria for unattended remediation |
| Mutation and dynamic verification | Experimental | Mutation/Poc scaffolding exists | Needs target-specific harnesses before it can be considered reliable |

## Stable User Promise

VulnScout provides a reliable AI-assisted audit workflow:

1. Check runtime readiness with `doctor.py`.
2. Run `--profile quick` without Semgrep registry access.
3. Review `.claude/findings.json` and generated reports.
4. Suppress accepted risk by stable key.
5. Fail CI with `--fail-on high`.

## Beta Promise

The `deep` and `audit` profiles add value when external tools are installed, but
their output should be read as best-effort evidence. Reports expose `tool_status`
so missing or failed analyzers are visible instead of silent.

## Experimental Promise

Auto-fix, PoC generation, mutation testing, and dynamic verification are reviewer
accelerators. They are not a substitute for explicit human approval, local test
harnesses, and safe execution boundaries.
