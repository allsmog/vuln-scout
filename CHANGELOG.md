# Changelog

## Unreleased

- Added first-class local MCP server with scanner, report, artifact, and Joern CPG tools.
- Fixed Homebrew Joern JavaScript/Python CPG creation for MCP and CLI workflows.
- Added deterministic `quick`, `deep`, and `audit` scan profiles.
- Added bundled offline Semgrep rules for first-run validation and CI smoke scans.
- Added `doctor.py` for local runtime readiness checks.
- Added a vulnerable demo target with expected quick-profile findings.
- Added product maturity, troubleshooting, CI template, and release checklist docs.
- Improved reports with tool status, confidence, suppression counts, and next actions.
- Unified Kuzushi runtime version metadata with `package.json` and added consistency checks.
- Added per-tool analyzer status details, benchmark quality gates, safer generated PoC defaults, and shared full-audit prompt fragments.
- Added evidence bundle report output and opt-in CodeQL model pack generation from verified findings.

### Deprecated

- Deprecated `--no-claude-analysis` in favor of `--no-semantic-analysis`; the old flag remains as an alias until v3.3.0.
