# VulnScout MCP Server

VulnScout ships a generic local MCP server for scanner automation and first-class
Joern CPG access. The server runs over stdio, reuses the existing VulnScout
Python scripts, and returns structured JSON for MCP hosts.

## Install

Required for the stable quick scan:

```bash
python3 -m pip install semgrep
```

Optional analyzer tools:

- Joern: required for `vulnscout_create_cpg`, `vulnscout_joern_query`, `vulnscout_joern_discover`, and CPG verification.
- CodeQL, Slither, Trivy, Checkov, gitleaks/truffleHog: used through `vulnscout_scan` when installed.

## Server Command

From the repository root:

```bash
python3 vuln-scout/scripts/mcp_server.py
```

Example MCP config:

```json
{
  "mcpServers": {
    "vuln-scout": {
      "command": "python3",
      "args": ["/path/to/vuln-scout/vuln-scout/scripts/mcp_server.py"]
    }
  }
}
```

## Tools

- `vulnscout_doctor` checks local readiness.
- `vulnscout_scan` runs quick, deep, or audit scans and returns `findings.json`.
- `vulnscout_report` renders JSON, SARIF, Markdown, HTML, PR comment, or bundle output.
- `vulnscout_create_cpg` creates or reuses cached Joern CPGs per language.
- `vulnscout_joern_query` runs a bounded raw local Joern CPGQL snippet against a CPG.
- `vulnscout_joern_discover` runs VulnScout's Joern discovery queries.
- `vulnscout_verify_findings` batch-verifies findings with Joern.
- `vulnscout_read_artifact` reads safe VulnScout artifacts from a workspace.

All path arguments are resolved inside the target workspace. Paths that escape
the workspace are rejected.

`vulnscout_report` returns the report path, exit code, and artifact summary by
default. Set `include_content: true` to include rendered Markdown/HTML/JSON text
in the MCP response; `max_content_bytes` caps the returned content.

Analyzer setup problems are returned as structured tool payloads. For example,
if Joern is installed but `joern-parse` cannot create a CPG for the target,
`vulnscout_create_cpg` returns `{"ok": false, "state": "failed", ...}` or
`{"ok": false, "state": "timed_out", ...}` instead of failing the MCP request.

## Resources

The server exposes template resources for host-side context loading:

- `vulnscout://findings/{workspace}`
- `vulnscout://review-ledger/{workspace}`
- `vulnscout://cpg-status/{workspace}`
- `vulnscout://tool-status/{workspace}`

Encode absolute workspace paths in the resource URI. Example:

```text
vulnscout://findings/%2Fpath%2Fto%2Frepo
```

## Prompts

- `verify-finding` guides CPG-backed finding verification.
- `triage-hotspots` ranks hotspots for manual review.
- `explain-cpg-path` turns CPG paths into reviewer-facing evidence.
- `review-pr-security` runs a diff-aware security review flow.

## Quick Smoke

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | python3 vuln-scout/scripts/mcp_server.py
```

Run the full local MCP smoke test:

```bash
python3 vuln-scout/scripts/mcp_smoke.py
```

Use `--require-joern` when the environment is expected to support CPG creation
and Joern query execution.

## Joern Query Example

Create a CPG first:

```json
{
  "target": "/path/to/repo",
  "language": "javascript"
}
```

Then run a bounded query:

```json
{
  "target": "/path/to/repo",
  "language": "javascript",
  "query": "cpg.method.name.l.take(20)"
}
```

The server returns stdout, stderr, the CPG path, and the Joern exit code.
It also returns `output`, a cleaned version of stdout with Joern loader chatter
removed for host display. Raw stdout/stderr remain available for debugging.

Raw CPGQL executes locally with the privileges of the MCP host process. Use it
for trusted workspaces and reviewer-controlled analysis.
