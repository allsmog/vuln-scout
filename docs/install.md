# Install VulnScout

## Prerequisites

- Python 3.9 or newer
- Semgrep for the stable `quick` scan profile
- Claude Code for slash-command workflows
- Optional deep analyzers: Joern, CodeQL, Slither, Trivy, Checkov

```bash
python3 -m pip install semgrep
```

## Marketplace Install

```bash
claude plugin install vuln-scout
```

## Local Zip Or Directory Testing

```bash
git clone https://github.com/allsmog/vuln-scout
cd vuln-scout
claude --plugin-dir ./vuln-scout
```

The canonical local plugin root is `./vuln-scout` from the repository root. To test one-release deprecated aliases locally, load the compatibility plugin root:

```bash
claude --plugin-dir ./whitebox-pentest
```

## Kuzushi Runtime

```bash
npm install @kuzushi/vuln-scout
```

## MCP Runtime

Use this local stdio server for MCP hosts that should call VulnScout scanner, report, artifact, and Joern CPG tools directly:

```bash
python3 vuln-scout/scripts/mcp_server.py
```

See [MCP integration](mcp.md) for host configuration and tool details.

## Contributor Symlink

Use this only when developing the plugin locally and you need Claude Code to read live files from a checkout.

```bash
mkdir -p .claude/plugins
ln -s /path/to/vuln-scout/vuln-scout .claude/plugins/vuln-scout
```

## Verify

```bash
python3 vuln-scout/scripts/doctor.py --strict
```

Then run the canonical five-minute demo:

```bash
python3 vuln-scout/scripts/scan_orchestrator.py demo/vulnerable-app --profile quick --output /tmp/vuln-scout-demo-findings.json
python3 vuln-scout/scripts/report.py /tmp/vuln-scout-demo-findings.json --format html --output report.html
```

Expected quick-profile result: two high findings and two medium findings. After the script path works, use the Claude Code workflow:

```text
/vuln-scout:full-audit demo/vulnerable-app
```
