# Migrating From 3.x To 3.2

VulnScout 3.2 collapses the old `whitebox-pentest` product name into the canonical `vuln-scout` name.

## Slash Commands

Update hardcoded command references:

```text
/whitebox-pentest:full-audit
/vuln-scout:full-audit
```

Deprecated `/whitebox-pentest:*` shim files remain for one release and print a rename notice. Marketplace and npm package installs include a small `whitebox-pentest` compatibility plugin root that contains only those shims.

## Plugin Directory

Update local plugin paths:

```text
whitebox-pentest/
vuln-scout/
```

For local testing, prefer:

```bash
claude --plugin-dir ./vuln-scout
```

To test the deprecated aliases directly:

```bash
claude --plugin-dir ./whitebox-pentest
```

## Marketplace Install

Use the new marketplace name:

```bash
claude plugin install vuln-scout
```

## Audit Profile Flag

`--no-claude-analysis` is deprecated. Use `--no-semantic-analysis`; the old flag remains as an alias until v3.3.0.
