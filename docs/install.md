# Install VulnScout

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

Then run the canonical first audit:

```text
/vuln-scout:full-audit demo/vulnerable-app
```
