# VulnScout Release Checklist

Run these checks before publishing a release:

```bash
python3 -m pytest
python3 whitebox-pentest/scripts/check_consistency.py
python3 whitebox-pentest/scripts/validate_evals.py
python3 whitebox-pentest/benchmarks/run_benchmark.py --list
node -e "import('./kuzushi-module.js').then(() => console.log('import ok'))"
npm --cache /tmp/vuln-scout-npm-cache pack --dry-run
```

Product checks:

- `python3 whitebox-pentest/scripts/doctor.py --strict` reports quick-profile readiness.
- `demo/vulnerable-app` quick scan produces the documented expected findings.
- Markdown, HTML, SARIF, and JSON reports render from `.claude/findings.json`.
- `tool_status` is present when scans request external tools.
- Benchmark quality gates are run before evidence-based release claims, for example
  `python3 whitebox-pentest/benchmarks/run_benchmark.py --all --profile quick --quality-gate`.
- Package dry-run excludes tests, `.pytest_cache`, and `__pycache__`.

Documentation checks:

- README describes the primary user and golden workflow.
- Feature maturity labels match implementation evidence.
- Troubleshooting covers Semgrep network errors, Joern, CodeQL, and plugin install.
- Changelog includes notable user-facing changes.
