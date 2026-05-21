# PR Review

Use the diff workflow when reviewing a branch against a base ref.

```text
/vuln-scout:diff origin/main
```

Verify only the new or changed findings:

```text
/vuln-scout:verify --from .claude/diff-findings.json
```

Render the Markdown payload for a PR comment:

```text
/vuln-scout:report --format pr-comment --output pr-comment.md
```

For review handoff, package the evidence bundle after verification:

```text
/vuln-scout:report --format bundle --output evidence-bundle
```
