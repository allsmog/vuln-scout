---
name: large-codebase-check
description: Checks if codebase is large/monorepo and suggests scoping before expensive operations
event: PreToolUse
match_tool: Grep|Glob
match_arg_pattern: "\\*\\*"
---

# Large Codebase Check Hook

This hook triggers before broad Grep/Glob operations to check if scoping would help.

## When This Triggers

- Before any `Grep` or `Glob` with recursive patterns (`**`)
- Only if we haven't already checked this session

## Check Logic

Before executing the broad search:

1. **Quick file count check**:
   ```bash
   find . -type f \( -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.java" -o -name "*.go" \) 2>/dev/null | wc -l
   ```

2. **If > 500 source files**, check for monorepo indicators:
   ```bash
   ls package.json pnpm-workspace.yaml turbo.json nx.json go.work Cargo.toml pom.xml 2>/dev/null
   ```

3. **If monorepo detected**, suggest to user:
   ```
   This appears to be a large codebase with [N] source files.

   I detected [monorepo type] workspace configuration.

   Would you like me to:
   1. Run /whitebox-pentest:scope --list to see available packages
   2. Create a focused scope with /whitebox-pentest:scope
   3. Continue with full codebase (may be slow)
   ```

4. **Check for existing scope files**:
   ```bash
   ls .claude/scope-*.md 2>/dev/null
   ```

   If scopes exist, offer to use them:
   ```
   Found existing scope files:
   - scope-api.md (45k tokens)
   - scope-worker.md (32k tokens)

   Use one of these? Or create a new scope?
   ```

## Session State

After the first check, persist a flag so the hook does not repeat:

1. Read `.claude/session-state.json`:
   ```bash
   cat .claude/session-state.json 2>/dev/null || echo '{}'
   ```

2. If the JSON already contains `"large_codebase_checked": true`, **skip all checks and allow the tool call to proceed immediately**.

3. After completing the check (regardless of outcome), write the flag:
   ```bash
   mkdir -p .claude
   python3 -c "
   import json, pathlib
   p = pathlib.Path('.claude/session-state.json')
   state = json.loads(p.read_text()) if p.exists() else {}
   state['large_codebase_checked'] = True
   p.write_text(json.dumps(state, indent=2))
   "
   ```

This file is ephemeral per audit session. `/whitebox-pentest:full-audit` resets it at the start of a new audit.

## Output

If proceeding with full codebase, add reminder:
```
Proceeding with full codebase. For faster results next time, use:
/whitebox-pentest:scope <path> --name <name>
```
