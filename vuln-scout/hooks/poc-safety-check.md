---
name: poc-safety-check
description: Safety confirmation before PoC development and execution — blocks until user explicitly approves
event: PreToolUse
match_tool: Write,Bash
---

# PoC Safety Check Hook

When writing or executing files that appear to be exploit scripts, **block until the user explicitly approves**. This hook is advisory for Write operations (PoC creation) and **blocking for Bash operations** (PoC execution).

## Detection Patterns

Check if the operation matches exploit patterns:

**For Write (file creation):**
- Filename contains: `exploit`, `poc`, `payload`, `attack`, `pwn`
- File path contains: `exploits/`, `poc/`, `payloads/`, `/tmp/poc-`
- Content contains: exploit class patterns, shell commands, injection payloads

**For Bash (execution):**
- Command references: `/tmp/poc-`, `exploit.py`, `poc-*.py`, `poc-*.sh`
- Command contains: `--execute` flag with a PoC script path

## Safety Prompt

If exploit patterns detected, **BLOCK execution and display**:

```
⚠️ **PoC Execution Authorization Required**

You're about to [create/execute] what appears to be an exploit script.

**Target**: [finding ID and type]
**Script**: [file path]
**Mode**: [--dry-run / --execute]

Before proceeding, confirm:
1. [ ] You have explicit authorization to test the target system
2. [ ] This is being developed for a legitimate security assessment
3. [ ] The script includes safety controls (--dry-run, --check, cleanup())
4. [ ] You understand the potential impact of running this code

Type "yes" to proceed, "skip" to skip this PoC, or "abort" to stop all PoC execution.
```

**Behavior:**
- **"yes"**: Proceed with this PoC only
- **"skip"**: Skip this PoC, continue to next
- **"abort"**: Cancel all remaining PoC executions
- **Any other input**: Re-prompt (do NOT proceed)

This is a **blocking** check. Do NOT proceed without explicit "yes" from the user.

## Exploit Script Standards

When creating exploit scripts, ensure they include:

1. **Header Documentation:**
   ```python
   """
   Exploit: [Application Name] [Vulnerability Type]
   Target: [Endpoint/Function]
   Author: [Your Name]
   Date: [Date]
   Authorization: [Reference to authorization document]
   """
   ```

2. **Safety Features:**
   - `--check` flag for safe verification only
   - `--dry-run` flag to simulate without executing
   - Confirmation prompts for destructive actions
   - Cleanup functionality

3. **Non-Destructive Defaults:**
   - Default to read-only operations where possible
   - Require explicit flags for data modification
   - Include verification before exploitation
