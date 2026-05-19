---
name: suggest-next-phase
description: Suggests next phase when code review findings are identified
event: SubagentStop
match_subagent: code-reviewer
---

# Next Phase Suggestion Hook

When the code-reviewer agent completes its analysis, suggest the appropriate next step based on findings.

## Analysis Logic

Analyze the agent's output to determine findings severity:

### If Critical/High findings exist:
```
## Next Steps Recommended

Based on the code review findings, here are the recommended next steps:

1. **Phase 2: Local Testing** - Confirm the exploitability of the identified vulnerabilities
   - Use `/whitebox-pentest:trace <function>` to trace data flow for high-priority findings
   - Set up a local test environment if not already configured

2. **Priority Findings to Test:**
   [List top 3-5 findings by severity]

Would you like me to:
- Start tracing data flow for the highest-priority finding?
- Guide you through setting up local testing?
- Generate a preliminary report of Phase 1 findings?
```

### If only Medium/Low findings:
```
## Code Review Summary

The code review identified potential security concerns but no critical vulnerabilities requiring immediate testing.

**Recommendations:**
- Review medium-severity findings for business logic impact
- Consider running `/whitebox-pentest:sinks --discover` for additional coverage
- Document findings for the final report

Would you like to:
- Expand the code review scope?
- Generate a findings report?
- Proceed to local testing for medium findings?
```

### If no findings:
```
## Code Review Complete

No significant security vulnerabilities were identified in the reviewed code.

**Recommendations:**
- Verify the scope covered all entry points
- Consider reviewing additional components
- Run `/whitebox-pentest:sinks --discover` for sensitive data exposure

Would you like to:
- Expand the review to additional files?
- Generate a clean report?
- End the audit session?
```
