# Full Audit Safety Contract

Full-audit automation must stay reviewer-driven:

- Do not execute PoCs unless the user explicitly opts into dynamic verification.
- Generated PoC scripts must default to dry-run behavior.
- Auto-fix output must be shown for review before patching unless the caller has
  explicitly requested a branch or PR workflow.
- `needs_review` findings must remain unresolved until evidence supports
  `verified` or `false_positive`.
- Headless mode must avoid interactive prompts and record unresolved review
  state instead of silently approving it.
