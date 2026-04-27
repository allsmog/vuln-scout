# Full Audit Phase Contract

`/whitebox-pentest:full-audit` is a phase orchestrator, not a single scanner.
Keep these phases stable when editing the command prompt:

1. Scope and architecture discovery.
2. Threat model and audit-plan creation.
3. Adversarial review of the plan.
4. Automated scan plus manual source review of prioritized modules.
5. Verification, triage, and attack-chain review.
6. Report and machine-readable artifact generation.

The command may add detail for compatibility, but phase sequencing belongs here
so future edits do not duplicate or reorder the workflow accidentally.
