---
name: OWASP Category Mapping
description: Use this skill when the user asks for OWASP Top 10 mapping, CWE alignment, or standards-oriented reporting. The directory name stays `owasp-2025` for backward compatibility, but external reports should use official OWASP Top 10 names.
version: 2.0.0
---

# OWASP Top 10 Reference

## Purpose

Map VulnScout findings to official OWASP Top 10 category names, highlight what the plugin covers well, and keep reports aligned with widely recognized security terminology.

## Reporting Rule

- Use official OWASP Top 10 names in user-facing reports.
- Treat the `owasp-2025` directory name as a compatibility alias, not as proof of a future OWASP taxonomy.
- Prefer CWE plus concrete vulnerability class when a finding does not fit cleanly into a single OWASP bucket.

## Coverage Overview

| OWASP Top 10 | VulnScout Coverage | Primary Skills |
|--------------|--------------------|----------------|
| A01: Broken Access Control | Strong | `business-logic`, `threat-modeling` |
| A02: Cryptographic Failures | Strong | `cryptographic-failures` |
| A03: Injection | Strong | `vuln-patterns`, `dangerous-functions`, `framework-patterns` |
| A04: Insecure Design | Strong | `business-logic`, `threat-modeling` |
| A05: Security Misconfiguration | Strong | `security-misconfiguration`, `framework-patterns` |
| A06: Vulnerable and Outdated Components | Out of scope | *(dependency and SBOM tooling)* |
| A07: Identification and Authentication Failures | Moderate | `vuln-patterns`, `business-logic` |
| A08: Software and Data Integrity Failures | Moderate | `vuln-patterns`, `sensitive-data-leakage` |
| A09: Security Logging and Monitoring Failures | Strong | `logging-failures`, `sensitive-data-leakage` |
| A10: Server-Side Request Forgery | Strong | `vuln-patterns`, `framework-patterns`, `vulnerability-chains` |

## Mapping Guidance

### A01: Broken Access Control

Use for:
- IDOR
- missing authorization checks
- role and tenant boundary bypasses
- unsafe direct access to user-controlled object identifiers

Common CWE anchors:
- CWE-284
- CWE-285
- CWE-639
- CWE-862
- CWE-863

### A02: Cryptographic Failures

Use for:
- weak or obsolete algorithms
- hardcoded secrets
- insecure randomness
- missing encryption on sensitive data paths

Common CWE anchors:
- CWE-326
- CWE-327
- CWE-330
- CWE-338
- CWE-798

### A03: Injection

Use for:
- SQL injection
- command injection
- SSTI
- XSS
- LDAP injection
- unsafe interpreter invocation

Common CWE anchors:
- CWE-77
- CWE-78
- CWE-79
- CWE-89
- CWE-90
- CWE-94

### A04: Insecure Design

Use for:
- missing rate limits or workflow controls
- trust boundary violations
- dangerous state transitions
- business logic flaws that are not just a missing authorization check

Common CWE anchors:
- CWE-209
- CWE-256
- CWE-501
- CWE-522
- CWE-656

### A05: Security Misconfiguration

Use for:
- debug mode in production
- insecure defaults
- exposed internal tooling
- missing hardening headers or framework safety controls

Common CWE anchors:
- CWE-16
- CWE-209
- CWE-215
- CWE-548
- CWE-756

### A06: Vulnerable and Outdated Components

Out of scope for this plugin's code-review workflow. If the user needs this category:
- hand off to dependency scanning, SBOM, or supply-chain tooling
- do not overstate coverage in VulnScout-generated reports

### A07: Identification and Authentication Failures

Use for:
- session fixation
- weak password or token validation
- authentication bypass
- unsafe MFA or reset flows

Common CWE anchors:
- CWE-287
- CWE-288
- CWE-294
- CWE-307
- CWE-384
- CWE-640

### A08: Software and Data Integrity Failures

Use for:
- unsafe deserialization
- integrity bypasses in update or build flows
- unsigned or unverified data loading
- missing signature verification

Common CWE anchors:
- CWE-345
- CWE-353
- CWE-502
- CWE-565
- CWE-784
- CWE-829

### A09: Security Logging and Monitoring Failures

Use for:
- log injection
- secrets in logs
- missing security event coverage
- missing or unusable audit trails for critical actions

Common CWE anchors:
- CWE-117
- CWE-223
- CWE-532
- CWE-778

### A10: Server-Side Request Forgery

Use for:
- server-side fetches of attacker-controlled URLs
- metadata service reachability
- internal pivoting through HTTP clients
- webhook, callback, and proxy misuse without host or protocol controls

Common CWE anchors:
- CWE-918

## Reporting Template

When mapping a finding, prefer this shape:

```markdown
- OWASP: A03 Injection
- CWE: CWE-89
- Why it fits: user-controlled input reaches SQL execution without parameter binding
```

## Guardrails

- Do not upgrade a `hotspot` into a reportable finding just to fill an OWASP bucket.
- If the best label is uncertain, keep the concrete vulnerability type and CWE, and state the OWASP category as provisional.
- Unsupported-language verification should remain `na_cpg`, not `false_positive`.
