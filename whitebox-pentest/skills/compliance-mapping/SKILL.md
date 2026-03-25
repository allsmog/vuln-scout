---
name: Compliance Mapping
description: This skill should be used when the user asks about "compliance mapping", "PCI-DSS", "HIPAA", "SOC 2", "NIST CSF", "regulatory requirements", "compliance report", or needs to map security findings to compliance framework requirements.
version: 1.0.0
---

# Compliance Framework Mapping

## Purpose

Map VulnScout security findings to compliance framework requirements. This enables security teams to understand the regulatory impact of discovered vulnerabilities and prioritize remediation based on compliance obligations.

## Supported Frameworks

### PCI-DSS v4.0

Payment Card Industry Data Security Standard for organizations handling cardholder data.

| Requirement | Description | VulnScout Finding Types |
|-------------|-------------|------------------------|
| 6.2.1 | Secure development practices | All code-level findings |
| 6.2.2 | Software security training | Recurring pattern findings |
| 6.2.3 | Code review before release | Unverified findings in diff |
| 6.2.4 | Prevent common vulnerabilities | sql-injection, xss, command-injection, path-traversal |
| 6.3.1 | Identify vulnerabilities via scanning | All findings from /scan |
| 6.3.2 | Maintain inventory of custom software | Framework detection results |
| 6.4.1 | Public-facing web app protection | ssrf, xss, csrf, open-redirect |
| 6.4.2 | Automated technical solution for web attacks | WAF findings, missing CSP |
| 6.5.1-6.5.6 | Address common coding vulnerabilities | Injection, auth bypass, XSS, access control |

### HIPAA Security Rule (45 CFR 164.312)

Health Insurance Portability and Accountability Act technical safeguards.

| Section | Description | VulnScout Finding Types |
|---------|-------------|------------------------|
| 164.312(a)(1) | Access Control | access-control, idor, business-logic |
| 164.312(a)(2)(i) | Unique User Identification | auth-bypass, session fixation |
| 164.312(a)(2)(iii) | Automatic Logoff | session management findings |
| 164.312(a)(2)(iv) | Encryption at Rest | cryptographic-failures, hardcoded-secret |
| 164.312(b) | Audit Controls | logging-failures |
| 164.312(c)(1) | Integrity Controls | sql-injection, deserialization, ssti |
| 164.312(c)(2) | Authentication of ePHI | auth-bypass, hardcoded-secret |
| 164.312(d) | Person/Entity Authentication | auth-bypass, insecure-randomness |
| 164.312(e)(1) | Transmission Security | cryptographic-failures, ssrf |
| 164.312(e)(2)(i) | Integrity Controls (transmission) | ssti, xss, command-injection |
| 164.312(e)(2)(ii) | Encryption in Transit | cryptographic-failures |

### SOC 2 Trust Services Criteria

Service Organization Control 2 for SaaS and cloud service providers.

| Criteria | Description | VulnScout Finding Types |
|----------|-------------|------------------------|
| CC6.1 | Logical and Physical Access | access-control, idor, auth-bypass |
| CC6.2 | Credential Management | hardcoded-secret, insecure-randomness |
| CC6.3 | Access Roles and Responsibilities | access-control, business-logic |
| CC6.6 | System Boundary Protection | ssrf, open-redirect, cors-misconfig |
| CC6.7 | Data Flow Restrictions | path-traversal, xxe, deserialization |
| CC6.8 | Malicious Software Prevention | command-injection, code-injection, ssti |
| CC7.1 | System Monitoring | logging-failures, exception-handling |
| CC7.2 | Anomaly Detection | insecure-randomness, race-condition |
| CC7.3 | Security Event Evaluation | logging-failures |
| CC7.4 | Incident Response | All critical/high findings |
| CC8.1 | Change Management | Findings in diff (--since-commit) |

### NIST Cybersecurity Framework (CSF) 2.0

| Function | Category | VulnScout Finding Types |
|----------|----------|------------------------|
| **Identify** | ID.AM - Asset Management | Framework detection, scope results |
| **Identify** | ID.RA - Risk Assessment | Threat model, STRIDE analysis |
| **Protect** | PR.AC - Access Control | access-control, idor, auth-bypass |
| **Protect** | PR.DS - Data Security | sql-injection, path-traversal, cryptographic-failures |
| **Protect** | PR.IP - Protective Processes | All remediated findings |
| **Protect** | PR.MA - Maintenance | Diff-aware scan results |
| **Detect** | DE.AE - Anomalies and Events | logging-failures, exception-handling |
| **Detect** | DE.CM - Continuous Monitoring | /scan --since-commit results |
| **Respond** | RS.AN - Analysis | Verified findings with evidence |
| **Recover** | RC.IM - Improvements | Patch advisor recommendations |

## Finding Type to Compliance Mapping

| Finding Type | PCI-DSS | HIPAA | SOC 2 | NIST CSF |
|-------------|---------|-------|-------|----------|
| sql-injection | 6.2.4, 6.5.1 | 164.312(c)(1) | CC6.8 | PR.DS |
| xss | 6.2.4, 6.4.1 | 164.312(e)(2)(i) | CC6.8 | PR.DS |
| command-injection | 6.2.4 | 164.312(e)(2)(i) | CC6.8 | PR.DS |
| path-traversal | 6.2.4 | 164.312(a)(1) | CC6.7 | PR.DS |
| ssrf | 6.4.1 | 164.312(e)(1) | CC6.6 | PR.DS |
| deserialization | 6.2.4 | 164.312(c)(1) | CC6.7 | PR.DS |
| ssti | 6.2.4 | 164.312(c)(1) | CC6.8 | PR.DS |
| xxe | 6.2.4 | 164.312(c)(1) | CC6.7 | PR.DS |
| access-control | 6.5.4 | 164.312(a)(1) | CC6.1 | PR.AC |
| auth-bypass | 6.5.3 | 164.312(d) | CC6.1 | PR.AC |
| hardcoded-secret | 6.2.4 | 164.312(a)(2)(iv) | CC6.2 | PR.AC |
| cryptographic-failures | 6.2.4 | 164.312(e)(2)(ii) | CC6.2 | PR.DS |
| logging-failures | 6.2.4 | 164.312(b) | CC7.1 | DE.AE |
| insecure-randomness | 6.2.4 | 164.312(d) | CC7.2 | PR.DS |
| idor | 6.5.4 | 164.312(a)(1) | CC6.1 | PR.AC |
| ldap-injection | 6.2.4, 6.5.1 | 164.312(c)(1) | CC6.8 | PR.DS |

## Report Integration

When generating a compliance-aware report, use the `--compliance` flag:

```
/whitebox-pentest:report --compliance pci-dss,hipaa,soc2
```

This appends a Compliance Impact section to the report:

```markdown
## Compliance Impact

### PCI-DSS v4.0
| Requirement | Status | Findings |
|-------------|--------|----------|
| 6.2.4 | FAIL | 3 injection findings |
| 6.4.1 | PASS | No public-facing web app findings |

### HIPAA 164.312
| Section | Status | Findings |
|---------|--------|----------|
| 164.312(a)(1) | FAIL | 2 access control findings |
| 164.312(c)(1) | FAIL | 1 SQL injection finding |
```

## Methodology

### Step 1: Determine Applicable Frameworks
Ask the user which compliance frameworks apply to their organization.

### Step 2: Run Standard Audit
```
/whitebox-pentest:full-audit .
```

### Step 3: Map Findings to Requirements
Use the mapping table above to categorize each finding by its compliance impact.

### Step 4: Prioritize by Compliance Risk
Findings that affect multiple frameworks should be prioritized higher.

### Step 5: Generate Compliance Report
Include both the technical finding details and the compliance requirement references.

## Integration with Other Skills

- Use **business-logic** for access control requirement mapping (PCI-DSS 6.5.4, HIPAA 164.312(a))
- Use **cryptographic-failures** for encryption requirements (HIPAA 164.312(e), PCI-DSS 6.2.4)
- Use **logging-failures** for audit control requirements (HIPAA 164.312(b), SOC 2 CC7.1)
- Use **security-misconfiguration** for baseline hardening requirements
