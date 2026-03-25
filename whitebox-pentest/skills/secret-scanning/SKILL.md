---
name: Secret Scanning
description: This skill should be used when the user asks about "secret scanning", "find secrets", "hardcoded credentials", "leaked API keys", "git history secrets", "credential scanning", "detect passwords in code", or needs to identify secrets and credentials in source code or git history during whitebox pentesting.
version: 1.0.0
---

# Secret Scanning Reference

## Purpose

Detect hardcoded secrets, API keys, credentials, and sensitive tokens in source code and git history. Secrets in code are among the most common and highest-impact findings in real-world penetration tests.

## When to Use

Activate this skill during:
- Initial code review phase to find low-hanging fruit
- Git history analysis for rotated but exposed credentials
- `.env` and configuration file review
- CI/CD pipeline security assessment

## High-Value Secret Patterns

### API Keys & Tokens

| Pattern | Regex | Severity |
|---------|-------|----------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | CRITICAL |
| AWS Secret Key | `[0-9a-zA-Z/+]{40}` (near AWS context) | CRITICAL |
| GitHub Token | `ghp_[0-9a-zA-Z]{36}` | HIGH |
| GitHub OAuth | `gho_[0-9a-zA-Z]{36}` | HIGH |
| GitLab Token | `glpat-[0-9a-zA-Z\-]{20}` | HIGH |
| Slack Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` | HIGH |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+` | MEDIUM |
| Stripe Secret Key | `sk_live_[0-9a-zA-Z]{24,}` | CRITICAL |
| Stripe Publishable | `pk_live_[0-9a-zA-Z]{24,}` | LOW |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | HIGH |
| Twilio API Key | `SK[0-9a-fA-F]{32}` | HIGH |
| SendGrid API Key | `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}` | HIGH |

### Private Keys & Certificates

| Pattern | Indicator | Severity |
|---------|-----------|----------|
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | CRITICAL |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | CRITICAL |
| SSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | CRITICAL |
| PKCS8 Key | `-----BEGIN PRIVATE KEY-----` | CRITICAL |
| Certificate | `-----BEGIN CERTIFICATE-----` | LOW |

### Database Credentials

| Pattern | Regex | Severity |
|---------|-------|----------|
| Connection String | `(postgres|mysql|mongodb)://[^:]+:[^@]+@` | CRITICAL |
| Redis URL | `redis://:[^@]+@` | HIGH |
| JDBC URL | `jdbc:(mysql|postgresql|oracle)://.*password=` | CRITICAL |

### JWT & Session Secrets

| Pattern | Regex | Severity |
|---------|-------|----------|
| JWT Secret | `(jwt|JWT).*secret.*=.*["'][^"']{8,}["']` | HIGH |
| Session Secret | `(session|SESSION).*secret.*=.*["'][^"']{8,}["']` | HIGH |
| Signing Key | `(signing|SIGNING).*key.*=.*["'][^"']{8,}["']` | HIGH |

## Methodology

### Step 1: Source Code Scanning

Search for secrets in the current codebase:

```bash
# AWS keys
grep -rniE "AKIA[0-9A-Z]{16}" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rb" --include="*.php"

# Private keys
grep -rn "BEGIN.*PRIVATE KEY" --include="*.pem" --include="*.key" --include="*.py" --include="*.js" --include="*.env"

# Connection strings with passwords
grep -rniE "(postgres|mysql|mongodb|redis)://[^:]+:[^@\s]+@" .

# Generic password/secret assignments
grep -rniE "(password|passwd|secret|api_key|apikey|access_token|auth_token)\s*[:=]\s*[\"'][^\"']{8,}" .

# .env files (often contain secrets)
find . -name ".env*" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null
```

### Step 2: Git History Scanning

Secrets may have been committed and later removed but remain in git history.

**Using gitleaks (recommended):**
```bash
gitleaks detect --source . --report-format json --report-path /tmp/gitleaks-results.json
```

**Using truffleHog:**
```bash
trufflehog filesystem . --json > /tmp/trufflehog-results.json
```

**Manual git history search:**
```bash
# Search for high-entropy strings in git history
git log -p --all -S "AKIA" -- . | head -100
git log -p --all -S "BEGIN RSA PRIVATE" -- . | head -100
git log -p --all -S "sk_live_" -- . | head -100
```

### Step 3: Configuration File Review

Check for secrets in configuration:

```bash
# Environment files
cat .env .env.local .env.production 2>/dev/null

# Docker compose secrets
grep -rniE "(password|secret|key|token)" docker-compose*.yml 2>/dev/null

# Kubernetes secrets (base64-encoded)
grep -rniE "data:" -A5 --include="*.yaml" --include="*.yml" | grep -v "^--$"

# CI/CD pipeline files
cat .github/workflows/*.yml .gitlab-ci.yml Jenkinsfile 2>/dev/null | grep -iE "(secret|password|token|key)"
```

### Step 4: Per-Language Hardcoded Credentials

**Python:**
```bash
grep -rniE "(os\.environ\.get|os\.getenv)\([\"'][^\"']+[\"'],\s*[\"'][^\"']{8,}" --include="*.py"
grep -rniE "password\s*=\s*[\"'][^\"']{4,}" --include="*.py"
```

**JavaScript/TypeScript:**
```bash
grep -rniE "process\.env\.\w+\s*\|\|\s*[\"'][^\"']{8,}" --include="*.js" --include="*.ts"
grep -rniE "const\s+\w*(secret|key|password|token)\w*\s*=\s*[\"']" --include="*.js" --include="*.ts"
```

**Java:**
```bash
grep -rniE "String\s+\w*(password|secret|key)\w*\s*=\s*\"" --include="*.java"
grep -rniE "\.setPassword\(\"[^\"]+\"\)" --include="*.java"
```

**Go:**
```bash
grep -rniE "(password|secret|apiKey|token)\s*[:=]\s*\"[^\"]{8,}" --include="*.go"
```

### Step 5: Classify and Report

For each secret found, determine:

| Factor | Assessment |
|--------|------------|
| **Scope** | Production, staging, or development? |
| **Rotation** | Is this a current or historical secret? |
| **Impact** | What does this secret grant access to? |
| **Exposure** | Is it in a public repo? In git history? |

**Severity mapping:**
- **CRITICAL**: Production credentials, cloud provider keys, database passwords
- **HIGH**: API keys with write access, JWT signing secrets
- **MEDIUM**: Read-only API keys, development credentials in non-dev branches
- **LOW**: Expired/rotated secrets, test/example credentials

## False Positive Indicators

- Example/placeholder values: `YOUR_API_KEY_HERE`, `changeme`, `xxxx`, `dummy`
- Test fixtures with fake credentials
- Documentation showing credential format
- Base64-encoded non-secret data (e.g., certificates vs private keys)
- Environment variable references without default values: `os.environ["KEY"]` (no hardcoded fallback)

## Integration with Findings Artifact

Map results to `.claude/findings.json` with:
- `type`: `"hardcoded-secret"`
- `kind`: `"finding"` (secrets are always reportable, not hotspots)
- `source_tool`: `"gitleaks"`, `"trufflehog"`, or `"manual"`
- `evidence`: Include the file, line, and a redacted excerpt (mask all but first 4 and last 4 characters)

## Integration with Other Skills

- Use **dangerous-functions** skill to find credential-handling code paths
- Use **security-misconfiguration** skill for exposed admin panels and debug endpoints
- Use **logging-failures** skill to check if secrets are leaked in log output
- Use **sensitive-data-leakage** skill for broader data exposure patterns
