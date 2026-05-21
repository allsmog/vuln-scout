---
name: cross-component
description: This skill should be used when analyzing multi-service architectures, frontend-backend interactions, microservices, or when looking for vulnerabilities that span multiple components. Use when the user asks about "cross-component", "frontend to backend", "service interaction", "internal service access", or "multi-service vulnerabilities".
---

# Cross-Component Security Analysis

Analyze how components interact and identify vulnerabilities that span service boundaries.

## Why Cross-Component Analysis Matters

Single-component analysis misses:
- SSRF in frontend reaching internal backend
- Auth bypass when backend trusts frontend headers
- Data leakage through shared databases
- Privilege escalation via service-to-service calls

## Step 1: Map the Architecture

### Find Orchestration Configs

```bash
# Docker Compose
find . -name "docker-compose*.yml" -o -name "docker-compose*.yaml"

# Supervisord
find . -name "supervisord.conf" -o -name "supervisor*.conf"

# Kubernetes
find . -name "*.k8s.yaml" -o -name "deployment*.yaml" -o -name "service*.yaml"

# PM2
find . -name "ecosystem.config.js" -o -name "pm2*.json"
```

### Extract Service Topology

```bash
# From docker-compose: services, ports, networks
grep -E "^\s+\w+:|ports:|expose:|depends_on:|networks:" docker-compose.yml

# From supervisord: programs and commands
grep -E "^\[program:|command=" supervisord.conf

# Internal-only services (not exposed externally)
grep -E "127\.0\.0\.1:|localhost:" docker-compose.yml supervisord.conf
```

### Generate Service Map

```markdown
## Service Topology

| Service | Port | Exposed | Language | Entry Points |
|---------|------|---------|----------|--------------|
| frontend | 1337 | ✅ External | Next.js | / |
| backend | 3000 | ❌ Internal | Flask | /api/* |
| redis | 6379 | ❌ Internal | - | - |

## Network Diagram

```
Internet → [1337] Next.js → [3000] Flask → [6379] Redis
                    ↓
              (Host header SSRF possible)
```
```

## Step 2: Identify Trust Boundaries

### Frontend → Backend Trust

```bash
# Does backend trust frontend headers?
grep -rn "X-User-ID\|X-Auth\|X-Forwarded\|X-Real-IP" --include="*.py" --include="*.go"

# Does backend skip auth for internal requests?
grep -rn "localhost\|127\.0\.0\.1\|internal" --include="*.py" --include="*.go" | grep -i "auth\|skip\|bypass"
```

### Service-to-Service Auth

```bash
# Find internal API calls
grep -rn "fetch\|requests\.\|http\.get" --include="*.ts" --include="*.py" | grep -E "localhost|127\.0\.0\.1|internal"

# Check for hardcoded service tokens
grep -rn "SERVICE_TOKEN\|INTERNAL_API_KEY\|X-Internal" --include="*.ts" --include="*.py" --include="*.env*"
```

## Step 3: Find Cross-Component Attack Paths

### SSRF → Internal Service

**Pattern**: External service has SSRF, internal service has high-impact vulnerability

```bash
# Step 1: Find SSRF in external service
grep -rn "redirect\|fetch\|requests\." --include="*.ts" --include="*.tsx" front-end/

# Step 2: Find sinks in internal service
grep -rn "render_template_string\|eval\|exec\|deserialize" --include="*.py" backend/

# Step 3: Check if SSRF can reach internal sink
# - Same network/container?
# - Internal port accessible?
# - User input reaches sink?
```

### Header Injection → Auth Bypass

**Pattern**: Frontend sets headers that backend trusts blindly

```bash
# Frontend setting user headers
grep -rn "X-User\|X-Auth\|headers.*user" --include="*.ts" front-end/

# Backend trusting headers
grep -rn "request\.headers\[" --include="*.py" backend/ | grep -v "Authorization"
```

### Shared Database → Data Leakage

**Pattern**: Frontend and backend share DB, one has SQLi

```bash
# Find database connection strings
grep -rn "DATABASE_URL\|POSTGRES\|MYSQL\|MONGO" --include="*.env*"

# If same DB, check both services for injection
grep -rn "query\|execute\|rawQuery" --include="*.ts" --include="*.py"
```

## Step 4: Document Attack Chains

### Chain Template

```markdown
## Attack Chain: [Name]

**Severity**: CRITICAL/HIGH/MEDIUM

**Components**:
1. [Service A] - [Vulnerability] at [location]
2. [Service B] - [Vulnerability] at [location]

**Attack Flow**:
1. Attacker sends request to [external service]
2. [Vulnerability 1] causes [effect]
3. [Effect] reaches [internal service]
4. [Vulnerability 2] is triggered
5. Impact: [RCE/Data Breach/etc.]

**Evidence**:
- `frontend/serverActions.tsx:15` - redirect() with Host header control
- `backend/routes.py:87` - render_template_string() with user input
- `supervisord.conf` - both services on same network
```

## Common Cross-Component Patterns

### Next.js + Flask (DoxPit Pattern)

```
Next.js (port 1337, external)
    │
    │ Server Action redirect()
    │ + attacker Host header
    ▼
Attacker Server
    │
    │ 302 Redirect to internal
    ▼
Flask (port 3000, internal)
    │
    │ render_template_string()
    │ with user input
    ▼
RCE via Jinja2 SSTI
```

### React + Express + MongoDB

```
React (external)
    │
    │ GraphQL query
    ▼
Express (external)
    │
    │ NoSQL injection in query
    ▼
MongoDB
    │
    │ Data exfiltration
    ▼
Credential theft
```

### Microservices with Message Queue

```
API Gateway (external)
    │
    │ Message to queue
    ▼
Message Queue (internal)
    │
    │ Deserialization
    ▼
Worker Service (internal)
    │
    │ Command injection
    ▼
RCE
```

## Checklist

- [ ] Mapped all services and their exposed ports
- [ ] Identified internal-only services (SSRF targets)
- [ ] Checked trust relationships between services
- [ ] Searched for SSRF in external services
- [ ] Searched for high-impact sinks in internal services
- [ ] Verified if SSRF can reach internal sinks
- [ ] Documented any attack chains found
- [ ] Included cross-component findings in report
