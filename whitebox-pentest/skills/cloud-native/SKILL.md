---
name: Cloud-Native Security
description: This skill should be used when the user asks about "cloud security", "AWS security", "GCP security", "Azure security", "Kubernetes security", "IMDS", "instance metadata", "S3 bucket policy", "IAM", "serverless security", "Lambda security", "container security", "cloud misconfiguration", "SSRF to cloud metadata", or needs to identify cloud-native security issues during whitebox pentesting.
version: 1.0.0
---

# Cloud-Native Security Patterns Reference

## Purpose

Identify security vulnerabilities specific to cloud-native environments, including IMDS exploitation, cloud provider misconfigurations, Kubernetes security issues, and serverless attack vectors. Cloud-native applications have unique trust boundaries and implicit assumptions that create vulnerability classes not present in traditional deployments.

## When to Use

Activate this skill when:
- Reviewing code that interacts with AWS, GCP, or Azure APIs
- Auditing Kubernetes manifests and Helm charts
- Assessing serverless functions (Lambda, Cloud Functions, Azure Functions)
- Evaluating SSRF findings for cloud metadata exploitation
- Reviewing Infrastructure as Code (Terraform, CloudFormation, Pulumi)
- Checking for hardcoded cloud credentials

## Instance Metadata Service (IMDS)

### Overview

Cloud instances expose a metadata service at a well-known IP address. SSRF vulnerabilities in cloud-hosted applications can be exploited to access this metadata, potentially leaking IAM credentials, instance identity tokens, and configuration data.

### IMDS Endpoints

| Provider | IPv4 Endpoint | IPv6 Endpoint | Protocol |
|----------|--------------|---------------|----------|
| AWS EC2 | `169.254.169.254` | `fd00:ec2::254` | HTTP |
| GCP | `metadata.google.internal` (`169.254.169.254`) | N/A | HTTP |
| Azure | `169.254.169.254` | N/A | HTTP |
| DigitalOcean | `169.254.169.254` | N/A | HTTP |
| Oracle Cloud | `169.254.169.254` | N/A | HTTP |

### AWS IMDSv1 vs IMDSv2

| Feature | IMDSv1 | IMDSv2 |
|---------|--------|--------|
| Request method | Simple GET | PUT to get token, then GET with token header |
| SSRF exploitable | Yes (single GET request) | Harder (requires PUT + custom header) |
| Mitigation | Disable or upgrade | Enforce IMDSv2-only via `HttpTokens: required` |

**IMDSv1 Exploitation** (simple GET):
```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

**IMDSv2 Exploitation** (requires PUT + header):
```
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
X-aws-ec2-metadata-token: <token>
```

**Detection Patterns**:
```bash
# References to IMDS IP addresses
grep -rniE "169\.254\.169\.254|fd00:ec2::254" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" --include="*.yaml" --include="*.yml" --include="*.tf" --include="*.json"

# GCP metadata endpoint
grep -rniE "metadata\.google\.internal|metadata-flavor.*Google" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java"

# Azure metadata
grep -rniE "169\.254\.169\.254.*Metadata.*true|Metadata.*169\.254\.169\.254" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java"

# URL fetch libraries that could be SSRF vectors to IMDS
grep -rniE "(requests\.get|urllib|http\.Get|axios|fetch)\s*\(" --include="*.py" --include="*.js" --include="*.ts" --include="*.go"
```

## AWS-Specific Patterns

### S3 Bucket Policy Misconfigurations

**Pattern**: S3 bucket policies with overly permissive Principal or Action statements.

```bash
# S3 bucket policy with wildcard principal
grep -rniE '"Principal"\s*:\s*"\*"|"Principal"\s*:\s*\{"AWS"\s*:\s*"\*"' --include="*.json" --include="*.tf" --include="*.yaml" --include="*.yml"

# Public ACL settings
grep -rniE "(PublicRead|public-read|public-read-write|authenticated-read)" --include="*.json" --include="*.tf" --include="*.yaml" --include="*.yml"

# S3 bucket creation without encryption
grep -rniE "aws_s3_bucket\b" --include="*.tf" -A 20 | grep -viE "(encryption|sse|kms)"

# Block public access disabled
grep -rniE "(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false" --include="*.tf"
```

### IAM Role Assumption Chains

**Pattern**: Overly permissive `sts:AssumeRole` policies that allow lateral movement or privilege escalation.

```bash
# IAM assume role policies
grep -rniE "sts:AssumeRole|sts:AssumeRoleWithWebIdentity|sts:AssumeRoleWithSAML" --include="*.json" --include="*.tf" --include="*.yaml" --include="*.yml"

# Wildcard IAM actions
grep -rniE '"Action"\s*:\s*"\*"|"Action"\s*:\s*\[.*"\*"' --include="*.json" --include="*.tf"

# Overly broad resource patterns
grep -rniE '"Resource"\s*:\s*"\*"' --include="*.json" --include="*.tf"
```

### STS Tokens and Access Keys

```bash
# Hardcoded AWS access keys
grep -rniE "AKIA[0-9A-Z]{16}" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" --include="*.env" --include="*.yaml" --include="*.yml" --include="*.tf"

# AWS secret keys (near AWS context)
grep -rniE "(aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[:=]\s*[\"'][0-9a-zA-Z/+]{40}" --include="*.py" --include="*.js" --include="*.ts" --include="*.env" --include="*.yaml"

# STS tokens in environment variables or code
grep -rniE "(AWS_SESSION_TOKEN|aws_session_token|SessionToken)\s*[:=]" --include="*.py" --include="*.js" --include="*.ts" --include="*.env" --include="*.yaml"

# AWS credentials in code (boto3)
grep -rniE "boto3\.(client|resource|Session)\s*\(" --include="*.py" -A 5 | grep -iE "(aws_access_key_id|aws_secret_access_key|aws_session_token)"
```

### AWS SDK Usage Patterns

```bash
# Detect AWS SDK usage
grep -rniE "^(import|from)\s+boto3|require\([\"']aws-sdk|@aws-sdk/" --include="*.py" --include="*.js" --include="*.ts"

# S3 operations
grep -rniE "\.(get_object|put_object|upload_file|download_file|list_objects)" --include="*.py"

# Dangerous AWS operations in code
grep -rniE "\.(create_user|attach_user_policy|put_role_policy|create_access_key)" --include="*.py"
```

## GCP-Specific Patterns

### Metadata Server Access

```bash
# GCP metadata endpoint usage
grep -rniE "metadata\.google\.internal" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java"

# GCP metadata headers
grep -rniE "Metadata-Flavor.*Google" --include="*.py" --include="*.js" --include="*.ts" --include="*.go"

# Service account key files
find . \( -name "*service-account*.json" -o -name "*credentials*.json" -o -name "*keyfile*.json" \) -not -path "*node_modules*" -not -path "*/.git/*" 2>/dev/null

# Hardcoded service account key content
grep -rniE '"type"\s*:\s*"service_account"' --include="*.json"

# GCP SDK usage
grep -rniE "from google\.cloud|google-cloud-|@google-cloud/" --include="*.py" --include="*.js" --include="*.ts"
```

### Default Compute Service Account

**Risk**: Applications running on GCP Compute Engine, GKE, or Cloud Functions may use the default service account, which often has the Editor role (overly broad permissions).

```bash
# Check for default service account references
grep -rniE "compute@developer\.gserviceaccount\.com|-compute@developer" --include="*.tf" --include="*.yaml" --include="*.yml" --include="*.json"

# GCP IAM bindings
grep -rniE "google_project_iam|google_service_account_iam" --include="*.tf" -A 10 | grep -iE "(roles/editor|roles/owner)"
```

## Azure-Specific Patterns

### Managed Identity Endpoint

```bash
# Azure IMDS endpoint
grep -rniE "169\.254\.169\.254.*metadata.*identity|IDENTITY_ENDPOINT|MSI_ENDPOINT" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" --include="*.cs"

# Azure SDK managed identity
grep -rniE "(DefaultAzureCredential|ManagedIdentityCredential|ChainedTokenCredential)" --include="*.py" --include="*.js" --include="*.ts" --include="*.cs"

# Azure Key Vault references in config
grep -rniE "(vault\.azure\.net|KeyVault|keyvault)" --include="*.py" --include="*.js" --include="*.ts" --include="*.cs" --include="*.yaml" --include="*.yml" --include="*.json"

# Hardcoded Azure credentials
grep -rniE "(AZURE_CLIENT_SECRET|AZURE_TENANT_ID|AZURE_CLIENT_ID)\s*[:=]\s*[\"']" --include="*.py" --include="*.js" --include="*.ts" --include="*.env" --include="*.yaml"
```

## Kubernetes Patterns

### ServiceAccount Token Exposure

**Risk**: Every pod mounts a ServiceAccount token at a well-known path. If an attacker gains code execution in a pod, they can use this token to interact with the Kubernetes API.

```bash
# ServiceAccount token path references
grep -rniE "/var/run/secrets/kubernetes\.io/serviceaccount/(token|ca\.crt|namespace)" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" --include="*.sh" --include="*.yaml"

# Kubernetes API access from within pods
grep -rniE "kubernetes\.default\.svc|KUBERNETES_SERVICE_HOST|kubernetes\.io/api" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java"

# automountServiceAccountToken not disabled
grep -rniE "automountServiceAccountToken" --include="*.yaml" --include="*.yml" | grep -viE "false"
```

### Host Path Volume Mounts

**Risk**: Mounting host filesystem paths into pods can expose sensitive host data or enable container escape.

```bash
# hostPath volume mounts
grep -rniE "hostPath:" --include="*.yaml" --include="*.yml" -A 3

# Dangerous host paths
grep -rniE "hostPath:" --include="*.yaml" --include="*.yml" -A 3 | grep -iE "(/|/etc|/var|/root|/home|/proc|/sys|docker\.sock)"

# Docker socket mount (container escape)
grep -rniE "docker\.sock|/var/run/docker" --include="*.yaml" --include="*.yml" --include="*.tf"
```

### Privileged Containers

**Risk**: Privileged containers have full access to the host kernel, enabling trivial container escape.

```bash
# Privileged flag
grep -rniE "privileged\s*:\s*true" --include="*.yaml" --include="*.yml" --include="*.tf"

# Dangerous capabilities
grep -rniE "(SYS_ADMIN|SYS_PTRACE|NET_ADMIN|ALL)" --include="*.yaml" --include="*.yml" -B 3 | grep -iE "(capabilities|add)"

# Running as root
grep -rniE "runAsUser\s*:\s*0|runAsNonRoot\s*:\s*false" --include="*.yaml" --include="*.yml"

# Missing security context
grep -rniE "containers:" --include="*.yaml" --include="*.yml" -A 30 | grep -viE "securityContext"
```

### RBAC Escalation

**Risk**: Overly permissive RBAC roles allowing lateral movement or privilege escalation within the cluster.

```bash
# ClusterRole with wildcard
grep -rniE "apiGroups.*\"\*\"|resources.*\"\*\"|verbs.*\"\*\"" --include="*.yaml" --include="*.yml"

# Dangerous verbs
grep -rniE "verbs:" --include="*.yaml" --include="*.yml" -A 1 | grep -iE "(create|delete|patch|escalate|bind|impersonate)"

# Secrets access
grep -rniE "resources:" --include="*.yaml" --include="*.yml" -A 1 | grep -iE "(secrets|configmaps)" -B 1

# Pod exec permissions
grep -rniE "resources.*pods/exec|resources.*pods/attach" --include="*.yaml" --include="*.yml"
```

## Serverless Patterns

### Environment Variable Secrets

**Risk**: Serverless functions commonly store secrets in environment variables, which can be leaked through error messages, SSRF, or debug endpoints.

```bash
# Lambda/Cloud Function environment variable secrets
grep -rniE "(Environment|environment|env):" --include="*.yaml" --include="*.yml" --include="*.tf" --include="*.json" -A 20 | grep -iE "(password|secret|key|token|api_key|database_url|connection_string)"

# Terraform Lambda environment variables
grep -rniE "environment\s*\{" --include="*.tf" -A 20 | grep -iE "(password|secret|key|token)"

# CloudFormation Lambda environment
grep -rniE "Environment:" --include="*.yaml" --include="*.yml" -A 20 | grep -iE "(password|secret|key|token)"

# Code reading env vars for secrets
grep -rniE "(os\.environ|process\.env|System\.getenv)\[.*?(PASSWORD|SECRET|KEY|TOKEN)" --include="*.py" --include="*.js" --include="*.ts" --include="*.java"
```

### Cold Start Race Conditions

**Risk**: During cold starts, serverless functions may have a window where initialization is incomplete, leading to race conditions with security implications (e.g., auth middleware not yet initialized).

```bash
# Global state initialization patterns
grep -rniE "^(let|var|const)\s+\w+;\s*$" --include="*.js" --include="*.ts" -A 5 | grep -iE "(client|connection|auth|db)"

# Lazy initialization patterns (potential race)
grep -rniE "if\s*\(\s*!\s*\w+(Client|Connection|Instance)\s*\)" --include="*.js" --include="*.ts" --include="*.py" -A 3
```

### Event Injection

**Risk**: Serverless functions triggered by events (S3, SQS, API Gateway, etc.) may trust event data without validation, enabling injection attacks.

```bash
# Lambda event handling without validation
grep -rniE "def\s+(handler|lambda_handler)\s*\(\s*event" --include="*.py" -A 20 | grep -iE "(event\[|event\.get)"

# Node.js Lambda event access
grep -rniE "exports\.(handler|main)\s*=\s*async" --include="*.js" --include="*.ts" -A 20 | grep -iE "(event\.|event\[)"

# Event data used in SQL/commands
grep -rniE "event\[" --include="*.py" -A 3 | grep -iE "(execute|query|system|subprocess|eval)"
```

## Infrastructure as Code Detection

```bash
# Find IaC files
find . \( -name "*.tf" -o -name "*.tfvars" -o -name "template.yaml" -o -name "template.json" -o -name "serverless.yml" -o -name "pulumi*.ts" -o -name "pulumi*.py" \) -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null

# Detect cloud provider usage
grep -rniE "^(provider|terraform)\s*\{" --include="*.tf"
grep -rniE "AWSTemplateFormatVersion|AWS::CloudFormation" --include="*.yaml" --include="*.yml" --include="*.json"
grep -rniE "pulumi\.(aws|gcp|azure)" --include="*.ts" --include="*.py"
```

## Methodology

### Step 1: Identify Cloud Environment

```bash
# Detect cloud SDKs in use
grep -rniE "^(import|from|require|use)\s+" --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" | grep -iE "(boto3|aws-sdk|@aws-sdk|google\.cloud|@google-cloud|azure|@azure)"

# Find IaC and deployment configs
find . \( -name "*.tf" -o -name "Dockerfile" -o -name "docker-compose*.yml" -o -name "*.yaml" -o -name "*.yml" \) -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null | head -50

# Find Kubernetes manifests
grep -rniE "apiVersion.*apps/v1|kind:\s*(Deployment|Service|Pod|StatefulSet)" --include="*.yaml" --include="*.yml"
```

### Step 2: Assess IMDS Exposure

1. Identify all HTTP client calls that accept user-controlled URLs (SSRF vectors)
2. Check if IMDS access is restricted (IMDSv2 enforcement, network policies)
3. Assess instance/pod IAM role permissions
4. Check for IMDS-specific URL blocklists in SSRF protections

### Step 3: Review Cloud Credentials

1. Scan for hardcoded access keys, secrets, and tokens
2. Check environment variable configuration for leaked credentials
3. Review IAM policies for overly broad permissions
4. Assess role assumption chains for privilege escalation paths

### Step 4: Audit Kubernetes Security

1. Review RBAC configuration for least privilege
2. Check for privileged containers and dangerous volume mounts
3. Verify ServiceAccount token automounting is disabled where unnecessary
4. Assess network policies for pod-to-pod isolation

### Step 5: Evaluate Serverless Security

1. Check for secrets in environment variables (use Secrets Manager/Key Vault instead)
2. Review event handler input validation
3. Assess function permissions (least privilege)
4. Check for cold start race conditions in auth initialization

### Step 6: Classify and Report

**Severity Mapping**:
- **CRITICAL**: Hardcoded AWS access keys, S3 bucket with `Principal: *` containing sensitive data, privileged container with host path mount, SSRF to IMDSv1
- **HIGH**: Overly permissive IAM roles, ServiceAccount token with cluster-admin, secrets in Lambda environment variables, Docker socket mount
- **MEDIUM**: IMDSv2 not enforced, GCP default compute service account, missing network policies, gRPC reflection in production
- **LOW**: Non-sensitive S3 bucket public access, missing Kubernetes security context with limited impact

## Integration with Findings Artifact

Map results to `.claude/findings.json` with:
- `type`: `"cloud-credential-exposure"`, `"imds-ssrf"`, `"s3-misconfiguration"`, `"iam-overpermission"`, `"k8s-privileged-container"`, `"k8s-rbac-escalation"`, `"serverless-secret-leak"`, or `"cloud-misconfiguration"`
- `kind`: `"finding"` for confirmed misconfigurations, `"hotspot"` for patterns requiring contextual review
- `source_tool`: `"manual"`, `"semgrep"`, or `"checkov"`
- `evidence`: Include the file, line, resource identifier, and description of the misconfiguration

## Integration with Other Skills

- Use **secret-scanning** to find hardcoded cloud credentials
- Use **vuln-patterns** for SSRF patterns that chain into IMDS exploitation
- Use **security-misconfiguration** for broader misconfiguration detection
- Use **data-flow-tracing** to trace user input to HTTP client calls (SSRF to IMDS)
- Use **framework-patterns** for cloud SDK framework-specific behaviors
