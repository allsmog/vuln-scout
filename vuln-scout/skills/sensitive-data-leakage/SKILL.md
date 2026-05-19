---
name: Sensitive Data Leakage
description: Detect ANY credential/secret flowing to ANY output sink. Use when asked about "credential leakage", "secret logging", "sensitive data exposure", "CWE-532", "password in logs", "token exposure", or security logging issues.
version: 2.1.0
---

# Generic Sensitive Data Leakage Detection

## Core Principle

```
IF data MATCHES sensitive_pattern
   AND data FLOWS TO output_sink
THEN potential_leak
```

This skill detects credentials, secrets, and sensitive data flowing to logging, error messages, HTTP responses, or any other output - regardless of which libraries the codebase uses.

## Phase 1: Identify Sensitive Data (Sources)

### 1.1 Sensitive Naming Patterns

Search for variables, fields, parameters with these patterns:

**Go:**
```bash
grep -rniE "(secret|password|passwd|pwd|apikey|api_key|token|credential|private.?key|access.?key|auth.?token|bearer|encryption.?key|signing.?key|client.?secret|consumer.?secret|conn.?str|connection.?string)" --include="*.go" | grep -v "_test\.go"
```

**Python:**
```bash
grep -rniE "(secret|password|passwd|pwd|apikey|api_key|token|credential|private.?key|access.?key|auth.?token|bearer)" --include="*.py" | grep -v "test_"
```

**Java:**
```bash
grep -rniE "(secret|password|passwd|pwd|apiKey|api_key|token|credential|privateKey|accessKey|authToken|bearer)" --include="*.java" | grep -v "Test\.java"
```

**JavaScript/TypeScript:**
```bash
grep -rniE "(secret|password|passwd|pwd|apiKey|api_key|token|credential|privateKey|accessKey|authToken|bearer)" --include="*.js" --include="*.ts" | grep -v "\.test\." | grep -v "\.spec\."
```

### 1.2 Sensitive Function Returns

```bash
# Functions that return/fetch secrets (Go)
grep -rniE "func.*(Get|Read|Fetch|Load|Decrypt|Retrieve).*(Secret|Password|Key|Token|Cred)" --include="*.go"

# Assignments from credential functions
grep -rniE "(secret|password|key|token|cred).*:?=.*(Get|Read|Fetch|Load|Decrypt|Retrieve)" --include="*.go"
```

### 1.3 Sensitive Struct/Class Fields

```bash
# Go struct fields
grep -rniE "^\s+(Secret|Password|Key|Token|Credential|ApiKey|PrivateKey|AccessKey)\s+\S+" --include="*.go"

# Python class attributes
grep -rniE "self\.(secret|password|key|token|credential|api_key)" --include="*.py"

# Java fields
grep -rniE "(private|protected|public)\s+\S+\s+(secret|password|key|token|credential)" --include="*.java"
```

### 1.4 Environment Variables

```bash
# Go
grep -rniE "os\.Getenv\([\"'].*?(SECRET|PASSWORD|KEY|TOKEN|CREDENTIAL|API_KEY)" --include="*.go"

# Python
grep -rniE "os\.environ\.get\([\"'].*?(SECRET|PASSWORD|KEY|TOKEN|CREDENTIAL|API_KEY)" --include="*.py"

# Node.js
grep -rniE "process\.env\.(SECRET|PASSWORD|KEY|TOKEN|CREDENTIAL|API_KEY)" --include="*.js" --include="*.ts"
```

## Phase 2: Identify Output Sinks

### 2.1 Discover Logging Library Used

```bash
# Go - find log imports
grep -rniE "^import|^\t\"" --include="*.go" | grep -iE "log|zap|logrus|zerolog|klog|glog|slog" | head -10

# Find actual log function calls
grep -rhoE "\w+\.(Error|Info|Debug|Warn|Fatal|Print|Log|Msg)(f|ln|w|Context)?\s*\(" --include="*.go" | sort | uniq -c | sort -rn | head -20
```

### 2.2 All Logging Calls (Generic)

```bash
# Matches ANY logging library
grep -rniE "\.(log|print|error|warn|info|debug|fatal|trace|notice|output|write|emit|send|record)(f|ln|w)?\s*\(" --include="*.go" --include="*.py" --include="*.java" --include="*.js"
```

### 2.3 Error Creation/Wrapping

```bash
# Go
grep -rniE "(fmt\.Errorf|errors\.New|errors\.Wrap|errors\.Wrapf|fmt\.Sprintf.*[Ee]rr)" --include="*.go"

# Python
grep -rniE "(raise\s+\w+Exception|raise\s+\w+Error)" --include="*.py"

# Java
grep -rniE "throw\s+new\s+\w+Exception" --include="*.java"
```

### 2.4 HTTP Responses

```bash
# Go
grep -rniE "(\.Write\(|\.WriteString\(|json\.Encode|\.JSON\(|c\.String\(|w\.Write)" --include="*.go"

# Python (Flask/Django)
grep -rniE "(jsonify|JsonResponse|Response\(|return.*json)" --include="*.py"

# Node.js
grep -rniE "(res\.send|res\.json|res\.write|response\.send)" --include="*.js" --include="*.ts"
```

## Phase 3: Find Dangerous Intersections

### 3.1 Sensitive Variable in Log Call

```bash
# Direct pattern - sensitive var name in log arguments
grep -rniE "(log|print|error|warn|info|debug|fatal)\w*\(.*\b(secret|password|key|token|cred|apikey)\w*\b" --include="*.go" | grep -v "_test\.go"
```

### 3.2 Format String Struct Dumps (%v, %+v, %#v)

```bash
# These format verbs dump ALL struct fields including secrets
grep -rniE "%[+#]?v" --include="*.go" | grep -v "_test\.go"

# More specific - %v with config/options types
grep -rniE "(Error|Info|Debug|Warn|Print|Log)(f|w)?\(.*%[+#]?v.*(config|option|session|setting|client|request)" --include="*.go"
```

### 3.3 Sensitive Data Passed to Format Functions

```bash
# Sensitive variable as argument to printf-style function
grep -rniE "(printf|errorf|sprintf|infof|debugf|warnf|fatalf)\([^)]+,\s*\w*(secret|password|key|token|cred)" --include="*.go"
```

### 3.4 Error Returns Containing Secrets

```bash
# Functions returning errors with sensitive data
grep -rniE "return.*(fmt\.Errorf|errors\.).*%(v|s|w).*\w*(secret|password|key|token|config|opt)" --include="*.go"
```

## Phase 4: Contextual Analysis (Critical for Avoiding False Positives)

For each finding, verify:

| Check | Question | How to Verify |
|-------|----------|---------------|
| **Is it actually sensitive?** | Not a map key, keyboard key, or generic "key" | Check variable usage context |
| **Does it reach output?** | Trace variable through code to log/response | Follow data flow |
| **Has safe String() method?** | Struct implements fmt.Stringer that redacts secrets? | `grep -A10 "func (.*TypeName) String()"` |
| **Format verb?** | Using %+v/%#v? (these bypass String() methods) | Check format string - `%s` and `%v` use String() |
| **Is it SDK error?** | SDK errors rarely contain config structs | Don't flag SDK error logging by default |
| **Log level?** | Debug logs may be disabled in prod | Lower severity for debug-only |

### Critical: Always Check for String() Method

Before flagging any struct being logged:
```bash
# For a struct named "Server" or "Config":
grep -rn "func (.*Server) String()" --include="*.go"
grep -rn "func (.*Config) String()" --include="*.go"
```

If a safe `String()` method exists that omits credentials → **NOT a vulnerability** (unless `%+v` or `%#v` is used)

## Phase 5: Common Vulnerable Patterns

### Pattern 1: Direct Struct Dump with Credentials
```go
// VULNERABLE: struct with credentials logged directly
type Config struct {
    Region    string
    SecretKey string  // Sensitive!
}
log.Warnf("Config issue: %+v", config)  // Dumps ALL fields including SecretKey
log.Warnf("Server error: %s", server)   // ONLY vulnerable if Server lacks safe String() method
```

**IMPORTANT**: Before flagging struct logging, check if the struct has a custom `String()` method:
```bash
# Check for safe String() implementation
grep -A5 "func (.*TypeName) String()" --include="*.go"
```
If the struct has a `String()` method that omits sensitive fields, logging with `%s` or `%v` is SAFE.

### Pattern 2: Config Struct Dump
```go
// VULNERABLE: config.SecretKey exposed
log.Debugf("Using config: %+v", config)
```

### Pattern 3: Request Logging
```go
// VULNERABLE: Authorization header exposed
log.Infof("Request: %+v", req)
log.Infof("Headers: %v", req.Header)
```

### Pattern 4: Error Chain Propagation
```go
// VULNERABLE: secret propagates up call stack
err := connectWithSecret(secretKey)
return fmt.Errorf("connection failed: %w", err)  // wraps error containing secret
```

### Pattern 5: Response Body Logging
```go
// VULNERABLE: response may contain tokens
body, _ := ioutil.ReadAll(resp.Body)
log.Debugf("Response: %s", body)  // May contain access_token, refresh_token
```

## Quick Scan Commands

### All-in-One Scan (Go)

```bash
#!/bin/bash
echo "=== Sensitive Data Leakage Scan ==="

echo -e "\n[1] Sensitive identifiers in log calls:"
grep -rniE "(log|print|error|warn|info|debug|fatal)\w*\([^)]*\b(secret|password|key|token|cred|apikey)\w*" --include="*.go" | grep -v "_test\.go" | head -20

echo -e "\n[2] Struct dumps with %v/%+v:"
grep -rniE "(Error|Info|Debug|Warn|Print)(f)?\([^)]*%[+#]?v" --include="*.go" | grep -v "_test\.go" | head -20

echo -e "\n[3] Sensitive data in error creation:"
grep -rniE "(Errorf|Wrapf?|New)\([^)]*\b(secret|password|key|token|cred)" --include="*.go" | grep -v "_test\.go" | head -20

echo -e "\n[4] Config/Options types being logged:"
grep -rniE "(log|print)\w*\([^)]*(config|option|session|setting|credential)" --include="*.go" | grep -v "_test\.go" | head -20

echo -e "\n=== Scan Complete ==="
```

### Format String Audit

```bash
# Find all %v/%+v usage for manual review
grep -rn "%+v\|%#v" --include="*.go" | grep -v "_test\.go" | while read line; do
    file=$(echo "$line" | cut -d: -f1)
    linenum=$(echo "$line" | cut -d: -f2)
    echo "[$file:$linenum] $(echo "$line" | cut -d: -f3-)"
done
```

## Remediation

### Fix 1: Log Only Error Message
```go
// Before (vulnerable)
log.Errorf("Failed: %v", err)

// After (safe)
log.Errorf("Failed: %s", err.Error())
```

### Fix 2: Implement fmt.Stringer Interface
```go
func (c *Config) String() string {
    return fmt.Sprintf("Config{Region: %s, Bucket: %s}",
        c.Region, c.Bucket)
    // Omit SecretKey, Password, etc.
}
```

### Fix 3: Use Structured Logging with Explicit Fields
```go
// Only log non-sensitive fields
logger.Error("connection failed",
    zap.String("region", config.Region),
    zap.String("endpoint", config.Endpoint),
    // Don't include: zap.String("secret", config.SecretKey)
)
```

### Fix 4: Redact Before Logging
```go
func redact(s string) string {
    if len(s) <= 4 {
        return "****"
    }
    return s[:2] + "****" + s[len(s)-2:]
}

log.Infof("Using key: %s", redact(apiKey))
```

### Fix 5: Use Log Sanitization Middleware
```go
// Wrap logger to auto-redact patterns
type RedactingLogger struct {
    inner Logger
    patterns []*regexp.Regexp
}

func (l *RedactingLogger) Errorf(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    msg = l.redactPatterns(msg)
    l.inner.Errorf("%s", msg)
}
```

## Common False Positives to Avoid

Before reporting a finding, verify it's not one of these common false positives:

### FP 1: SDK Error Logging
```go
// USUALLY NOT VULNERABLE
session, err := session.NewSessionWithOptions(opts)
if err != nil {
    log.Errorf("Failed to create session: %v", err)  // err is just an error message
}
```
**Why it's usually safe**: SDK errors typically contain descriptive error messages, NOT the config struct with credentials. The `err` object from most SDKs (AWS, GCP, Azure) does not embed or reference the options/config passed to the function.

**When it IS vulnerable**: Only if the SDK explicitly includes config in error (rare), or if wrapping an error that contains sensitive data.

### FP 2: Struct with Safe String() Method
```go
// NOT VULNERABLE if Server has safe String() method
log.Warnf("Server issue: %s", server)

// Check: Does Server implement String()?
func (s *Server) String() string {
    return s.ID + "=>" + s.Address  // Safe - omits credentials
}
```
**Verification**: Always grep for `func (.*StructName) String()` before flagging.

### FP 3: Generic "key" or "token" Variable Names
```go
// NOT VULNERABLE - these are map keys, not secrets
for key, value := range items {
    log.Debugf("Processing key: %s", key)
}

// NOT VULNERABLE - JWT token parsing (token is being validated, not a secret)
token, err := jwt.Parse(tokenString, keyFunc)
```
**Verification**: Check context - is "key" a cryptographic key or a map/dictionary key?

### FP 4: Error Contains Path, Not Credentials
```go
// USUALLY NOT VULNERABLE
credsJSON, err := ioutil.ReadFile(storageCredsPath)
if err != nil {
    log.Errorf("Unable to read credentials: %v", err)  // err contains file path, not credentials
}
```
**Why it's usually safe**: File read errors contain the path and OS error, not file contents.

**When it IS vulnerable**: If the path itself is sensitive (contains account IDs, etc.)

## Verification Checklist

Before reporting any credential logging finding, verify:

| Step | Check | If No → |
|------|-------|---------|
| 1 | Is the logged variable actually a struct with credentials? | Not a vulnerability |
| 2 | If struct: Does it have a custom `String()` method? | If safe String() exists → Not vulnerable |
| 3 | If error: Does the SDK/library actually embed config in errors? | Usually no → Likely FP |
| 4 | Is `%+v` or `%#v` used? (These bypass String() methods) | If just `%v` or `%s` → Check String() method |
| 5 | Is the sensitive field directly in the format string args? | If not direct → trace data flow |

## Integration with Other Skills

- Use **dangerous-functions** skill for traditional injection sinks
- Use **data-flow-tracing** skill for complex flow analysis
- Use **vuln-patterns** skill for exploitation context
