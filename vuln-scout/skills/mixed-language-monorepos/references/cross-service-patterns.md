# Cross-Service Security Patterns

## Common Polyglot Stacks

### Stack 1: Go API + Python ML + React Frontend

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   React     │────▶│   Go API    │────▶│  Python ML  │
│  Frontend   │REST │   Gateway   │gRPC │   Service   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  PostgreSQL │
                    └─────────────┘
```

**Security Hotspots:**
1. Go Gateway: JWT validation, rate limiting
2. Go → Python: Auth token propagation
3. Python: ML model input validation, SQL injection
4. React: XSS, CSRF tokens

### Stack 2: Java Microservices + Node.js BFF

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Mobile    │────▶│  Node.js    │────▶│    Java     │
│    App      │REST │    BFF      │REST │  Services   │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │    Kafka    │
                                        └─────────────┘
```

**Security Hotspots:**
1. Node.js BFF: Input aggregation, response transformation
2. BFF → Java: Service-to-service auth
3. Java: Deserialization, Kafka message validation
4. Kafka: Message integrity, consumer authorization

### Stack 3: Rust Core + Go Services + TypeScript Admin

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ TypeScript  │────▶│     Go      │────▶│    Rust     │
│   Admin     │REST │   Service   │gRPC │    Core     │
└─────────────┘     └─────────────┘     └─────────────┘
```

**Security Hotspots:**
1. TypeScript Admin: Privilege escalation, RBAC
2. Go: Input validation, auth propagation
3. Rust: Memory safety (less concern), FFI boundaries

## Cross-Service Attack Patterns

### Pattern 1: Gateway Bypass

**Attack**: Directly call internal service, bypassing gateway auth

```
Normal:  Client → Gateway (auth) → Service
Attack:  Client → Service (no auth)
```

**Detection Queries:**

```bash
# Check if internal services are exposed
grep -rniE "0\.0\.0\.0:|INADDR_ANY|::" --include="*.go" --include="*.py" --include="*.java"

# Check for network policy/firewall rules
find . -name "*.yaml" -exec grep -l "NetworkPolicy\|firewall" {} \;

# Check Kubernetes services for external exposure
grep -rniE "type:\s*LoadBalancer|type:\s*NodePort" --include="*.yaml"
```

**Verification:**
```bash
# From within cluster, try direct service call
curl http://internal-service:8080/api/admin  # Should fail without auth
```

### Pattern 2: Auth Token Confusion

**Attack**: Exploit differences in how services interpret auth tokens

```go
// Go service: Expects JWT in Authorization header
token := r.Header.Get("Authorization")
claims := parseJWT(token)
```

```python
# Python service: Also accepts X-User-ID header (legacy)
user_id = request.headers.get('X-User-ID') or get_user_from_jwt()
```

**Attack**: Send request with both headers, exploit priority confusion

**Detection:**
```bash
# Find all auth header access
grep -rniE "Authorization|X-User|X-Auth|Bearer" --include="*.go" --include="*.py" --include="*.java" --include="*.ts"

# Check for multiple auth methods
grep -rniE "get.*header.*user|getHeader.*auth" -A5 --include="*.go" --include="*.py" --include="*.java"
```

### Pattern 3: Serialization Boundary Attack

**Attack**: Exploit language differences in JSON/protobuf handling

```json
// Sent by TypeScript client
{"userId": "123", "userId": "admin"}  // Duplicate key
```

```go
// Go: Uses first value → userId = "123"
```

```python
# Python: Uses last value → userId = "admin"
```

**Detection:**
```bash
# Find JSON parsing
grep -rniE "json\.Unmarshal|json\.loads|JSON\.parse|objectMapper\.read" --include="*.go" --include="*.py" --include="*.ts" --include="*.java"

# Check for strict parsing options
grep -rniE "DisallowUnknownFields|strict=|strictMode" --include="*.go" --include="*.py" --include="*.ts"
```

### Pattern 4: Type Coercion Attack

**Attack**: Exploit language type systems at boundaries

```typescript
// TypeScript client sends
{ "quantity": "100" }  // String
```

```go
// Go service: Strict typing, fails or coerces
type Order struct {
    Quantity int `json:"quantity"`  // Expects int
}
```

```python
# Python service: Duck typing, accepts anything
quantity = data.get('quantity')  # Could be string or int
result = quantity * price  # "100" * 10 = "100100100..." (string repeat!)
```

**Detection:**
```bash
# Find numeric operations on potentially untyped data
grep -rniE "\.get\(.*\)\s*\*|data\[.*\]\s*\*" --include="*.py"

# Find type assertions/conversions
grep -rniE "int\(|float\(|str\(" --include="*.py"
grep -rniE "\.\(int\)|\.\(string\)" --include="*.go"
```

### Pattern 5: Error Message Information Leak

**Attack**: Error messages from one service leak through another

```python
# Python ML service: Detailed error
raise ValueError(f"Model not found: {model_path}")  # Leaks path
```

```go
// Go gateway: Passes through
if err != nil {
    http.Error(w, err.Error(), 500)  // Leaks Python error to client
}
```

**Detection:**
```bash
# Find error pass-through
grep -rniE "err\.Error\(\)|str\(e\)|e\.message|error\.message" --include="*.go" --include="*.py" --include="*.ts" --include="*.java"

# Check for error sanitization
grep -rniE "sanitize.*error|clean.*error|wrap.*error" --include="*.go" --include="*.py"
```

### Pattern 6: Race Condition Across Services

**Attack**: Exploit async processing between services

```
1. User requests: DELETE /account
2. Gateway sends to: Auth Service (delete user)
3. Gateway sends to: Billing Service (cancel subscription)
4. Race: Billing still processes payment before deletion completes
```

**Detection:**
```bash
# Find parallel/async calls to multiple services
grep -rniE "Promise\.all|asyncio\.gather|go\s+func|goroutine|CompletableFuture" --include="*.ts" --include="*.py" --include="*.go" --include="*.java"

# Find saga/transaction patterns
grep -rniE "saga|compensate|rollback|distributed.transaction" --include="*.go" --include="*.py" --include="*.java"
```

## Protocol-Specific Vulnerabilities

### gRPC Security Issues

| Issue | Description | Detection |
|-------|-------------|-----------|
| **No TLS** | gRPC over plaintext | `grep -rn "grpc.Dial.*Insecure\|insecure=True"` |
| **Missing Auth** | No interceptor for auth | `grep -rn "grpc.NewServer()" ` without auth interceptor |
| **Large Message** | DoS via huge proto | Check for `MaxRecvMsgSize` settings |
| **Reflection** | Server reflection exposed | `grep -rn "reflection.Register"` |

### REST/HTTP Security Issues

| Issue | Description | Detection |
|-------|-------------|-----------|
| **CORS Misconfiguration** | Overly permissive CORS | `grep -rn "Access-Control-Allow-Origin.*\*"` |
| **Missing HTTPS** | Internal HTTP calls | `grep -rn "http://.*internal\|http://localhost"` |
| **Header Injection** | Unsanitized header values | `grep -rn "w.Header().Set.*\+\|response.headers\[.*\+"`|

### Message Queue Security Issues

| Issue | Description | Detection |
|-------|-------------|-----------|
| **No Auth** | Unauthenticated broker access | Check broker connection strings |
| **No Encryption** | Messages in plaintext | `grep -rn "PLAINTEXT\|security.protocol=none"` |
| **No Schema Validation** | Accept any message format | Missing schema registry config |
| **Poison Message** | No dead letter queue | Check for DLQ configuration |

## Service Mesh Security

If using Istio/Linkerd/Envoy:

### Istio Security Checks

```bash
# Check mTLS mode
kubectl get peerauthentication -A -o yaml | grep mode

# Check authorization policies
kubectl get authorizationpolicy -A -o yaml

# Check for permissive policies
grep -rniE "mode:\s*PERMISSIVE|action:\s*ALLOW" --include="*.yaml"
```

### Common Misconfigurations

| Issue | Impact | Detection |
|-------|--------|-----------|
| **PERMISSIVE mTLS** | Allows plaintext | `mode: PERMISSIVE` in PeerAuthentication |
| **Wildcard AuthPolicy** | Overly broad access | `principals: ["*"]` in AuthorizationPolicy |
| **Missing Egress Control** | Data exfiltration | No ServiceEntry restrictions |
| **Debug Endpoints** | Info disclosure | Envoy admin on 15000 exposed |

## Testing Cross-Service Security

### 1. Service Identity Spoofing Test

```bash
# From attacker pod, try to impersonate internal service
curl -H "X-Service-Name: auth-service" http://target-service/internal/endpoint
```

### 2. Auth Bypass Test

```bash
# Direct call to internal service (bypassing gateway)
kubectl port-forward svc/internal-service 8080:8080
curl http://localhost:8080/api/admin  # Should require auth
```

### 3. Schema Injection Test

```bash
# Send malformed proto/JSON
grpcurl -plaintext -d '{"user": {"id": "1", "id": "admin"}}' localhost:50051 UserService/GetUser
```

### 4. Cross-Origin Test

```bash
# Test CORS from different origin
curl -H "Origin: https://evil.com" -I http://api.target.com/endpoint
```

## Secure Patterns

### 1. Zero Trust Between Services

```go
// Every service validates JWT, even internal ones
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    token := extractToken(ctx)
    if err := validateJWT(token); err != nil {
        return nil, status.Error(codes.Unauthenticated, "invalid token")
    }
    return handler(ctx, req)
}
```

### 2. Strict Schema Validation

```python
# Validate all incoming messages against schema
from pydantic import BaseModel, validator

class UserRequest(BaseModel):
    user_id: str

    @validator('user_id')
    def validate_user_id(cls, v):
        if not v.isalnum():
            raise ValueError('Invalid user_id format')
        return v
```

### 3. Error Sanitization at Boundaries

```go
// Gateway sanitizes errors before returning to client
func handleError(err error) *ErrorResponse {
    // Log full error internally
    log.Error("internal error", "error", err)

    // Return sanitized error to client
    return &ErrorResponse{
        Code:    "INTERNAL_ERROR",
        Message: "An error occurred processing your request",
        // Never include: err.Error(), stack traces, paths
    }
}
```

### 4. Distributed Tracing for Security

```yaml
# Include security context in traces
tracing:
  sampling: 100%  # For security-critical paths
  tags:
    - user.id
    - auth.method
    - service.caller
```
