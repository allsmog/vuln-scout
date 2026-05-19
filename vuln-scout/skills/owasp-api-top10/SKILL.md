---
name: OWASP API Security Top 10
description: This skill should be used when the user asks about "API security", "OWASP API Top 10", "BOLA", "broken object level authorization", "API authentication", "mass assignment", "GraphQL security", "gRPC security", "rate limiting", "API abuse", "REST API vulnerabilities", or needs to identify API-specific security issues during whitebox pentesting.
version: 1.0.0
---

# OWASP API Security Top 10 (2023) Reference

## Purpose

Identify API-specific security vulnerabilities based on the OWASP API Security Top 10 (2023 edition), including REST, GraphQL, and gRPC patterns. APIs are the primary attack surface for modern applications, and these vulnerability classes represent the most critical and commonly exploited API security risks.

## When to Use

Activate this skill when:
- Auditing REST API endpoints and route handlers
- Reviewing GraphQL schemas, resolvers, and configurations
- Assessing gRPC service definitions and interceptors
- Evaluating API authentication and authorization logic
- Testing rate limiting and resource consumption controls
- Reviewing API gateway configurations

## API1:2023 - Broken Object Level Authorization (BOLA)

**Description**: API endpoints that accept object IDs and do not verify that the authenticated user has permission to access the referenced object.

**Pattern**: ID parameters used directly in database queries without ownership checks.

**Vulnerable Code Examples**:

Express.js:
```javascript
// VULNERABLE: No ownership check
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order); // Any authenticated user can access any order
});
```

Flask:
```python
# VULNERABLE: No ownership check
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())  # Missing: order.user_id == current_user.id
```

Spring:
```java
// VULNERABLE: No ownership check
@GetMapping("/api/orders/{id}")
public Order getOrder(@PathVariable Long id) {
    return orderRepository.findById(id)
        .orElseThrow(); // Any authenticated user can access any order
}
```

Go (net/http):
```go
// VULNERABLE: No ownership check
func getOrder(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    order, _ := db.GetOrder(id) // Missing: order.UserID == authenticatedUser.ID
    json.NewEncoder(w).Encode(order)
}
```

**Detection Patterns**:
```bash
# Express: Route params used directly in DB queries
grep -rniE "req\.params\.\w+" --include="*.js" --include="*.ts" -A 5 | grep -iE "(findById|findOne|findByPk|where)"

# Flask: Route parameters in DB queries without ownership check
grep -rniE "def\s+\w+\(.*_id\)" --include="*.py" -A 10 | grep -iE "(query\.get|filter_by|find_one)"

# Spring: PathVariable in repository calls
grep -rniE "@PathVariable" --include="*.java" -A 5 | grep -iE "(findById|getOne|findOne)"

# Go: URL parameters in DB calls
grep -rniE "(mux\.Vars|chi\.URLParam|r\.URL\.Query)" --include="*.go" -A 5 | grep -iE "(GetOrder|FindBy|QueryRow)"

# Generic: Look for endpoints with ID params lacking authorization
grep -rniE "(/:id|/<int:|/{id}|\{id\})" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.go"
```

**Fix Pattern**: Always verify that the authenticated user owns or has permission to access the requested resource:
```python
order = Order.query.get_or_404(order_id)
if order.user_id != current_user.id:
    abort(403)
```

## API2:2023 - Broken Authentication

**Description**: Weak or missing authentication mechanisms on API endpoints.

**Vulnerable Patterns**:

| Pattern | Risk | Detection |
|---------|------|-----------|
| API key in URL query string | HIGH | `grep -rniE "api[_-]?key=.*[?&]" --include="*.js" --include="*.py"` |
| No rate limiting on auth endpoints | HIGH | Check `/login`, `/auth`, `/token` for rate limit middleware |
| JWT with `none` algorithm | CRITICAL | `grep -rniE "algorithm.*none\|alg.*none" --include="*.py" --include="*.js"` |
| Missing token expiration | HIGH | `grep -rniE "expiresIn\|exp" --include="*.js" --include="*.py"` (check if absent) |
| Hardcoded JWT secret | CRITICAL | `grep -rniE "(jwt_secret\|JWT_SECRET\|secret_key)\s*=\s*[\"']" --include="*.py" --include="*.js"` |
| Password in API response | HIGH | Check serialization excludes password fields |
| No authentication on sensitive endpoints | CRITICAL | Routes without `auth`, `authenticate`, `login_required` middleware |

**Per-Framework Detection**:

```bash
# Express: Routes without auth middleware
grep -rniE "app\.(get|post|put|delete|patch)\s*\(" --include="*.js" --include="*.ts" | grep -viE "(auth|protect|verify|middleware|passport)"

# Flask: Routes without login_required
grep -rniE "@app\.route" --include="*.py" -A 2 | grep -viE "(login_required|jwt_required|auth)"

# Spring: Endpoints without @PreAuthorize or security config
grep -rniE "@(Get|Post|Put|Delete)Mapping" --include="*.java" -B 3 | grep -viE "(PreAuthorize|Secured|RolesAllowed)"

# Go: Handlers without auth middleware in chain
grep -rniE "HandleFunc|Handle\(" --include="*.go" | grep -viE "(auth|middleware|protect)"
```

## API3:2023 - Broken Object Property Level Authorization

**Description**: API exposes object properties that the user should not be able to read (excessive data exposure) or write (mass assignment).

**Excessive Data Exposure Patterns**:
```bash
# Returning entire ORM objects without field filtering
grep -rniE "\.to_dict\(\)|\.toJSON\(\)|jsonify\(\w+\)|res\.json\(\w+\)" --include="*.py" --include="*.js"

# Spring: Returning entity directly
grep -rniE "return\s+\w+Repository\.find" --include="*.java"

# Missing field selection in serialization
grep -rniE "JSON\.stringify\(user\)|json\.dumps\(\w+\.__dict__\)" --include="*.js" --include="*.py"
```

**Mass Assignment Patterns**:
```bash
# Express: Spreading request body into model
grep -rniE "\.create\(\s*req\.body\)|\.update\(\s*req\.body\)|Object\.assign\(\w+,\s*req\.body\)" --include="*.js" --include="*.ts"

# Flask: Direct assignment from request
grep -rniE "request\.(json|form|data)" --include="*.py" -A 3 | grep -iE "\*\*|update\(|setattr"

# Spring: No @JsonIgnore on sensitive fields
grep -rniE "class\s+\w+(Entity|Model|DTO)" --include="*.java" -A 20 | grep -iE "(password|role|admin|isAdmin|permissions)"

# Ruby on Rails: permit all params
grep -rniE "params\.permit!" --include="*.rb"
grep -rniE "attr_accessible" --include="*.rb"
```

## API4:2023 - Unrestricted Resource Consumption

**Description**: API does not restrict the size or number of resources that can be requested, leading to denial of service, excessive costs, or resource exhaustion.

**Vulnerable Patterns**:

| Pattern | Risk | Detection |
|---------|------|-----------|
| No pagination on list endpoints | HIGH | List endpoints returning all records |
| Missing `limit`/`offset` caps | HIGH | User-controlled page sizes without maximum |
| Unbounded file uploads | HIGH | No size limits on `multipart/form-data` |
| Regex DoS (ReDoS) | MEDIUM | Evil regex patterns on user input |
| No rate limiting | HIGH | Endpoints without `express-rate-limit`, `flask-limiter`, etc. |
| Unbounded query depth (GraphQL) | HIGH | No query depth limit configuration |

**Detection Patterns**:
```bash
# Unbounded queries (no limit/pagination)
grep -rniE "\.(find|findAll|select|query)\s*\(" --include="*.js" --include="*.ts" --include="*.py" | grep -viE "(limit|paginate|take|first|top)"

# Missing rate limiting middleware
grep -rniE "(express-rate-limit|flask.limiter|RateLimiter|throttle)" --include="*.js" --include="*.ts" --include="*.py" --include="*.java"

# Unbounded file upload size
grep -rniE "(multer|busboy|formidable|FileUpload)" --include="*.js" --include="*.ts" | grep -viE "(limit|maxFileSize|maxSize)"

# User-controlled page size without cap
grep -rniE "(pageSize|page_size|limit|per_page)\s*=\s*(req\.|request\.)" --include="*.js" --include="*.ts" --include="*.py"
```

## API5:2023 - Broken Function Level Authorization

**Description**: Administrative or privileged endpoints accessible to regular users due to missing role-based access control.

**Vulnerable Patterns**:
```bash
# Admin routes without role check
grep -rniE "(\/admin|\/manage|\/internal|\/debug|\/system)" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.go" | grep -viE "(role|admin|isAdmin|authorize|permission)"

# Different HTTP methods with inconsistent auth (e.g., GET is protected but DELETE is not)
grep -rniE "app\.(delete|put|patch)\s*\(" --include="*.js" --include="*.ts" -B 1 | grep -viE "(auth|admin|role)"

# Internal APIs exposed externally
grep -rniE "(internal|private|admin).*api" --include="*.yaml" --include="*.yml" --include="*.json" | grep -viE "(#|//|<!--)"
```

## API6:2023 - Unrestricted Access to Sensitive Business Flows

**Description**: APIs that expose sensitive business flows (purchasing, posting, reservations) without protections against automated abuse.

**Key Indicators**:
- No CAPTCHA or bot detection on high-value operations
- No velocity checks on purchase/transfer endpoints
- Missing device fingerprinting on account creation

## API7:2023 - Server Side Request Forgery (SSRF)

**Description**: API fetches remote resources based on user-supplied URLs without validation.

See the **vuln-patterns** skill for detailed SSRF patterns. API-specific concerns include:
- Webhook URL registration without URL validation
- URL preview/unfurl features
- PDF generation from user-supplied URLs

**Detection Patterns**:
```bash
# Webhook registration endpoints
grep -rniE "(webhook|callback|notify).*url" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.go"

# URL fetching based on user input
grep -rniE "(axios|fetch|requests\.get|http\.Get|HttpClient)\s*\(" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" | grep -iE "(req\.|request\.|params|body|query)"
```

## API8:2023 - Security Misconfiguration

**Description**: Missing security hardening, overly permissive CORS, unnecessary HTTP methods enabled, verbose error messages.

**Detection Patterns**:
```bash
# Overly permissive CORS
grep -rniE "Access-Control-Allow-Origin.*\*|cors\(\s*\)|origin:\s*true" --include="*.js" --include="*.ts" --include="*.py" --include="*.java"

# Verbose error responses
grep -rniE "(stack|stackTrace|traceback|debug.*true)" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" | grep -viE "(test|spec|__test__)"

# Missing security headers
grep -rniE "(helmet|security-headers|X-Content-Type-Options|X-Frame-Options)" --include="*.js" --include="*.ts" --include="*.py"
```

## API9:2023 - Improper Inventory Management

**Description**: Exposed old API versions, unpatched endpoints, unnecessary debug endpoints, lack of API documentation matching actual endpoints.

**Key Indicators**:
- Multiple API versions deployed (`/v1/`, `/v2/`, `/v3/`)
- Debug or test endpoints in production (`/debug/`, `/test/`, `/swagger/`)
- Undocumented endpoints not in OpenAPI spec

## API10:2023 - Unsafe Consumption of APIs

**Description**: Application trusts data from third-party APIs without validation, leading to injection or logic flaws.

**Detection Patterns**:
```bash
# Third-party API responses used without validation
grep -rniE "(axios|fetch|requests)\.(get|post)" --include="*.js" --include="*.ts" --include="*.py" -A 5 | grep -iE "(\.data\.|response\[|res\.json)"

# External data inserted into DB without sanitization
grep -rniE "(insert|create|update)\s*\(" --include="*.js" --include="*.ts" --include="*.py" -B 5 | grep -iE "(response|apiResult|externalData)"
```

## GraphQL-Specific Patterns

### Introspection Enabled in Production

**Risk**: Exposes entire schema including types, fields, mutations, and internal documentation to attackers.

```bash
# Check for introspection configuration
grep -rniE "introspection\s*:\s*(true|!)" --include="*.js" --include="*.ts" --include="*.py" --include="*.java"

# Check for introspection disabled
grep -rniE "introspection\s*:\s*false" --include="*.js" --include="*.ts" --include="*.py"

# Environment-conditional introspection (common pattern to verify)
grep -rniE "introspection.*NODE_ENV|introspection.*process\.env" --include="*.js" --include="*.ts"
```

### Nested Query Depth Attacks

**Risk**: Deeply nested queries can cause exponential backend processing, leading to denial of service.

```bash
# Check for depth limiting
grep -rniE "(depthLimit|queryDepth|maxDepth|depth-limit)" --include="*.js" --include="*.ts" --include="*.py" --include="*.java"

# Apollo Server: check for validation rules
grep -rniE "validationRules" --include="*.js" --include="*.ts" -A 5

# Graphene (Python): check for middleware
grep -rniE "(DepthAnalysisBackend|depth_limit)" --include="*.py"
```

### Batching Attacks

**Risk**: GraphQL allows sending multiple queries in a single request, bypassing rate limiting.

```bash
# Check for batching controls
grep -rniE "(allowBatchedHttpRequests|batching|maxBatchSize|batch)" --include="*.js" --include="*.ts" --include="*.py" | grep -iE "(graphql|apollo|schema)"

# Array of queries in request handling
grep -rniE "Array\.isArray\(req\.body\)|isinstance.*list" --include="*.js" --include="*.ts" --include="*.py"
```

### Mutation Authorization

**Risk**: Mutations that modify data without proper authorization checks in resolvers.

```bash
# Resolvers with mutations
grep -rniE "Mutation\s*[:=]|type\s+Mutation" --include="*.js" --include="*.ts" --include="*.py" --include="*.graphql" -A 20

# Check resolvers for auth checks
grep -rniE "(resolve|resolver)" --include="*.js" --include="*.ts" --include="*.py" -A 10 | grep -iE "(auth|permission|role|context\.user)"
```

## gRPC-Specific Patterns

### Reflection Enabled in Production

**Risk**: gRPC reflection allows clients to discover all services and methods, similar to GraphQL introspection.

```bash
# Go: gRPC reflection
grep -rniE "reflection\.Register" --include="*.go"

# Java: gRPC reflection
grep -rniE "ProtoReflectionService|ServerReflection" --include="*.java"

# Python: gRPC reflection
grep -rniE "reflection\.enable_server_reflection" --include="*.py"

# Check for conditional reflection (should be dev-only)
grep -rniE "reflection" --include="*.go" --include="*.java" --include="*.py" -B 3 | grep -iE "(debug|dev|environment|NODE_ENV)"
```

### Metadata Injection

**Risk**: gRPC metadata (similar to HTTP headers) can be injected if user-controlled data flows into metadata without sanitization.

```bash
# Go: Metadata from context
grep -rniE "metadata\.(New|Pairs|FromIncomingContext)" --include="*.go"

# Java: Metadata handling
grep -rniE "Metadata\.(Key|put)" --include="*.java"

# Python: Metadata in calls
grep -rniE "metadata\s*=\s*\[" --include="*.py"
```

### Missing Per-RPC Authentication

**Risk**: Individual RPC methods may lack authentication even when the service has a global interceptor, due to bypass or misconfiguration.

```bash
# Go: Check for per-RPC auth interceptors
grep -rniE "(UnaryInterceptor|StreamInterceptor)" --include="*.go" -A 10 | grep -iE "(auth|token|jwt)"

# Java: Check for security interceptors
grep -rniE "(ServerInterceptor|@GrpcGlobalServerInterceptor)" --include="*.java"

# Check for auth bypass lists
grep -rniE "(skip_auth|noAuth|public_methods|whitelist)" --include="*.go" --include="*.java" --include="*.py"
```

## Methodology

### Step 1: Map API Surface

```bash
# Find all route definitions
grep -rniE "(app\.(get|post|put|delete|patch)|@(Get|Post|Put|Delete|Patch)Mapping|@app\.route|HandleFunc)" --include="*.js" --include="*.ts" --include="*.py" --include="*.java" --include="*.go"

# Find OpenAPI/Swagger specs
find . \( -name "openapi*.yaml" -o -name "openapi*.json" -o -name "swagger*.yaml" -o -name "swagger*.json" \) 2>/dev/null

# Find GraphQL schemas
find . \( -name "*.graphql" -o -name "schema.js" -o -name "schema.ts" -o -name "schema.py" \) -not -path "*/node_modules/*" 2>/dev/null

# Find gRPC proto files
find . -name "*.proto" -not -path "*/node_modules/*" 2>/dev/null
```

### Step 2: Check Authentication and Authorization

For each endpoint:
1. Verify authentication middleware is applied
2. Check for authorization logic (BOLA, BFLA)
3. Verify role-based access where applicable
4. Test for mass assignment protections

### Step 3: Assess Resource Controls

1. Check rate limiting configuration
2. Verify pagination limits
3. Assess file upload size limits
4. Review GraphQL depth/complexity limits

### Step 4: Review Data Exposure

1. Check API response serialization for sensitive field leakage
2. Review error responses for information disclosure
3. Verify CORS configuration
4. Check for debug endpoints in production

### Step 5: Classify and Report

**Severity Mapping**:
- **CRITICAL**: BOLA on sensitive data, broken auth on admin endpoints, mass assignment enabling privilege escalation
- **HIGH**: Missing rate limiting on auth endpoints, unrestricted GraphQL introspection in production, gRPC reflection in production
- **MEDIUM**: Excessive data exposure, missing pagination caps, verbose error messages
- **LOW**: Minor CORS misconfigurations, missing security headers on non-sensitive endpoints

## Integration with Findings Artifact

Map results to `.claude/findings.json` with:
- `type`: `"bola"`, `"broken-auth"`, `"mass-assignment"`, `"excessive-data-exposure"`, `"missing-rate-limit"`, `"graphql-introspection"`, `"ssrf"`, or `"security-misconfiguration"`
- `kind`: `"finding"` for confirmed authorization bypasses, `"hotspot"` for patterns requiring manual review
- `source_tool`: `"manual"` or `"semgrep"`
- `evidence`: Include the endpoint, HTTP method, file, line, and description of the missing control

## Integration with Other Skills

- Use **vuln-patterns** for general injection and SSRF patterns
- Use **business-logic** for authorization logic flaws beyond BOLA
- Use **framework-patterns** for framework-specific API security behaviors
- Use **security-misconfiguration** for broader misconfiguration patterns
- Use **data-flow-tracing** to trace user input through API handlers to sinks
