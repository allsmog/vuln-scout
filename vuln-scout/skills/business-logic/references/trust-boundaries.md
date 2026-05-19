# Trust Boundary Analysis

## Overview

Trust boundaries define where different levels of trust exist in an application. Vulnerabilities occur when data crosses a trust boundary without proper validation, or when one component trusts another component's data inappropriately.

---

## Trust Boundary Locations

```
┌─────────────────────────────────────────────────────────────────────┐
│                         UNTRUSTED ZONE                              │
│  User's Browser / Mobile App / External Client                      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ Trust Boundary #1: Client → Server
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    PARTIALLY TRUSTED ZONE                           │
│  API Gateway / Load Balancer / CDN                                  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ Trust Boundary #2: Edge → Application
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       APPLICATION ZONE                               │
│  Web Application / Backend Services                                 │
│    ┌─────────────┐    Trust     ┌─────────────┐                    │
│    │  Service A  │──Boundary───▶│  Service B  │                    │
│    └─────────────┘     #3       └─────────────┘                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ Trust Boundary #4: App → Data Store
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        TRUSTED ZONE                                  │
│  Database / Cache / Internal Services                               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Common Trust Boundary Vulnerabilities

### 1. Client → Server (Frontend to Backend)

**Flaw**: Backend trusts client-side validation

```javascript
// FRONTEND - Client-side validation
function validateOrder(order) {
    if (order.price < 0) return false;
    if (order.quantity > 100) return false;
    return true;
}

// If backend doesn't re-validate, attacker bypasses frontend entirely
```

```python
# BACKEND - Missing server-side validation
def create_order(request):
    # VULNERABLE - Trusts client validation
    order = Order(
        price=request.data['price'],      # Attacker sets $0
        quantity=request.data['quantity'], # Attacker sets 99999
        user_id=request.data['user_id']   # Attacker sets admin's ID
    )
```

**Grep Patterns:**
```bash
# Find values taken directly from request without validation
grep -rniE "request\.(data|json|body|form|params)\[" --include="*.py" --include="*.js" --include="*.java" --include="*.php" -A 1 | grep -E "=.*request\."

# Find frontend-only validation
grep -rniE "(if.*\.length|validate|check).*return" --include="*.js" --include="*.ts"
```

---

### 2. Hidden Field Trust

**Flaw**: Backend trusts hidden form fields

```html
<!-- FRONTEND - Hidden fields -->
<form action="/api/order" method="POST">
    <input type="hidden" name="user_id" value="123">
    <input type="hidden" name="role" value="customer">
    <input type="hidden" name="price" value="99.99">
    <input type="text" name="address">
    <button type="submit">Order</button>
</form>
```

```python
# BACKEND - Trusts hidden fields
def process_order(request):
    # VULNERABLE - User can modify hidden fields
    user_id = request.form['user_id']  # Modify to another user
    role = request.form['role']        # Modify to "admin"
    price = request.form['price']      # Modify to 0.01
```

**Grep Patterns:**
```bash
# Find hidden inputs
grep -rniE "type=['\"]hidden['\"]" --include="*.html" --include="*.php" --include="*.erb" --include="*.ejs"

# Find sensitive hidden fields
grep -rniE "type=['\"]hidden['\"].*name=['\"].*(id|role|admin|price|user)" --include="*.html" --include="*.php"
```

---

### 3. Service → Service Trust

**Flaw**: Internal service trusts data from another service without validation

```python
# Service A - User service
def get_user(user_id):
    return {"id": user_id, "role": "user", "data": db.get_user(user_id)}

# Service B - Order service (VULNERABLE)
def process_order(request):
    user_data = user_service.get_user(request.user_id)
    # Trusts user_service data completely - but what if user_service is compromised?
    # Or if attacker can inject data into user_service response?
    if user_data['role'] == 'premium':
        apply_premium_discount()
```

**Grep Patterns:**
```bash
# Find inter-service calls
grep -rniE "(requests\.(get|post)|fetch|axios|http\.client)" --include="*.py" --include="*.js" --include="*.java"

# Find trust of external data
grep -rniE "response\.(json|data|body)\[" --include="*.py" --include="*.js"
```

---

### 4. Database Trust

**Flaw**: Application trusts database content to be safe

```python
# VULNERABLE - Trusting database content
def render_profile(user_id):
    user = User.query.get(user_id)
    # User bio came from user input, stored in DB
    # If not sanitized on output, stored XSS possible
    return f"<div class='bio'>{user.bio}</div>"

# SECURE
def render_profile(user_id):
    user = User.query.get(user_id)
    return f"<div class='bio'>{escape(user.bio)}</div>"
```

```python
# VULNERABLE - Trusting database-sourced URLs
def process_webhook(webhook_id):
    webhook = Webhook.query.get(webhook_id)
    # URL stored by potentially malicious user
    requests.get(webhook.url)  # SSRF via stored URL
```

**Grep Patterns:**
```bash
# Find unescaped output from database
grep -rniE "f['\"].*\{.*\.(name|bio|description|content|body)" --include="*.py"
grep -rniE "\$\{.*\.(name|bio|description|content)\}" --include="*.js"

# Find database values used in sensitive operations
grep -rniE "\.url\s*\)|\.path\s*\)|\.host\s*\)" --include="*.py" --include="*.js" --include="*.java"
```

---

### 5. JWT/Token Trust

**Flaw**: Trusting JWT claims without verification

```python
# VULNERABLE - Trusting JWT payload without verification
import base64
import json

def get_user_from_token(token):
    # Just decodes payload, doesn't verify signature!
    payload = base64.b64decode(token.split('.')[1])
    return json.loads(payload)

# SECURE
import jwt
def get_user_from_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
```

**Grep Patterns:**
```bash
# Find JWT handling
grep -rniE "(jwt\.decode|jose\.|jsonwebtoken)" --include="*.py" --include="*.js" --include="*.java"

# Find base64 decoding of tokens (suspicious)
grep -rniE "(base64\.decode|atob|Buffer\.from).*token" --include="*.py" --include="*.js"

# Find missing algorithm specification (vulnerable)
grep -rniE "jwt\.decode.*\)" --include="*.py" | grep -v "algorithms"
```

---

### 6. Environment/Config Trust

**Flaw**: Trusting environment variables or config files as safe

```python
# VULNERABLE - Trusting user-controllable environment
def get_admin_email():
    return os.environ.get('ADMIN_EMAIL', 'admin@example.com')

# If attacker can set environment variables (e.g., via .env injection),
# they control application behavior
```

```python
# VULNERABLE - Trusting config files
def load_plugins():
    config = yaml.safe_load(open('config.yml'))  # YAML can execute code!
    for plugin in config['plugins']:
        load_plugin(plugin['path'])  # Path traversal if attacker controls config
```

**Grep Patterns:**
```bash
# Find environment variable usage
grep -rniE "(os\.environ|process\.env|getenv|System\.getenv)" --include="*.py" --include="*.js" --include="*.java"

# Find config file loading
grep -rniE "(yaml\.load|json\.load|configparser|\.ini|\.yml)" --include="*.py" --include="*.js"
```

---

## Trust Boundary Analysis Process

### Step 1: Identify All Data Entry Points

1. **External Sources**
   - HTTP requests (body, query, headers, cookies)
   - File uploads
   - WebSocket messages
   - Email (IMAP/POP3)
   - External APIs

2. **Internal Sources**
   - Database queries
   - Cache (Redis, Memcached)
   - Inter-service communication
   - Message queues

### Step 2: Map Data Flow

For each entry point:
```
Source → Processing → Storage → Output
  |           |           |         |
  v           v           v         v
Where?    Validated?   Encoded?   Escaped?
```

### Step 3: Identify Trust Assumptions

Document assumptions like:
- "Frontend validates input"
- "Database content is safe"
- "Internal service is trusted"
- "JWT is valid if present"

### Step 4: Challenge Each Assumption

For each assumption:
- What if this is false?
- How would an attacker exploit this?
- What validation is missing?

---

## Detection Checklist

### Client → Server
- [ ] All input re-validated server-side?
- [ ] No hidden fields for sensitive data?
- [ ] CSRF protection on state-changing requests?
- [ ] Rate limiting on endpoints?

### Service → Service
- [ ] Authentication between services?
- [ ] Response data validated/sanitized?
- [ ] Network segmentation in place?
- [ ] Error messages don't leak internal details?

### Database Trust
- [ ] Output encoded/escaped?
- [ ] User-stored URLs not used for SSRF?
- [ ] SQL queries parameterized?
- [ ] ORM not bypassed with raw queries?

### Token Trust
- [ ] JWT signatures verified?
- [ ] Token expiration checked?
- [ ] Algorithm specified (not "none")?
- [ ] Claims validated against database?

---

## Code Review Focus Areas

### High Priority
```python
# Any direct use of request data
request.data[...]
request.json[...]
request.form[...]
request.args[...]

# Any trust of external data
response.json()
external_api.get(...)

# Any output without encoding
f"<div>{user_input}</div>"
render_template_string(user_input)
```

### Medium Priority
```python
# Database queries with user data
User.query.filter_by(id=user_provided_id)

# Config file loading
yaml.load(...)
json.load(...)

# Environment variables for sensitive values
os.environ.get('SECRET_KEY')
```

### Lower Priority
```python
# Internal service calls (still validate!)
internal_service.get_user(user_id)

# Cached data usage
redis.get(key)
```
