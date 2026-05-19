# IDOR & Broken Access Control Patterns

## Overview

Insecure Direct Object References (IDOR) and Broken Access Control vulnerabilities occur when applications fail to properly verify that the requesting user has authorization to access or modify the requested resource.

**OWASP Mapping**: A01:2021 - Broken Access Control

---

## Vulnerability Pattern

```
IF user_controlled_id IN request
   AND resource = lookup(user_controlled_id)
   AND NO authorization_check(current_user, resource)
THEN IDOR_vulnerability
```

---

## Common Indicators

### 1. Direct Object References in URLs/Parameters

**Patterns to Search:**
```bash
# URL path parameters with IDs
grep -rniE "(\/users?\/|\/accounts?\/|\/orders?\/|\/files?\/|\/documents?\/)\{?\w*[Ii]d\}?" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"

# Query parameters with IDs
grep -rniE "(user_?id|account_?id|order_?id|file_?id|doc_?id|customer_?id|profile_?id)\s*=" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"
```

### 2. Database Lookups Without Ownership Check

**PHP:**
```php
// VULNERABLE - No ownership verification
$order = Order::find($_GET['order_id']);

// SECURE - Scoped to current user
$order = Order::where('user_id', auth()->id())
              ->findOrFail($_GET['order_id']);
```

**Python (Django):**
```python
# VULNERABLE
order = Order.objects.get(pk=request.GET['order_id'])

# SECURE
order = Order.objects.get(pk=request.GET['order_id'], user=request.user)
```

**Java (Spring):**
```java
// VULNERABLE
Order order = orderRepository.findById(orderId);

// SECURE
Order order = orderRepository.findByIdAndUserId(orderId, currentUser.getId());
```

**Node.js:**
```javascript
// VULNERABLE
const order = await Order.findById(req.params.orderId);

// SECURE
const order = await Order.findOne({
    _id: req.params.orderId,
    userId: req.user.id
});
```

**Go:**
```go
// VULNERABLE
var order Order
db.First(&order, orderID)

// SECURE
var order Order
db.Where("id = ? AND user_id = ?", orderID, currentUserID).First(&order)
```

---

## Grep Patterns by Language

### PHP
```bash
# Find direct lookups without ownership check
grep -rniE "(::find|::findOrFail|->find)\s*\(\s*\$_(GET|POST|REQUEST)" --include="*.php"

# Find where clauses that might be missing user scope
grep -rniE "->where\s*\(['\"]id['\"]\s*,\s*\$" --include="*.php"
```

### Python (Django/Flask)
```bash
# Django - objects.get without user filter
grep -rniE "\.objects\.get\s*\(\s*pk\s*=" --include="*.py"

# Flask-SQLAlchemy direct query
grep -rniE "\.query\.get\s*\(|\.query\.filter_by\s*\(\s*id\s*=" --include="*.py"
```

### Java (Spring)
```bash
# Repository findById without user context
grep -rniE "(findById|getOne|getReferenceById)\s*\(" --include="*.java"

# Path variable IDs
grep -rniE "@PathVariable.*[Ii]d" --include="*.java"
```

### Node.js
```bash
# Mongoose findById without ownership
grep -rniE "(findById|findOne)\s*\(\s*(req\.(params|query|body))" --include="*.js" --include="*.ts"
```

### Go
```bash
# GORM First/Find without ownership filter
grep -rniE "\.First\s*\(&\w+,\s*\w+ID\)|\.Find\s*\(&\w+,\s*\w+ID\)" --include="*.go"
```

### Ruby (Rails)
```bash
# ActiveRecord find without scope
grep -rniE "\.find\s*\(\s*params\[" --include="*.rb"

# Missing current_user scope
grep -rniE "\.where\s*\(\s*id:\s*params" --include="*.rb"
```

---

## Horizontal vs Vertical Privilege Escalation

### Horizontal IDOR (Same Role, Different User)
- User A accessing User B's data
- Same permission level, different ownership

**Example:**
```
GET /api/orders/12345  # User A's order
GET /api/orders/12346  # User B's order (accessible to User A = IDOR)
```

### Vertical Privilege Escalation (Different Role)
- Regular user accessing admin functionality
- Lower privilege accessing higher privilege resources

**Example:**
```
GET /api/users/123/profile     # Regular user's profile
GET /api/admin/users           # Admin-only endpoint (accessible = vertical escalation)
```

---

## Common Vulnerable Endpoints

| Endpoint Pattern | Risk | Description |
|-----------------|------|-------------|
| `/api/users/{id}` | High | User profile access |
| `/api/orders/{id}` | High | Order details/modification |
| `/api/files/{id}` | High | File download/access |
| `/api/documents/{id}` | High | Document access |
| `/api/invoices/{id}` | High | Financial data |
| `/api/messages/{id}` | Medium | Private communications |
| `/api/settings/{id}` | Medium | User settings |
| `/admin/*` | Critical | Admin functionality |

---

## Authorization Check Patterns

### Missing Checks (Vulnerable)
```python
# VULNERABLE - No authorization
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())
```

### Proper Checks (Secure)
```python
# SECURE - Ownership verification
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first_or_404()
    return jsonify(order.to_dict())
```

---

## Framework-Specific Defenses

### Django
```python
# Use get_object_or_404 with user filter
from django.shortcuts import get_object_or_404

def order_detail(request, order_id):
    order = get_object_or_404(Order, pk=order_id, user=request.user)
```

### Rails
```ruby
# Scope to current_user
def show
    @order = current_user.orders.find(params[:id])
end
```

### Spring
```java
// Use @PreAuthorize or custom authorization
@PreAuthorize("@orderService.isOwner(#orderId, authentication.principal)")
@GetMapping("/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) { ... }
```

### Express.js
```javascript
// Middleware for ownership check
const checkOwnership = async (req, res, next) => {
    const resource = await Resource.findById(req.params.id);
    if (!resource || resource.userId.toString() !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    req.resource = resource;
    next();
};
```

---

## Testing Checklist

1. [ ] Identify all endpoints with object IDs in URL/params
2. [ ] Test accessing resources with different user sessions
3. [ ] Test incrementing/decrementing numeric IDs
4. [ ] Test with UUIDs (may still be guessable from logs/emails)
5. [ ] Check if authorization is enforced on both read AND write operations
6. [ ] Test bulk operations (array of IDs)
7. [ ] Check for indirect references (e.g., /api/users/me/orders vs /api/orders/{id})
8. [ ] Test parameter pollution (duplicate params with different values)

---

## Remediation

### 1. Always Scope Queries to Current User
```python
# Instead of: Model.query.get(id)
# Use: Model.query.filter_by(id=id, user_id=current_user.id).first()
```

### 2. Use Indirect References
```python
# Map internal IDs to external tokens
external_id = generate_token(user_id, resource_id)
# Validate token includes current user's context
```

### 3. Implement Authorization Middleware
```javascript
app.use('/api/resources/:id', authorizeResource);
```

### 4. Use Framework Authorization
- Django: django-guardian, django-rules
- Rails: Pundit, CanCanCan
- Spring: Spring Security @PreAuthorize
- Express: CASL, accesscontrol

---

## Related CWEs

- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
