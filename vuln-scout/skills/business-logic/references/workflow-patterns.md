# Workflow Vulnerability Patterns

## Overview

Multi-step workflows are common attack surfaces for business logic vulnerabilities. Each step in a workflow represents an assumption about user behavior that can be violated.

---

## Common Vulnerable Workflows

| Workflow | Steps | Common Flaws |
|----------|-------|--------------|
| Checkout | Cart → Address → Payment → Confirm | Price manipulation, step skipping |
| Registration | Email → Verify → Profile → Complete | Verification bypass, duplicate accounts |
| Password Reset | Request → Email → Token → New Password | Token reuse, token prediction |
| Upgrade/Downgrade | Select Plan → Payment → Activate | Plan manipulation, downgrade bypass |
| Refund | Request → Review → Approve → Process | Direct status manipulation |

---

## 1. Checkout Flow Vulnerabilities

### Price Manipulation

```python
# VULNERABLE - Price from client
def add_to_cart(request):
    product_id = request.data['product_id']
    price = request.data['price']  # Attacker sets price to $0.01
    Cart.add_item(product_id, price)

# SECURE - Price from database
def add_to_cart(request):
    product_id = request.data['product_id']
    product = Product.query.get(product_id)
    Cart.add_item(product_id, product.price)  # Price from server
```

**Grep Patterns:**
```bash
# Find price handling in requests
grep -rniE "request\.(data|json|form)\[.*(price|amount|total|cost)\]" --include="*.py"
grep -rniE "req\.body\.(price|amount|total|cost)" --include="*.js"
```

### Quantity Bounds

```python
# VULNERABLE - No bounds checking
def update_quantity(request):
    quantity = int(request.data['quantity'])  # Can be negative or huge
    cart_item.quantity = quantity

# SECURE
def update_quantity(request):
    quantity = int(request.data['quantity'])
    if quantity < 1 or quantity > MAX_QUANTITY:
        raise ValidationError("Invalid quantity")
    cart_item.quantity = quantity
```

### Coupon Stacking

```python
# VULNERABLE - Multiple coupons applied
def apply_coupon(request):
    coupon_code = request.data['code']
    coupon = Coupon.query.filter_by(code=coupon_code).first()
    order.discounts.append(coupon.discount)  # No limit on number of coupons

# SECURE
def apply_coupon(request):
    if len(order.discounts) >= 1:
        raise ValidationError("Only one coupon allowed")
    # ... apply coupon
```

---

## 2. Registration Flow Vulnerabilities

### Email Verification Bypass

```python
# VULNERABLE - Verification can be skipped
def complete_registration(request, user_id):
    user = User.query.get(user_id)
    user.status = 'active'  # No check if email was verified!

# SECURE
def complete_registration(request, user_id):
    user = User.query.get(user_id)
    if not user.email_verified:
        raise PermissionError("Email not verified")
    user.status = 'active'
```

**Grep Patterns:**
```bash
# Find verification status checks
grep -rniE "(email_verified|is_verified|verified)\s*=\s*True" --include="*.py"
grep -rniE "if.*(email_verified|is_verified)" --include="*.py" --include="*.js"

# Find account activation without verification
grep -rniE "(status|state)\s*=\s*['\"]active['\"]" --include="*.py" --include="*.js"
```

### Duplicate Account Creation

```python
# VULNERABLE - Race condition allows duplicates
def register(request):
    email = request.data['email']
    if not User.query.filter_by(email=email).first():  # Check
        # Window for race condition
        user = User(email=email)  # Use
        db.session.add(user)
        db.session.commit()

# SECURE - Database constraint
class User(Model):
    email = Column(String(255), unique=True)  # Database enforces uniqueness
```

### Privileged Username Registration

**Vulnerability**: Application allows registration with privileged usernames (admin, root, system, etc.) that grant elevated permissions or have special meaning.

**Real-World Example**: Dark Runes CTF - Registering as "admin" granted administrative access with no restrictions. The scanner suggested complex cookie forgery when simply registering as "admin" worked.

> **CRITICAL: Always verify this assumption!** Do NOT assume registration blocks privileged usernames. Run the grep patterns below and explicitly check for reserved username validation. If no validation exists, this is often the easiest path to admin access.

```python
# VULNERABLE - No reserved username check
def register(request):
    username = request.data['username']
    password = request.data['password']
    user = User(username=username)  # Can create "admin"!
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

# SECURE - Reserved username validation
RESERVED_USERNAMES = {
    'admin', 'administrator', 'root', 'system', 'superuser',
    'sysadmin', 'moderator', 'mod', 'support', 'help',
    'info', 'contact', 'webmaster', 'postmaster', 'hostmaster',
    'null', 'undefined', 'api', 'www', 'mail', 'ftp'
}

def register(request):
    username = request.data['username'].lower().strip()
    if username in RESERVED_USERNAMES:
        raise ValidationError("This username is reserved")
    # ... continue registration
```

**Grep Patterns:**
```bash
# Find registration functions
grep -rniE "(def|function|func)\s+(register|signup|create_user|new_user)" --include="*.py" --include="*.php" --include="*.js" --include="*.go" --include="*.java" --include="*.rb"

# Find username assignment without validation
grep -rniE "username\s*=\s*(request|req|params|data)\." --include="*.py" --include="*.php" --include="*.js" --include="*.go"

# Find reserved/blocked username checks (if present - absence is the vulnerability)
grep -rniE "(reserved|blocked|forbidden|banned).*username|username.*(reserved|blocked|forbidden|banned)" --include="*.py" --include="*.php" --include="*.js" --include="*.go"
```

### Role/Permission Injection

**Vulnerability**: Registration endpoint accepts role or permission parameters that should be server-controlled.

```python
# VULNERABLE - Role from client
def register(request):
    username = request.data['username']
    role = request.data.get('role', 'user')  # Attacker sends role=admin
    user = User(username=username, role=role)

# VULNERABLE - Mass assignment
def register(request):
    user = User(**request.data)  # All fields from client!
    db.session.add(user)

# SECURE - Server-controlled role
def register(request):
    username = request.data['username']
    user = User(
        username=username,
        role='user'  # Always default, never from client
    )
```

**Grep Patterns:**
```bash
# Find role in registration
grep -rniE "register.*role|signup.*role|role.*request\.(data|json|form|body)" --include="*.py" --include="*.php" --include="*.js" --include="*.go"

# Find mass assignment in user creation
grep -rniE "User\s*\(\s*\*\*|User\.create\s*\(\s*params|new\s+User\s*\(\s*req\.(body|data)" --include="*.py" --include="*.php" --include="*.js" --include="*.go"

# Find admin/permission fields from request
grep -rniE "(is_admin|is_staff|is_superuser|permissions|admin)\s*=\s*(request|req|params)" --include="*.py" --include="*.php" --include="*.js" --include="*.go"
```

### Username Validation Bypass

**Vulnerability**: Inconsistent username normalization allows creating accounts that appear identical or bypass restrictions.

```python
# VULNERABLE - Case-sensitive uniqueness
def register(request):
    username = request.data['username']
    if User.query.filter_by(username=username).first():  # Only matches exact case
        raise ValidationError("Username taken")
    # "Admin" passes if "admin" exists

# VULNERABLE - No homoglyph protection
def register(request):
    username = request.data['username']
    # "аdmin" (Cyrillic 'а') passes if "admin" exists

# SECURE - Normalized comparison
import unicodedata

def normalize_username(username):
    normalized = unicodedata.normalize('NFKC', username)
    normalized = normalized.lower().strip()
    normalized = ''.join(c for c in normalized if c.isalnum() or c == '_')
    return normalized

def register(request):
    username = request.data['username']
    normalized = normalize_username(username)

    if User.query.filter(
        func.lower(User.username) == normalized
    ).first():
        raise ValidationError("Username taken")
```

**Common Homoglyph Attacks:**
| Normal | Attack | Unicode |
|--------|--------|---------|
| admin | аdmin | Cyrillic 'а' (U+0430) |
| admin | admіn | Cyrillic 'і' (U+0456) |
| root | rооt | Cyrillic 'о' (U+043E) |

**Grep Patterns:**
```bash
# Find username uniqueness checks (may be case-sensitive)
grep -rniE "filter.*username.*=|where.*username.*=|findOne.*username" --include="*.py" --include="*.php" --include="*.js" --include="*.go"

# Find normalization functions (secure pattern)
grep -rniE "unicodedata|normalize|NFKC|lower\(\)|casefold" --include="*.py" --include="*.php" --include="*.js" --include="*.go"

# Find case-insensitive database queries
grep -rniE "ILIKE|LOWER\(|COLLATE.*NOCASE|iexact" --include="*.py" --include="*.php" --include="*.js" --include="*.sql"
```

### Missing Rate Limiting on Registration

**Vulnerability**: No rate limiting allows automated account creation, credential stuffing preparation, or resource exhaustion.

```python
# VULNERABLE - No rate limit
@app.route('/register', methods=['POST'])
def register():
    # Can be called unlimited times

# SECURE - Rate limited
from flask_limiter import Limiter
limiter = Limiter(app)

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    # Rate limited
```

**Grep Patterns:**
```bash
# Find registration endpoints
grep -rniE "@(app\.|router\.)(route|post).*register|@(app\.|router\.)(route|post).*signup" --include="*.py" --include="*.js" --include="*.ts"

# Find rate limiting decorators/middleware
grep -rniE "(rate_limit|limiter|throttle|RateLimiter)" --include="*.py" --include="*.php" --include="*.js" --include="*.go"

# Find captcha/anti-bot on registration
grep -rniE "(recaptcha|captcha|hcaptcha|turnstile)" --include="*.py" --include="*.php" --include="*.js" --include="*.go"
```

### Registration Security Checklist

**MANDATORY VERIFICATION** - Do not assume these are implemented. Run grep patterns to confirm:

1. [ ] **VERIFY FIRST**: Can you register with privileged usernames (admin, root, system)? Run: `grep -rniE "(reserved|blocked|forbidden)" src/` - if empty, vulnerability exists!
2. [ ] Can you inject role/permission parameters in registration?
3. [ ] Is username comparison case-insensitive?
4. [ ] Are homoglyph/confusable characters blocked?
5. [ ] Is there rate limiting on registration?
6. [ ] Is there CAPTCHA or anti-bot protection?
7. [ ] Are disposable email domains blocked?
8. [ ] Is there a reserved username list?

> **Lesson learned**: In Dark Runes CTF, the scanner assumed "admin" registration was blocked. It wasn't. Always verify with grep patterns before assuming protections exist.

---

## 3. Password Reset Flow Vulnerabilities

### Token Reuse

```python
# VULNERABLE - Token can be used multiple times
def reset_password(request):
    token = request.data['token']
    new_password = request.data['password']

    reset_request = ResetToken.query.filter_by(token=token).first()
    if reset_request:
        user = reset_request.user
        user.set_password(new_password)
        db.session.commit()
        # Token not invalidated!

# SECURE
def reset_password(request):
    token = request.data['token']
    new_password = request.data['password']

    reset_request = ResetToken.query.filter_by(token=token, used=False).first()
    if reset_request:
        user = reset_request.user
        user.set_password(new_password)
        reset_request.used = True  # Invalidate token
        db.session.commit()
```

**Grep Patterns:**
```bash
# Find token handling
grep -rniE "(reset_token|password_token|verification_token)" --include="*.py" --include="*.js" --include="*.php"

# Find token invalidation (or lack thereof)
grep -rniE "\.used\s*=|\.invalidate|delete.*token" --include="*.py" --include="*.js"
```

### Token Prediction

```python
# VULNERABLE - Sequential/predictable tokens
def create_reset_token(user):
    token = str(user.id) + str(int(time.time()))  # Predictable!
    return ResetToken(user_id=user.id, token=token)

# SECURE
import secrets
def create_reset_token(user):
    token = secrets.token_urlsafe(32)  # Cryptographically random
    return ResetToken(user_id=user.id, token=token)
```

**Grep Patterns:**
```bash
# Find token generation
grep -rniE "token\s*=\s*(str\(|f\"|uuid\.uuid1)" --include="*.py"
grep -rniE "token.*=.*(Math\.random|Date\.now)" --include="*.js"

# Find secure token generation
grep -rniE "(secrets\.token|crypto\.random|uuid\.uuid4|randomBytes)" --include="*.py" --include="*.js"
```

---

## 4. Subscription/Plan Vulnerabilities

### Plan ID Manipulation

```python
# VULNERABLE - Plan ID from client
def upgrade_plan(request):
    plan_id = request.data['plan_id']
    user.plan_id = plan_id  # User can set enterprise plan without paying!

# SECURE - Verify payment first
def upgrade_plan(request):
    plan_id = request.data['plan_id']
    plan = Plan.query.get(plan_id)

    # Verify payment processed for this plan
    if not Payment.query.filter_by(
        user_id=user.id,
        plan_id=plan_id,
        status='completed'
    ).first():
        raise PermissionError("Payment required")

    user.plan_id = plan_id
```

### Trial Extension

```python
# VULNERABLE - Trial start from client
def start_trial(request):
    trial_start = request.data.get('trial_start', datetime.now())
    user.trial_ends = trial_start + timedelta(days=30)
    # Attacker sets trial_start far in future

# SECURE
def start_trial(request):
    if user.trial_ends:  # Already had a trial
        raise ValidationError("Trial already used")
    user.trial_ends = datetime.now() + timedelta(days=30)
```

---

## 5. Refund Flow Vulnerabilities

### Status Manipulation

```python
# VULNERABLE - Direct status update
def update_refund(request, refund_id):
    refund = Refund.query.get(refund_id)
    refund.status = request.data['status']  # User sets status to "approved"!

# SECURE - Server controls state transitions
def approve_refund(request, refund_id, admin_user):
    if not admin_user.has_permission('approve_refunds'):
        raise PermissionError()
    refund = Refund.query.get(refund_id)
    if refund.status == 'pending':
        refund.status = 'approved'
```

### Multiple Refund Claims

```python
# VULNERABLE - No check for existing refund
def request_refund(request, order_id):
    order = Order.query.get(order_id)
    refund = Refund(order_id=order_id, amount=order.total)
    db.session.add(refund)
    db.session.commit()
    # User can request refund multiple times!

# SECURE
def request_refund(request, order_id):
    order = Order.query.get(order_id)
    existing = Refund.query.filter_by(order_id=order_id).first()
    if existing:
        raise ValidationError("Refund already requested")
    refund = Refund(order_id=order_id, amount=order.total)
    db.session.add(refund)
    db.session.commit()
```

---

## Detection Checklist

For each workflow:

1. [ ] Can steps be skipped?
2. [ ] Can steps be repeated?
3. [ ] Are client-provided values trusted (price, quantity, status)?
4. [ ] Are tokens single-use and cryptographically random?
5. [ ] Is the final state verified against all prerequisites?
6. [ ] Are there race conditions between check and use?
7. [ ] Can the workflow be reversed unexpectedly?

---

## Testing Approach

### 1. Map the Workflow
```
Step 1 (Cart) → Step 2 (Address) → Step 3 (Payment) → Step 4 (Confirm)
     |              |                   |                  |
     v              v                   v                  v
What params?   What params?        What params?       What checks?
```

### 2. Test Step Skipping
- Remove intermediate requests
- Directly call final endpoint
- Modify step counter parameters

### 3. Test Parameter Tampering
- Modify prices, quantities, IDs
- Send negative values
- Use another user's IDs

### 4. Test Race Conditions
- Send same request concurrently
- Target single-use tokens/actions
- Look for check-then-use patterns
