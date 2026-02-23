---
name: Business Logic Analysis
description: This skill should be used when the user asks about "business logic", "workflow vulnerability", "trust boundary", "state machine", "authorization bypass", "multi-step process", "workflow bypass", "application logic flaw", or needs to identify business logic vulnerabilities during whitebox pentesting.
version: 1.0.0
---

# Business Logic Analysis

## Purpose

Provide comprehensive knowledge of business logic vulnerabilities - flaws that arise from incorrect assumptions about how users will interact with an application, rather than from traditional injection or parsing errors.

**Key Insight**: Unlike technical vulnerabilities (SQLi, XSS), business logic flaws require deep understanding of what the application is supposed to do. You cannot find them without first understanding the application.

---

## When to Use

Activate this skill when:
- Beginning a whitebox pentest (understand before hunt)
- Analyzing multi-step workflows (checkout, registration, auth)
- Reviewing authorization and access control
- Looking for ways to abuse intended functionality
- Identifying trust boundaries between components

---

## Core Concepts

### 1. Deep Application Understanding

Before hunting for business logic bugs:
1. Understand the application's purpose
2. Map all user roles and permissions
3. Identify critical workflows (money, data, access)
4. Document trust assumptions between components
5. Model state machines for multi-step processes

### 2. Trust Boundaries

Trust boundaries exist where:
- Frontend communicates with backend
- Service A calls Service B
- Application trusts database content
- External APIs are consumed
- User-controlled data crosses privilege levels

**Common flaw**: Backend trusts frontend validation, allowing bypass.

### 3. State Machine Vulnerabilities

Multi-step processes have states. Vulnerabilities arise from:
- Skipping states (jump from step 1 to step 4)
- Invalid transitions (completed → pending)
- Replaying states (submit same step twice)
- Concurrent state manipulation (race)

---

## Vulnerability Categories

### Authorization Logic Flaws

| Flaw | Pattern | Impact |
|------|---------|--------|
| IDOR | Direct object reference without ownership check | Access other users' data |
| Horizontal Privilege Escalation | Role check missing on specific action | Act as peer user |
| Vertical Privilege Escalation | Admin function callable by regular user | Gain admin access |
| Function-Level Access Control | Endpoint has no auth check | Bypass authentication |

### Workflow Bypass

| Flaw | Pattern | Impact |
|------|---------|--------|
| Step Skipping | No enforcement of workflow sequence | Bypass verification steps |
| State Manipulation | Direct modification of state parameters | Change order/payment status |
| Race Conditions | Non-atomic check-then-use | Double-spend, over-redeem |
| Replay Attacks | Action can be repeated without limit | Free resources, repeated discounts |

### Input Trust Issues

| Flaw | Pattern | Impact |
|------|---------|--------|
| Client-Side Validation Only | Backend trusts frontend checks | Bypass all input validation |
| Price Manipulation | Price sent from client | Purchase at arbitrary price |
| Quantity Manipulation | Quantity not validated server-side | Order more than allowed |
| Hidden Field Tampering | User role/ID in hidden field | Impersonate other users |

---

## Methodology

### Phase 1: Map the Application

1. **Identify User Roles**
   - Anonymous
   - Authenticated (regular user)
   - Premium/Paid user
   - Admin/Staff
   - Super Admin

2. **Find Critical Workflows**
   - Authentication flow
   - **Registration/onboarding** (privileged usernames, role injection, rate limiting)
   - Payment/checkout
   - Password reset
   - Data export
   - Admin functions

3. **Document Trust Boundaries**
   - What validates user input?
   - Where are authorization checks?
   - What does the backend trust?

### Phase 2: Model State Machines

For each critical workflow:
```
[State A] --action--> [State B] --action--> [State C]
                            ^
                            |
                       What prevents:
                       - Skipping B?
                       - Reversing to A?
                       - Racing through B?
```

### Phase 3: Identify Attack Surface

Look for:
- Parameters that control flow (step, status, role)
- IDs/references without ownership validation
- Values that should be server-controlled but come from client
- Actions that should be rate-limited or single-use

### Phase 4: Test Hypotheses

Develop test cases:
- What if I skip step 2?
- What if I change user_id to another user?
- What if I modify the price?
- What if I send request 100x simultaneously?

---

## Code Review Indicators

### Authorization Flaws

```python
# VULNERABLE - No ownership check
def get_order(order_id):
    return Order.query.get(order_id)  # Any user can access any order

# SECURE
def get_order(order_id, user):
    return Order.query.filter_by(id=order_id, user_id=user.id).first()
```

### Trust Boundary Issues

```python
# VULNERABLE - Trusting client-provided role
def update_user(request):
    user.role = request.data['role']  # User can set their own role!

# SECURE
def update_user(request, current_user):
    if current_user.is_admin:  # Server-side check
        user.role = request.data['role']
```

### State Manipulation

```python
# VULNERABLE - State as client parameter
def update_order_status(request, order_id):
    order = Order.query.get(order_id)
    order.status = request.data['status']  # User can set order to "shipped"!

# SECURE - Server controls state transitions
def ship_order(order_id, admin_user):
    if admin_user.has_permission('ship'):
        order = Order.query.get(order_id)
        if order.status == 'paid':  # Valid transition check
            order.status = 'shipped'
```

---

## Grep Patterns

### Find Authorization Checks (or lack thereof)

```bash
# Look for direct object access without filtering by user
grep -rniE "\.get\s*\(\s*[a-z_]+_id\s*\)" --include="*.py"
grep -rniE "findById|getById|find\(.*id\)" --include="*.java" --include="*.js"

# Find role/permission checks
grep -rniE "(is_admin|has_role|has_permission|authorize)" --include="*.py" --include="*.java" --include="*.php"

# Find missing auth decorators (compare with route definitions)
grep -rniE "@(login_required|authenticated|requires_auth)" --include="*.py"
```

### Find Trust Boundary Issues

```bash
# Client-controlled sensitive values
grep -rniE "request\.(data|json|form)\[.*(role|admin|price|discount|status)\]" --include="*.py"
grep -rniE "req\.body\.(role|admin|price|discount|status)" --include="*.js"

# Hidden field patterns in templates
grep -rniE "type=['\"]hidden['\"].*name=['\"].*id" --include="*.html" --include="*.php" --include="*.erb"
```

### Find State Machine Logic

```bash
# Status/state transitions
grep -rniE "(status|state|step)\s*=\s*(request|req|params)" --include="*.py" --include="*.java" --include="*.php" --include="*.js"

# Workflow step handling
grep -rniE "(step|stage|phase)\s*(==|!=|>=|<=)" --include="*.py" --include="*.java" --include="*.php" --include="*.js"
```

### Find Registration Security Issues

```bash
# Privileged username registration (absence of reserved check is the vulnerability)
grep -rniE "(def|function|func)\s+(register|signup|create_user)" --include="*.py" --include="*.php" --include="*.js" --include="*.go" -A 20 | grep -vE "(reserved|blocked|forbidden)"

# Role injection in registration
grep -rniE "role.*=.*request\.(data|json|form|body)|is_admin.*=.*request" --include="*.py" --include="*.php" --include="*.js"

# Missing username normalization
grep -rniE "username.*=.*request" --include="*.py" --include="*.php" --include="*.js" | grep -v "lower\|upper\|strip"

# Missing rate limiting on registration
grep -rniE "@(app\.|router\.)(route|post).*register" --include="*.py" --include="*.js" | grep -v "limiter\|throttle"
```

---

## Integration with Other Skills

- Use **dangerous-functions** after mapping trust boundaries
- Use **data-flow-tracing** to trace user input through authorization checks
- Use **vuln-patterns/race-conditions** for state manipulation attacks
- Use **exploit-techniques** to develop PoC for confirmed logic flaws

---

## Reference Files

For detailed patterns and examples:
- **`references/workflow-patterns.md`** - Multi-step process bypass techniques
- **`references/trust-boundaries.md`** - Trust boundary analysis and common flaws
- **`references/state-machine-bugs.md`** - State transition vulnerabilities
