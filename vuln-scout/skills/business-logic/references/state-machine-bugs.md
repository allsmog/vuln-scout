# State Machine Vulnerabilities

## Overview

State machines define valid transitions between states in a multi-step process. Vulnerabilities occur when:
- States can be skipped
- Invalid transitions are allowed
- States can be replayed
- Concurrent state changes cause race conditions

---

## State Machine Model

```
┌─────────┐    action_1    ┌─────────┐    action_2    ┌─────────┐
│ State A │───────────────▶│ State B │───────────────▶│ State C │
└─────────┘                └─────────┘                └─────────┘
     ▲                          │                          │
     │                          │                          │
     └──────────────────────────┴──────────────────────────┘
              Vulnerabilities: Can we bypass B? Reverse from C?
```

---

## Common State Machine Examples

### E-Commerce Order States

```
[Created] → [Pending Payment] → [Paid] → [Processing] → [Shipped] → [Delivered]
                                  │
                                  └────→ [Cancelled] → [Refunded]
```

**Attack Scenarios:**
- Skip from Created → Shipped (no payment)
- Move from Shipped → Cancelled → Refunded (refund fraud)
- Stay in Pending Payment indefinitely (inventory lock)

### Account Verification States

```
[Unverified] → [Email Sent] → [Email Clicked] → [Verified]
```

**Attack Scenarios:**
- Direct access to verified state without email confirmation
- Reuse verification token
- Race condition on verification

### Payment States

```
[Initiated] → [Authorized] → [Captured] → [Completed]
                                │
                                └────→ [Refunded]
```

**Attack Scenarios:**
- Move directly to Completed without Authorized
- Multiple captures from single authorization
- Refund without prior completion

---

## Vulnerability Patterns

### 1. Missing Transition Validation

```python
# VULNERABLE - Any state transition allowed
class Order:
    def set_status(self, new_status):
        self.status = new_status  # No validation!
        self.save()

# User can call: order.set_status('shipped') directly
```

```python
# SECURE - Explicit transition validation
class Order:
    VALID_TRANSITIONS = {
        'pending': ['paid', 'cancelled'],
        'paid': ['processing', 'refunded'],
        'processing': ['shipped'],
        'shipped': ['delivered'],
        'cancelled': [],  # Terminal state
        'delivered': [],  # Terminal state
    }

    def set_status(self, new_status):
        if new_status not in self.VALID_TRANSITIONS.get(self.status, []):
            raise InvalidTransitionError(
                f"Cannot transition from {self.status} to {new_status}"
            )
        self.status = new_status
        self.save()
```

**Grep Patterns:**
```bash
# Find state/status setters without validation
grep -rniE "\.(status|state)\s*=\s*(request|req|params)" --include="*.py" --include="*.js" --include="*.java" --include="*.php"

# Find valid transition definitions (good)
grep -rniE "(VALID_TRANSITIONS|allowed_transitions|state_machine|transitions\s*=)" --include="*.py" --include="*.js" --include="*.java"
```

---

### 2. Step Skipping

```python
# VULNERABLE - Steps not enforced
def checkout():
    if request.step == 'payment':
        process_payment()  # What if cart wasn't validated?
    elif request.step == 'confirm':
        complete_order()   # What if payment wasn't processed?

# SECURE - Each step verifies prerequisites
def checkout():
    if request.step == 'payment':
        if not current_order.cart_validated:
            raise InvalidStateError("Cart not validated")
        process_payment()
    elif request.step == 'confirm':
        if not current_order.payment_completed:
            raise InvalidStateError("Payment not completed")
        complete_order()
```

**Grep Patterns:**
```bash
# Find step/stage handling
grep -rniE "(step|stage|phase)\s*(==|!=|in\s*\[)" --include="*.py" --include="*.js" --include="*.java" --include="*.php"

# Find prerequisite checks
grep -rniE "if not.*(completed|verified|validated|approved)" --include="*.py"
```

---

### 3. State Replay Attack

```python
# VULNERABLE - No idempotency on state transitions
def apply_coupon(request):
    coupon = Coupon.query.get(request.coupon_id)
    order.apply_discount(coupon.discount)  # Can be called multiple times!
    coupon.usage_count += 1
    db.session.commit()

# SECURE - Track application and prevent replay
def apply_coupon(request):
    coupon = Coupon.query.get(request.coupon_id)

    # Check if already applied
    if CouponUsage.query.filter_by(
        order_id=order.id,
        coupon_id=coupon.id
    ).first():
        raise ValidationError("Coupon already applied to this order")

    order.apply_discount(coupon.discount)
    CouponUsage.create(order_id=order.id, coupon_id=coupon.id)
    coupon.usage_count += 1
    db.session.commit()
```

**Grep Patterns:**
```bash
# Find increment operations without idempotency checks
grep -rniE "\+=\s*1|\.add\(|\.append\(|\.push\(" --include="*.py" --include="*.js" --include="*.java" --include="*.php"

# Find duplicate prevention patterns (good)
grep -rniE "(already_.*|exists\(|filter_by.*\.first)" --include="*.py"
```

---

### 4. Concurrent State Modification

```python
# VULNERABLE - Non-atomic state transition
def ship_order(order_id):
    order = Order.query.get(order_id)
    if order.status == 'paid':  # Check
        # Race window here!
        order.status = 'shipped'  # Use
        notify_shipping()
        order.save()

# Two concurrent requests could both pass the check and double-ship

# SECURE - Atomic transition with row locking
def ship_order(order_id):
    with db.session.begin():
        order = Order.query.with_for_update().get(order_id)
        if order.status == 'paid':
            order.status = 'shipped'
            notify_shipping()
            db.session.commit()
```

**Grep Patterns:**
```bash
# Find check-then-modify patterns (potential race)
grep -rniE "if.*\.(status|state)\s*==.*\n.*\.(status|state)\s*=" --include="*.py" --include="*.java" --include="*.php"

# Find locking patterns (good)
grep -rniE "(with_for_update|FOR UPDATE|pessimistic_lock|@Lock)" --include="*.py" --include="*.java"
```

---

### 5. Terminal State Bypass

```python
# VULNERABLE - Terminal state can be changed
class Subscription:
    def cancel(self):
        self.status = 'cancelled'
        self.save()

    def reactivate(self):
        self.status = 'active'  # Can reactivate even if cancelled!
        self.save()

# SECURE - Enforce terminal states
class Subscription:
    TERMINAL_STATES = ['cancelled', 'expired']

    def reactivate(self):
        if self.status in self.TERMINAL_STATES:
            raise InvalidTransitionError("Cannot reactivate from terminal state")
        self.status = 'active'
        self.save()
```

**Grep Patterns:**
```bash
# Find terminal state definitions
grep -rniE "(TERMINAL|FINAL|END)_STATE" --include="*.py" --include="*.js" --include="*.java"

# Find state modifications
grep -rniE "\.(status|state)\s*=\s*['\"]" --include="*.py" --include="*.js" --include="*.java"
```

---

## Detection Methodology

### Step 1: Identify State Machines

Look for:
- Status/state columns in database models
- Enum definitions for states
- Workflow handlers
- Order/payment/subscription processing

```bash
# Find state definitions
grep -rniE "(status|state)_choices|class.*State|enum.*(Status|State)" --include="*.py" --include="*.java"

# Find status columns
grep -rniE "(status|state)\s*=\s*Column|@Column.*status" --include="*.py" --include="*.java"
```

### Step 2: Map Valid Transitions

Document the expected state machine:
```
State A → [valid transitions] → State B, State C
State B → [valid transitions] → State D
...
```

### Step 3: Check Transition Enforcement

For each transition, verify:
1. Is the transition validated in code?
2. Can the transition be triggered via API?
3. Are prerequisites checked?

### Step 4: Test Invalid Transitions

Try:
- Skipping intermediate states
- Reversing from later states
- Replaying the same transition
- Concurrent transitions

---

## Language-Specific Patterns

### Python (Django)

```python
# State machine library
from django_fsm import FSMField, transition

class Order(models.Model):
    status = FSMField(default='pending')

    @transition(field=status, source='pending', target='paid')
    def pay(self):
        pass  # Only allows pending → paid
```

### Java (Spring)

```java
@Entity
public class Order {
    @Enumerated(EnumType.STRING)
    private OrderStatus status;

    public void ship() {
        if (this.status != OrderStatus.PAID) {
            throw new InvalidStateException("Cannot ship unpaid order");
        }
        this.status = OrderStatus.SHIPPED;
    }
}
```

### Node.js

```javascript
// Using xstate
import { createMachine } from 'xstate';

const orderMachine = createMachine({
  initial: 'pending',
  states: {
    pending: { on: { PAY: 'paid' } },
    paid: { on: { SHIP: 'shipped' } },
    shipped: { on: { DELIVER: 'delivered' } },
    delivered: { type: 'final' }
  }
});
```

---

## Testing Checklist

For each state machine:

1. [ ] Can states be set directly via API parameter?
2. [ ] Are valid transitions explicitly defined and enforced?
3. [ ] Can prerequisite states be skipped?
4. [ ] Can terminal states be exited?
5. [ ] Is the same transition idempotent or can it be replayed?
6. [ ] Are concurrent transitions handled atomically?
7. [ ] Are state transitions logged for audit?
8. [ ] Can admin override state (intentional vs vulnerability)?

---

## Exploitation Example

### Order State Manipulation

1. **Identify API endpoint**
   ```
   POST /api/order/123/status
   {"status": "shipped"}
   ```

2. **Test direct manipulation**
   ```bash
   # Try skipping payment
   curl -X POST /api/order/123/status -d '{"status": "shipped"}'
   ```

3. **Test race condition**
   ```python
   import asyncio
   import aiohttp

   async def ship_order():
       async with aiohttp.ClientSession() as session:
           tasks = [
               session.post('/api/order/123/ship')
               for _ in range(20)
           ]
           responses = await asyncio.gather(*tasks)
           # Check if multiple shipments created
   ```

4. **Test state reversal**
   ```bash
   # Order is delivered, try to cancel for refund
   curl -X POST /api/order/123/status -d '{"status": "cancelled"}'
   curl -X POST /api/order/123/refund
   ```
