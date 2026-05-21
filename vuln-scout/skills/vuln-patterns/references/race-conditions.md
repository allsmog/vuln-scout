# Race Conditions & TOCTOU Vulnerabilities

## Overview

Race conditions occur when the outcome of an operation depends on the timing or sequence of uncontrollable events. In web applications, these often manifest as Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities where a condition is checked and then used in a non-atomic manner.

**OWASP Mapping**: Related to A04:2021 - Insecure Design

---

## Vulnerability Pattern

```
IF check(resource)           # Time of Check
   THEN use(resource)        # Time of Use
   AND operation_not_atomic
THEN race_condition_possible
```

---

## Common Race Condition Categories

### 1. Financial/Balance Race Conditions
### 2. Inventory/Stock Race Conditions
### 3. Coupon/Voucher Race Conditions
### 4. Rate Limit Bypass
### 5. File System Race Conditions
### 6. Authentication Race Conditions

---

## 1. Financial/Balance Race Conditions

### Double Spend Attack

```python
# VULNERABLE - Non-atomic balance check and deduction
def withdraw(user_id, amount):
    user = User.query.get(user_id)
    if user.balance >= amount:  # Check
        time.sleep(0.1)  # Window for race
        user.balance -= amount  # Use
        db.session.commit()
        transfer_money(amount)
        return True
    return False
```

**Grep Patterns:**
```bash
# Find balance check patterns
grep -rniE "(balance|credit|points|coins|tokens)\s*(>=|>|<=|<|==)\s*" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"

# Find non-atomic operations
grep -rniE "(if.*balance|if.*amount).*\n.*(-=|\+=|update)" --include="*.py" --include="*.java" --include="*.php"
```

### Secure Implementation

```python
# SECURE - Database-level atomic operation with row locking
def withdraw(user_id, amount):
    with db.session.begin():
        user = User.query.with_for_update().get(user_id)  # Row lock
        if user.balance >= amount:
            user.balance -= amount
            db.session.commit()
            return True
    return False

# SECURE - Single atomic query
def withdraw(user_id, amount):
    result = User.query.filter(
        User.id == user_id,
        User.balance >= amount
    ).update({User.balance: User.balance - amount})
    db.session.commit()
    return result > 0
```

---

## 2. Inventory/Stock Race Conditions

### Overselling Attack

```php
// VULNERABLE
function purchase($product_id, $quantity) {
    $product = Product::find($product_id);
    if ($product->stock >= $quantity) {  // Check
        // Race window here
        $product->stock -= $quantity;    // Use
        $product->save();
        create_order($product_id, $quantity);
    }
}
```

**Grep Patterns:**
```bash
# Stock/inventory checks
grep -rniE "(stock|inventory|quantity|available)\s*(>=|>|<=|<)\s*" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"

# Decrement operations
grep -rniE "(stock|inventory|quantity).*(-=|decrement|reduce)" --include="*.py" --include="*.java" --include="*.php" --include="*.js"
```

---

## 3. Coupon/Voucher Race Conditions

### Single-Use Coupon Bypass

```javascript
// VULNERABLE
async function applyCoupon(userId, couponCode) {
    const coupon = await Coupon.findOne({ code: couponCode });
    if (coupon && !coupon.used) {  // Check
        // Race window
        await applyDiscount(userId, coupon.discount);
        coupon.used = true;  // Use
        await coupon.save();
    }
}
```

**Grep Patterns:**
```bash
# Coupon/voucher/promo code handling
grep -rniE "(coupon|voucher|promo|discount|gift_?card).*\.(used|redeemed|claimed)" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"

# Single-use flag patterns
grep -rniE "if.*!(used|redeemed|claimed)" --include="*.py" --include="*.java" --include="*.php" --include="*.js"
```

---

## 4. Rate Limit Bypass

### Counter Race Condition

```python
# VULNERABLE - In-memory counter can be raced
request_count = {}

def check_rate_limit(user_id):
    if request_count.get(user_id, 0) >= 100:
        return False
    request_count[user_id] = request_count.get(user_id, 0) + 1  # Not atomic!
    return True
```

**Grep Patterns:**
```bash
# Rate limiting patterns
grep -rniE "(rate_limit|request_count|api_calls|throttle)" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"

# Counter increment patterns
grep -rniE "\+=\s*1|\+\+|incr\(" --include="*.py" --include="*.java" --include="*.php" --include="*.js"
```

---

## 5. File System Race Conditions

### TOCTOU File Access

```python
# VULNERABLE - Classic TOCTOU
def process_file(filepath):
    if os.path.isfile(filepath):  # Check
        # Attacker can replace file here with symlink
        with open(filepath, 'r') as f:  # Use
            return f.read()
```

```c
// VULNERABLE - C example
if (access(filename, R_OK) == 0) {  // Check
    // Race window - file could be replaced
    fd = open(filename, O_RDONLY);   // Use
}
```

**Grep Patterns:**
```bash
# File existence checks followed by operations
grep -rniE "(os\.path\.(exists|isfile)|file_exists|access\()" --include="*.py" --include="*.php" --include="*.c" --include="*.go"

# Symlink-related
grep -rniE "(symlink|readlink|lstat)" --include="*.py" --include="*.php" --include="*.c" --include="*.go"
```

### Temp File Race

```bash
# Find temp file creation patterns
grep -rniE "(tempfile|mktemp|tmpfile|tmp_name)" --include="*.py" --include="*.php" --include="*.c" --include="*.go" --include="*.java"

# Insecure temp file patterns
grep -rniE "open\s*\(\s*['\"]\/tmp\/" --include="*.py" --include="*.php" --include="*.c"
```

---

## 6. Authentication Race Conditions

### Session Race Condition

```python
# VULNERABLE - Login race can create duplicate sessions
def login(username, password):
    user = authenticate(username, password)
    if user:
        if not Session.query.filter_by(user_id=user.id).first():  # Check
            # Race window
            session = Session(user_id=user.id)  # Use
            db.session.add(session)
            db.session.commit()
```

**Grep Patterns:**
```bash
# Session creation patterns
grep -rniE "(session|token).*create|new.*(session|token)" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"
```

---

## Detection Techniques

### 1. Identify Non-Atomic Operations

```bash
# Look for check-then-use patterns across multiple lines
grep -rniE "if\s*\(" --include="*.py" --include="*.java" --include="*.php" --include="*.js" -A 5 | grep -E "(balance|stock|count|limit|used)"
```

### 2. Find Missing Locks

```bash
# Database locking
grep -rniE "(for_update|SELECT.*FOR UPDATE|LOCK|with_for_update|lock\()" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb"

# Thread/mutex locks
grep -rniE "(threading\.Lock|synchronized|mutex|RLock|Semaphore)" --include="*.py" --include="*.java" --include="*.go"
```

### 3. Identify Atomic Operations (Safe)

```bash
# Atomic database operations
grep -rniE "(atomic|transaction|BEGIN|COMMIT|F\('|update.*where)" --include="*.py" --include="*.java" --include="*.php" --include="*.js"

# Redis atomic operations
grep -rniE "(INCR|DECR|SETNX|WATCH|MULTI|EXEC)" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go"
```

---

## Language-Specific Patterns

### Python (Django/Flask)
```bash
# Django F expressions (atomic)
grep -rniE "F\(['\"]" --include="*.py"

# SQLAlchemy locking
grep -rniE "with_for_update|select_for_update" --include="*.py"

# Django atomic blocks
grep -rniE "@transaction\.atomic|with transaction\.atomic" --include="*.py"
```

### Java
```bash
# Synchronized blocks
grep -rniE "synchronized|AtomicInteger|AtomicLong" --include="*.java"

# JPA locking
grep -rniE "@Lock|LockModeType\.(PESSIMISTIC|OPTIMISTIC)" --include="*.java"
```

### PHP
```bash
# Database transactions
grep -rniE "(beginTransaction|commit|rollback|lockForUpdate)" --include="*.php"

# File locking
grep -rniE "flock\(" --include="*.php"
```

### Go
```bash
# Mutex usage
grep -rniE "(sync\.Mutex|sync\.RWMutex|\.Lock\(\)|\.Unlock\(\))" --include="*.go"

# Atomic operations
grep -rniE "atomic\.(Add|Load|Store|CompareAndSwap)" --include="*.go"
```

### Node.js
```bash
# Async/await race patterns
grep -rniE "async.*await.*if.*await" --include="*.js" --include="*.ts"

# Redis atomic operations
grep -rniE "(multi|exec|watch)\s*\(" --include="*.js" --include="*.ts"
```

---

## Exploitation Techniques

### 1. Turbo Intruder (Burp Suite)
```python
# Single-packet attack for race conditions
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100)
    for i in range(30):
        engine.queue(target.req, gate='race')
    engine.openGate('race')
```

### 2. Parallel Requests Script
```python
#!/usr/bin/env python3
import asyncio
import aiohttp

async def send_request(session, url, data):
    async with session.post(url, data=data) as response:
        return await response.text()

async def race_attack(url, data, count=50):
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data) for _ in range(count)]
        responses = await asyncio.gather(*tasks)
        return responses

# Usage
asyncio.run(race_attack('https://target/api/withdraw', {'amount': 100}))
```

---

## Testing Checklist

1. [ ] Identify operations with check-then-use pattern
2. [ ] Test concurrent requests to financial endpoints
3. [ ] Attempt double-spending/redemption attacks
4. [ ] Check for database locking mechanisms
5. [ ] Test file operations for TOCTOU
6. [ ] Verify atomic operations for counters
7. [ ] Test session creation for duplicates
8. [ ] Check rate limiting with parallel requests

---

## Remediation

### 1. Database-Level Locking
```sql
-- PostgreSQL/MySQL
SELECT * FROM users WHERE id = 1 FOR UPDATE;
UPDATE users SET balance = balance - 100 WHERE id = 1 AND balance >= 100;
```

### 2. Atomic Operations
```python
# Django atomic F expression
User.objects.filter(id=user_id, balance__gte=amount).update(
    balance=F('balance') - amount
)
```

### 3. Optimistic Locking
```python
# Version-based concurrency control
class User(models.Model):
    balance = models.IntegerField()
    version = models.IntegerField(default=0)

# Update only if version matches
User.objects.filter(id=user_id, version=current_version).update(
    balance=F('balance') - amount,
    version=F('version') + 1
)
```

### 4. Redis Distributed Locks
```python
import redis
from redis.lock import Lock

r = redis.Redis()
with Lock(r, f'user:{user_id}:withdraw'):
    # Perform operation
    pass
```

---

## Related CWEs

- CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization
- CWE-366: Race Condition Within a Thread
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- CWE-421: Race Condition During Access to Alternate Channel
- CWE-689: Permission Race Condition During Resource Copy
