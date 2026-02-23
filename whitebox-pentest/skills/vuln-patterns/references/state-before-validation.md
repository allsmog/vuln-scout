# State Before Validation Vulnerabilities

## Overview

This reference covers vulnerabilities where **state-modifying operations occur BEFORE validation**, and the state change persists even when validation fails. These are subtle bugs that combine operation ordering issues with input validation gaps.

## Vulnerability Categories

### 1. Premature State Change

**Pattern**: State is modified before authentication/authorization is verified.

**Risk**: Attackers can trigger state changes even with invalid credentials.

### 2. Cache Key Injection

**Pattern**: User-controlled input used directly in cache/Redis key construction.

**Risk**: Path traversal in keys, cache poisoning, accessing other users' data.

### 3. Inconsistent Validation

**Pattern**: Input validation exists on one endpoint but not another using the same data.

**Risk**: Attackers bypass validation by using the unvalidated endpoint.

### 4. Failed Operation Persistence

**Pattern**: Side effects from failed operations are not rolled back.

**Risk**: Partial state changes create exploitable conditions.

---

## Detection Patterns

### Go

```bash
# Premature state change in auth handlers
grep -rniE "(PrepareSession|SetSession|CreateSession|InitSession)" --include="*.go" -A10 | \
  grep -E "(login|Login|authenticate|Authenticate|validate|Validate)"

# Cache/Redis operations with user input
grep -rniE "redis\.(Set|Get|Del|HSet|HGet)\(" --include="*.go" -B2 -A2
grep -rniE "cache\.(Set|Get|Delete)\(" --include="*.go" -B2 -A2

# Cache key construction with variables
grep -rniE "(redis|cache)\.(Set|Get).*\+" --include="*.go"
grep -rniE "key\s*:?=.*username|key\s*:?=.*credentials" --include="*.go"

# Inconsistent validation - find validation patterns
grep -rniE "ContainsAny.*[\"'][/\\\\.]" --include="*.go"
grep -rniE "strings\.(Contains|HasPrefix).*\.\." --include="*.go"

# State change without cleanup on error
grep -rniE "if err != nil \{" --include="*.go" -A5 | grep -v "cleanup\|rollback\|delete\|remove"
```

### Python

```bash
# Premature state change
grep -rniE "(session\[|cache\.set|redis\.set|r\.set)" --include="*.py" -A10 | \
  grep -E "(authenticate|login|validate|check_password)"

# Cache key with user input
grep -rniE "redis\.(set|get|delete)\(.*request\." --include="*.py"
grep -rniE "cache\[.*request\.|cache\.set\(.*request\." --include="*.py"

# Key construction patterns
grep -rniE "key\s*=.*f['\"].*{.*username" --include="*.py"
grep -rniE "key\s*=.*\+.*username" --include="*.py"
```

### JavaScript/TypeScript

```bash
# Premature state change
grep -rniE "(redis\.set|cache\.set|session\[)" --include="*.ts" --include="*.js" -A10 | \
  grep -E "(authenticate|login|verify|validate)"

# Cache key with user input
grep -rniE "redis\.(set|get)\(`.*\$\{" --include="*.ts" --include="*.js"
grep -rniE "cache\[.*req\.(body|params|query)" --include="*.ts" --include="*.js"
```

---

## Vulnerable Code Examples

### Example 1: Premature State Change (Go)

```go
// VULNERABLE: State change BEFORE authentication
func LoginHandler(c *fiber.Ctx) error {
    var credentials Credentials
    c.BodyParser(&credentials)

    sessionID := generateSessionID()

    // BUG: Redis key set BEFORE authentication check!
    PrepareSession(sessionID, credentials.Username)  // ← State change

    // Authentication happens AFTER
    user, err := loginUser(credentials.Username, credentials.Password)
    if err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid credentials"})
        // Redis key still exists with attacker-controlled username!
    }

    CreateSession(sessionID, user)
    return c.Redirect("/dashboard")
}
```

**Attack**:
1. Send login request with `username=../../malicious/path`
2. Auth fails, but Redis now has key `../../malicious/path` → `sessionID`
3. Chain with other vulnerabilities (file operations, path traversal)

### Example 2: Cache Key Injection (Go)

```go
// VULNERABLE: User input directly in cache key
func GetUserSession(username string) (*Session, error) {
    // No validation of username!
    key := "session:" + username  // username could be "../../../etc/passwd"

    data, err := redis.Get(key)
    if err != nil {
        return nil, err
    }

    return parseSession(data)
}

// Attack: Set username cookie to "../../other_user" to access their session
```

### Example 3: Inconsistent Validation (Go)

```go
// Registration endpoint HAS validation
func RegisterHandler(c *fiber.Ctx) error {
    username := c.FormValue("username")

    // Validation present
    if strings.ContainsAny(username, "/.\\") {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid username"})
    }

    // ... create user
}

// Login endpoint MISSING validation
func LoginHandler(c *fiber.Ctx) error {
    username := c.FormValue("username")

    // NO validation here!
    // Attacker bypasses by going directly to login with malicious username

    PrepareSession(sessionID, username)  // Path traversal possible
    // ...
}
```

### Example 4: Failed Operation Persistence (Python)

```python
# VULNERABLE: State change not rolled back on failure
def transfer_funds(from_account, to_account, amount):
    # Debit happens first
    from_account.balance -= amount
    db.session.commit()  # ← State change persisted

    # Credit may fail
    try:
        to_account.balance += amount
        db.session.commit()
    except Exception as e:
        # Debit was already committed!
        # Money disappeared from system
        raise e
```

---

## Secure Code Patterns

### Pattern 1: Validate Before State Change

```go
// SECURE: Validation and auth BEFORE any state change
func LoginHandler(c *fiber.Ctx) error {
    var credentials Credentials
    c.BodyParser(&credentials)

    // 1. Validate input FIRST
    if strings.ContainsAny(credentials.Username, "/.\\") {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid username"})
    }

    // 2. Authenticate SECOND
    user, err := loginUser(credentials.Username, credentials.Password)
    if err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid credentials"})
    }

    // 3. State change LAST (only after validation succeeds)
    sessionID := generateSessionID()
    PrepareSession(sessionID, user.Username)  // Use validated user object
    CreateSession(sessionID, user)

    return c.Redirect("/dashboard")
}
```

### Pattern 2: Safe Cache Key Construction

```go
// SECURE: Validate and sanitize before using as key
func GetUserSession(username string) (*Session, error) {
    // Option 1: Validate
    if strings.ContainsAny(username, "/.\\:") {
        return nil, errors.New("invalid username")
    }

    // Option 2: Hash the key (prevents any injection)
    keyHash := sha256.Sum256([]byte(username))
    key := "session:" + hex.EncodeToString(keyHash[:])

    data, err := redis.Get(key)
    // ...
}
```

### Pattern 3: Consistent Validation

```go
// SECURE: Centralized validation function used everywhere
func validateUsername(username string) error {
    if len(username) < 3 || len(username) > 32 {
        return errors.New("username must be 3-32 characters")
    }
    if strings.ContainsAny(username, "/.\\:") {
        return errors.New("username contains invalid characters")
    }
    if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
        return errors.New("username must be alphanumeric")
    }
    return nil
}

// Use in BOTH register AND login
func RegisterHandler(c *fiber.Ctx) error {
    if err := validateUsername(credentials.Username); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }
    // ...
}

func LoginHandler(c *fiber.Ctx) error {
    if err := validateUsername(credentials.Username); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }
    // ...
}
```

### Pattern 4: Atomic Operations with Rollback

```python
# SECURE: Use transactions with automatic rollback
def transfer_funds(from_account, to_account, amount):
    with db.session.begin():  # Atomic transaction
        from_account.balance -= amount
        to_account.balance += amount
        # Both committed together, or neither
```

---

## Real-World Attack Scenario

**Target**: Web application with session management via Redis

**Vulnerability Chain**:
1. Login endpoint sets Redis key before validating credentials
2. Username is not validated on login (only on registration)
3. Session files stored at `/tmp/sessions/{username}/{sessionID}`
4. File upload extracts to `./files/{username}/`

**Exploitation**:
```bash
# Step 1: Attempt login with path traversal username (auth fails, but Redis key set)
curl -X POST http://target/login \
  -d '{"username":"../../app/files/attacker","password":"anything"}'
# Redis now has: "../../app/files/attacker" → "predictable_session_id"

# Step 2: Upload admin session file
echo '{"username":"admin","role":"admin"}' > session.json
tar -cf exploit.tar session.json
curl -X POST http://target/upload -F "file=@exploit.tar" -b "session=valid_session"
# File extracted to ./files/attacker/session.json

# Step 3: Access with path traversal
curl http://target/admin \
  -H "Cookie: username=../../app/files/attacker; session=session.json"
# Session lookup: /tmp/sessions/../../app/files/attacker/session.json
#              = /app/files/attacker/session.json (our uploaded file!)
```

---

## Audit Checklist

When reviewing authentication and session code:

- [ ] **Operation Order**: Do all state changes happen AFTER validation/authentication?
- [ ] **Cache Keys**: Are cache/Redis keys constructed from validated input only?
- [ ] **Consistent Validation**: Is input validation applied uniformly across all endpoints?
- [ ] **Error Handling**: Do error paths clean up any state changes made before the error?
- [ ] **Input Sources**: Is the same validation applied regardless of input source (body, cookie, header)?
- [ ] **Predictable State**: Are session IDs, tokens, and keys unpredictable?

---

## Related Patterns

- **Race Conditions** (`race-conditions.md`) - Concurrent check-then-use issues
- **Auth Bypass** (`auth-bypass.md`) - Session fixation, weak tokens
- **Path Traversal** (`injection-attacks.md`) - File path manipulation
- **Business Logic** (`workflow-patterns.md`) - Step skipping, state manipulation
