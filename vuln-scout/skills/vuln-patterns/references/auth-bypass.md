# Authentication Bypass Patterns

## Overview

Authentication bypass vulnerabilities allow attackers to access protected functionality or impersonate users without valid credentials. These flaws often stem from logic errors, weak token generation, or improper session handling.

**OWASP Mapping**: A07:2021 - Identification and Authentication Failures

---

## Vulnerability Categories

### 1. Broken Authentication Logic
### 2. Session Management Flaws
### 3. Password Reset Vulnerabilities
### 4. Token/JWT Weaknesses
### 5. Multi-Factor Authentication Bypass

---

## 1. Broken Authentication Logic

### Logic Flaws in Login

**Vulnerable Pattern:**
```python
# VULNERABLE - Logic flaw allows bypass
def login(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password(password, user.password):
        return create_session(user)
    elif user and user.is_admin:  # BUG: Admin bypass!
        return create_session(user)
    return None
```

**Grep Patterns:**
```bash
# Find login functions with multiple return paths
grep -rniE "def (login|authenticate|verify_user)" --include="*.py" -A 20 | grep -E "(return|if.*admin|if.*role)"

# PHP login logic
grep -rniE "function\s+(login|authenticate)" --include="*.php" -A 20

# JavaScript auth functions
grep -rniE "(async\s+)?function\s+(login|authenticate|verifyUser)" --include="*.js" --include="*.ts" -A 20
```

### Type Juggling (PHP)

```php
// VULNERABLE - Type juggling bypass
if ($password == $stored_hash) {  // Use === instead
    authenticate();
}

// VULNERABLE - Magic hash
if (md5($password) == "0e123456789") {  // Compares as 0 == 0
    authenticate();
}
```

**Grep Pattern:**
```bash
# Find weak comparisons in auth
grep -rniE "(password|token|hash)\s*==\s*" --include="*.php"
```

### Default Credentials

```bash
# Search for hardcoded credentials
grep -rniE "(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]" --include="*.py" --include="*.java" --include="*.php" --include="*.js" --include="*.go" --include="*.rb" --include="*.yml" --include="*.yaml" --include="*.json"

# Common default patterns
grep -rniE "(admin|root|test|demo):(admin|root|test|demo|password|123)" --include="*"
```

---

## 2. Session Management Flaws

### Session Fixation

```php
// VULNERABLE - No session regeneration after login
session_start();
if (authenticate($user, $pass)) {
    $_SESSION['user'] = $user;
    // Missing: session_regenerate_id(true);
}
```

**Grep Patterns:**
```bash
# PHP - Missing session regeneration
grep -rniE "session_start|session_regenerate_id" --include="*.php"

# Python Flask
grep -rniE "session\[|login_user" --include="*.py"

# Check for session ID in URL
grep -rniE "PHPSESSID|JSESSIONID|session_id" --include="*.php" --include="*.java"
```

### Insecure Session Storage

```bash
# Find session configuration
grep -rniE "(session|cookie).*(secure|httponly|samesite)" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb"

# Missing secure flags
grep -rniE "set_?cookie|setCookie" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb"
```

### Session Timeout Issues

```bash
# Session timeout configuration
grep -rniE "(session|idle|timeout|expire)\s*[=:]\s*\d+" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.yml" --include="*.xml"
```

---

## 3. Password Reset Vulnerabilities

### Predictable Reset Tokens

```python
# VULNERABLE - Predictable token
def generate_reset_token(user):
    return hashlib.md5(user.email.encode()).hexdigest()  # Predictable!

# VULNERABLE - Weak randomness
def generate_reset_token(user):
    return str(random.randint(100000, 999999))  # Only 900k possibilities

# SECURE
def generate_reset_token(user):
    return secrets.token_urlsafe(32)
```

**Grep Patterns:**
```bash
# Find password reset functions
grep -rniE "(password_reset|reset_password|forgot_password|reset_token)" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb" --include="*.go"

# Weak token generation
grep -rniE "(random\.|Math\.random|rand\(|mt_rand)" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb" --include="*.go"
```

### Host Header Poisoning

```python
# VULNERABLE - Uses Host header for reset link
reset_url = f"http://{request.headers['Host']}/reset?token={token}"
# Attacker sets Host: evil.com to receive reset link
```

**Grep Pattern:**
```bash
# Host header in URLs
grep -rniE "(Host|X-Forwarded-Host).*reset|reset.*Host" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb"
```

### No Rate Limiting

```bash
# Check for rate limiting on auth endpoints
grep -rniE "(rate_limit|throttle|attempts|lockout)" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb"
```

---

## 4. Token/JWT Weaknesses

### JWT Algorithm Confusion

```python
# VULNERABLE - Accepts "none" algorithm
jwt.decode(token, options={"verify_signature": False})

# VULNERABLE - Algorithm in token header
decoded = jwt.decode(token, key, algorithms=[header['alg']])  # Attacker controls alg!

# SECURE
decoded = jwt.decode(token, key, algorithms=['RS256'])  # Explicit algorithm
```

**Grep Patterns:**
```bash
# JWT handling
grep -rniE "(jwt\.|jsonwebtoken|jose|pyjwt)" --include="*.py" --include="*.js" --include="*.java" --include="*.go" --include="*.rb"

# Algorithm none or weak
grep -rniE "(alg|algorithm).*none|HS256|verify.*false" --include="*.py" --include="*.js" --include="*.java" --include="*.go"
```

### Weak JWT Secrets

```bash
# Hardcoded JWT secrets
grep -rniE "(jwt_secret|JWT_SECRET|secret_key|SECRET_KEY)\s*[=:]\s*['\"]" --include="*.py" --include="*.js" --include="*.java" --include="*.go" --include="*.env" --include="*.yml"
```

### Missing Token Validation

```javascript
// VULNERABLE - No expiration check
const decoded = jwt.decode(token);  // decode != verify!
if (decoded.userId) {
    // Allow access
}

// SECURE
const decoded = jwt.verify(token, secret);  // Verifies signature + expiration
```

---

## 5. Multi-Factor Authentication Bypass

### MFA State Manipulation

```python
# VULNERABLE - MFA check can be skipped
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect('/login')
    # Missing: if session.get('mfa_required') and not session.get('mfa_verified'):
    return render_template('dashboard.html')
```

**Grep Patterns:**
```bash
# MFA implementation
grep -rniE "(mfa|2fa|two_factor|totp|otp)" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb" --include="*.go"

# MFA verification flow
grep -rniE "(mfa_verified|mfa_complete|otp_verified)" --include="*.py" --include="*.php" --include="*.js"
```

### OTP Brute Force

```bash
# OTP length and rate limiting
grep -rniE "(otp|totp|code)\s*[=:]\s*\d{4,6}|generate.*otp" --include="*.py" --include="*.php" --include="*.js" --include="*.java"
```

### Backup Codes

```bash
# Backup code handling
grep -rniE "(backup_code|recovery_code|emergency_code)" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb"
```

---

## Authentication Bypass Techniques

### 1. Parameter Manipulation

| Technique | Example |
|-----------|---------|
| User ID swap | `?user_id=admin` |
| Role elevation | `?role=admin` |
| Skip MFA | `?mfa=false` |
| Debug mode | `?debug=true` |

### 2. HTTP Method Override

```bash
# Find method override handling
grep -rniE "(X-HTTP-Method|X-Method-Override|_method)" --include="*.py" --include="*.php" --include="*.js" --include="*.java" --include="*.rb"
```

### 3. Response Manipulation

```javascript
// VULNERABLE - Auth decision based on response
fetch('/api/verify', { body: JSON.stringify({token}) })
    .then(r => r.json())
    .then(data => {
        if (data.success) {  // Attacker can manipulate client-side
            localStorage.setItem('isAdmin', data.isAdmin);
        }
    });
```

---

## Framework-Specific Vulnerabilities

### Django
```bash
# Authentication backends
grep -rniE "AUTHENTICATION_BACKENDS|authenticate\(" --include="*.py"

# Session settings
grep -rniE "SESSION_|CSRF_" --include="*.py" --include="settings.py"
```

### Spring Security
```bash
# Security configuration
grep -rniE "@EnableWebSecurity|WebSecurityConfigurerAdapter|SecurityFilterChain" --include="*.java"

# Permit all patterns
grep -rniE "permitAll|anonymous" --include="*.java"
```

### Express.js (Passport)
```bash
# Passport strategies
grep -rniE "passport\.(use|authenticate|serializeUser)" --include="*.js" --include="*.ts"
```

### Rails (Devise)
```bash
# Devise configuration
grep -rniE "devise|authenticate_user|current_user" --include="*.rb"
```

---

## Testing Checklist

1. [ ] Test login with SQL injection payloads
2. [ ] Test password reset token predictability
3. [ ] Attempt session fixation attacks
4. [ ] Test JWT algorithm confusion (alg: none)
5. [ ] Check for default credentials
6. [ ] Test MFA bypass by direct endpoint access
7. [ ] Check rate limiting on login/reset
8. [ ] Test remember-me token security
9. [ ] Verify session invalidation on logout
10. [ ] Check for credential enumeration (timing, messages)

---

## Remediation Summary

| Vulnerability | Fix |
|--------------|-----|
| Weak tokens | Use cryptographically secure random generation |
| Session fixation | Regenerate session ID after authentication |
| JWT alg confusion | Explicitly specify allowed algorithms |
| Missing MFA check | Enforce MFA state in middleware |
| No rate limiting | Implement progressive delays/lockouts |
| Type juggling | Use strict comparison (===) |
| Host header poison | Whitelist allowed hosts |

---

## Related CWEs

- CWE-287: Improper Authentication
- CWE-288: Authentication Bypass Using an Alternate Path
- CWE-294: Authentication Bypass by Capture-replay
- CWE-302: Authentication Bypass by Assumed-Immutable Data
- CWE-303: Incorrect Implementation of Authentication Algorithm
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-384: Session Fixation
- CWE-640: Weak Password Recovery Mechanism

---

## Registration Security

For registration-specific vulnerabilities (privileged usernames, role injection, username bypass), see:
- **`../../business-logic/references/workflow-patterns.md`** - Registration Flow Vulnerabilities section

### Quick Reference: Registration Grep Patterns

```bash
# Find registration without reserved username check
grep -rniE "(def|function)\s+(register|signup)" --include="*.py" --include="*.js" --include="*.go" -A 20 | grep -vE "(reserved|blocked|forbidden)"

# Find role injection vectors
grep -rniE "(role|admin|is_staff).*request\.(data|json|body|form)" --include="*.py" --include="*.js" --include="*.go"

# Find missing rate limiting on registration
grep -rniE "(route|post).*register" --include="*.py" --include="*.js" | grep -v "limiter\|throttle\|rate"
```
