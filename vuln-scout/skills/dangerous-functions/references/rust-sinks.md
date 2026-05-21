# Rust Dangerous Functions

## Overview

Rust's memory safety guarantees prevent many traditional vulnerabilities, but security issues can still arise through unsafe blocks, FFI, and logic errors.

---

## Command Execution

| Function/Type | Risk | Notes |
|---------------|------|-------|
| `std::process::Command` | Critical | Shell command execution |
| `Command::new().arg()` | Critical | Command with arguments |
| `Command::spawn()` | Critical | Async command execution |
| `std::process::exit()` | Medium | Process termination |

**Grep Patterns:**
```bash
grep -rniE "(Command::new|\.spawn\(\)|\.output\(\)|process::Command)" --include="*.rs"

# Shell execution with user input
grep -rniE "Command::new.*\.arg\(" --include="*.rs"
```

**Vulnerable Pattern:**
```rust
// VULNERABLE - User input in command
use std::process::Command;

fn run_command(user_input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(user_input)  // Command injection!
        .output()
        .expect("failed");
}
```

**Secure Pattern:**
```rust
// SECURE - Avoid shell, use direct execution
fn run_command(filename: &str) {
    Command::new("cat")
        .arg(filename)  // Still validate filename!
        .output()
        .expect("failed");
}
```

---

## Unsafe Code

| Pattern | Risk | Notes |
|---------|------|-------|
| `unsafe { }` blocks | High | Bypasses borrow checker |
| `*const T` / `*mut T` | High | Raw pointers |
| `std::mem::transmute` | Critical | Type coercion, UB risk |
| `std::ptr::read/write` | High | Manual memory operations |
| `from_raw_parts` | High | Slice from raw pointer |

**Grep Patterns:**
```bash
# Find all unsafe blocks
grep -rniE "unsafe\s*\{" --include="*.rs"

# Raw pointer operations
grep -rniE "(\*const|\*mut|transmute|from_raw_parts)" --include="*.rs"

# Unsafe function declarations
grep -rniE "unsafe\s+fn" --include="*.rs"
```

**Review Focus:**
- Buffer overflows in unsafe blocks
- Use-after-free via raw pointers
- Data races with `*mut`
- Undefined behavior from transmute

---

## FFI (Foreign Function Interface)

| Pattern | Risk | Notes |
|---------|------|-------|
| `extern "C"` | High | C ABI functions |
| `#[link]` attribute | High | External library linking |
| `CString`/`CStr` | Medium | C string handling |
| `libc` crate | High | Direct libc calls |

**Grep Patterns:**
```bash
# FFI declarations
grep -rniE '(extern\s+"C"|#\[link|#\[no_mangle\])' --include="*.rs"

# libc usage
grep -rniE "(libc::|use libc)" --include="*.rs"

# CString operations
grep -rniE "(CString|CStr|as_ptr|into_raw)" --include="*.rs"
```

---

## SQL/Database

| Library/Pattern | Risk | Notes |
|-----------------|------|-------|
| `sqlx::query!` | Low | Compile-time checked |
| `sqlx::query()` | High | Runtime query, check for concat |
| `diesel::sql_query` | High | Raw SQL |
| `rusqlite` | High | Check for string formatting |
| `format!` in SQL | Critical | SQL injection |

**Grep Patterns:**
```bash
# String formatting in queries
grep -rniE "(format!|&format).*SELECT|INSERT|UPDATE|DELETE" --include="*.rs"

# Raw SQL execution
grep -rniE "(sql_query|execute\(|raw_sql)" --include="*.rs"

# Dynamic query building
grep -rniE "\.query\(&|query_as\(&" --include="*.rs"
```

**Vulnerable Pattern:**
```rust
// VULNERABLE - Format string in SQL
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
sqlx::query(&query).fetch_one(&pool).await?;
```

**Secure Pattern:**
```rust
// SECURE - Parameterized query
sqlx::query!("SELECT * FROM users WHERE id = $1", user_id)
    .fetch_one(&pool)
    .await?;
```

---

## File Operations

| Function | Risk | Notes |
|----------|------|-------|
| `std::fs::read` | Medium | File read |
| `std::fs::write` | High | File write |
| `std::fs::remove_file` | High | File deletion |
| `std::fs::File::open` | Medium | File access |
| `include_str!` / `include_bytes!` | Low | Compile-time inclusion |

**Grep Patterns:**
```bash
# File operations with potential user input
grep -rniE "(fs::read|fs::write|fs::remove|File::open|File::create)" --include="*.rs"

# Path operations
grep -rniE "(Path::new|PathBuf::from)" --include="*.rs"
```

**Path Traversal Check:**
```rust
// VULNERABLE
fn read_file(filename: &str) -> std::io::Result<String> {
    std::fs::read_to_string(filename)  // No path validation!
}

// SECURE
fn read_file(filename: &str) -> std::io::Result<String> {
    let path = Path::new("./safe_dir").join(filename);
    let canonical = path.canonicalize()?;
    if !canonical.starts_with("./safe_dir") {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Path traversal"));
    }
    std::fs::read_to_string(canonical)
}
```

---

## HTTP/Network (SSRF)

| Library | Risk | Notes |
|---------|------|-------|
| `reqwest` | High | If URL user-controlled |
| `hyper` | High | Low-level HTTP |
| `surf` | High | Async HTTP client |
| `ureq` | High | Blocking HTTP client |

**Grep Patterns:**
```bash
# HTTP clients with potential user URLs
grep -rniE "(reqwest::get|Client::new|hyper::Client|ureq::get)" --include="*.rs"

# URL construction
grep -rniE "(format!.*http|Url::parse)" --include="*.rs"
```

---

## Deserialization

| Library/Pattern | Risk | Notes |
|-----------------|------|-------|
| `serde_json` | Low | Generally safe |
| `serde_yaml` | Medium | YAML-specific attacks |
| `bincode` | Medium | Binary format |
| `rmp-serde` | Medium | MessagePack |
| Custom `Deserialize` | High | Check implementations |

**Grep Patterns:**
```bash
# Deserialization calls
grep -rniE "(from_str|from_slice|from_reader|deserialize)" --include="*.rs"

# Serde derive with custom behavior
grep -rniE '#\[serde\(' --include="*.rs"
```

---

## Cryptography

| Pattern | Risk | Notes |
|---------|------|-------|
| Hardcoded keys | Critical | Embedded secrets |
| `rand::thread_rng` | Low | Generally OK for crypto |
| `rand::random` | Medium | Check usage context |
| Custom crypto | Critical | Don't roll your own |

**Grep Patterns:**
```bash
# Hardcoded secrets
grep -rniE '(secret|key|password|token)\s*[=:]\s*"' --include="*.rs"

# Weak random
grep -rniE "rand::random|thread_rng" --include="*.rs"

# Crypto operations
grep -rniE "(encrypt|decrypt|sign|verify|hash)" --include="*.rs"
```

---

## Error Handling

| Pattern | Risk | Notes |
|---------|------|-------|
| `.unwrap()` | Medium | Panics on error |
| `.expect()` | Medium | Panics with message |
| `panic!()` | Medium | Explicit panic |
| Error messages with secrets | High | Information disclosure |

**Grep Patterns:**
```bash
# Panic-prone patterns
grep -rniE "(\.unwrap\(\)|\.expect\(|panic!)" --include="*.rs"

# Error messages with potential secrets
grep -rniE '(Err|Error|panic!).*format!' --include="*.rs"
```

---

## Web Frameworks

### Actix-web

```bash
# Route handlers
grep -rniE '#\[(get|post|put|delete|patch)\(' --include="*.rs"

# Path parameters
grep -rniE "web::Path|web::Query|web::Json" --include="*.rs"

# Missing authentication
grep -rniE "HttpResponse::" --include="*.rs" | grep -v "auth\|guard\|middleware"
```

### Rocket

```bash
# Route attributes
grep -rniE '#\[(get|post|put|delete)\(' --include="*.rs"

# Form data
grep -rniE "Form<|FromForm" --include="*.rs"
```

### Axum

```bash
# Extractors
grep -rniE "(Path|Query|Json|Form)<" --include="*.rs"

# Route definitions
grep -rniE "Router::new\(\)|\.route\(" --include="*.rs"
```

---

## Concurrency Issues

| Pattern | Risk | Notes |
|---------|------|-------|
| `Arc<Mutex<>>` | Medium | Potential deadlocks |
| `static mut` | Critical | Data races |
| `lazy_static!` | Low | Generally safe |
| `crossbeam` channels | Low | Safe concurrency |

**Grep Patterns:**
```bash
# Mutable statics (unsafe)
grep -rniE "static\s+mut" --include="*.rs"

# Mutex usage
grep -rniE "(Mutex|RwLock|Arc)" --include="*.rs"

# Unsafe sync primitives
grep -rniE "UnsafeCell" --include="*.rs"
```

---

## Environment Variables

```bash
# Environment variable access
grep -rniE "(env::var|env::var_os|std::env::)" --include="*.rs"

# Sensitive env vars
grep -rniE 'env::var.*"(SECRET|PASSWORD|KEY|TOKEN|API)"' --include="*.rs"
```

---

## Testing Checklist

1. [ ] Review all `unsafe` blocks for memory safety
2. [ ] Check FFI boundaries for proper validation
3. [ ] Verify SQL queries use parameterization
4. [ ] Audit command execution for injection
5. [ ] Check file operations for path traversal
6. [ ] Review error handling for information disclosure
7. [ ] Verify HTTP clients validate URLs
8. [ ] Check for hardcoded credentials
9. [ ] Review concurrent code for race conditions
10. [ ] Audit deserialization of untrusted data
