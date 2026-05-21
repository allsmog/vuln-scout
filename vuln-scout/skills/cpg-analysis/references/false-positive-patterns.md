# False Positive Patterns Database

Common patterns that cause security tools to report false positives. Use this to quickly identify and eliminate non-issues.

## SQL Injection False Positives

### Parameterized Queries

**Pattern**: Placeholders separate data from query structure.

```javascript
// FALSE POSITIVE - Parameterized query
db.query('SELECT * FROM users WHERE id = ?', [userId]);
db.query('SELECT * FROM users WHERE email = $1', [email]);
db.query('SELECT * FROM users WHERE name = :name', { name: userName });
```

**Vulnerable pattern** (TRUE POSITIVE): Template literals or string concatenation with user input in query string.

**Detection**: Look for `?`, `$1`, `:name` placeholders AND separate parameter array.

### ORM Methods

**Pattern**: ORM methods that auto-escape.

```javascript
// FALSE POSITIVE - ORM handles escaping
User.findById(userId);
User.findOne({ where: { email: userEmail } });
prisma.user.findUnique({ where: { id: userId } });
```

**Vulnerable pattern** (TRUE POSITIVE): Raw query methods with string interpolation.

**Detection**: Method names like `findById`, `findOne`, `findUnique` with object params.

### Type Coercion

**Pattern**: Input converted to safe type before use.

```javascript
// FALSE POSITIVE - Coerced to number
const id = parseInt(req.params.id, 10);
// id is now a number, cannot contain SQL syntax
```

**Detection**: `parseInt`, `Number()`, `parseFloat` before query.

### Constant/Config Sources

**Pattern**: Query built from trusted sources.

```javascript
// FALSE POSITIVE - Config value, not user input
const table = config.tableName;  // From trusted config
```

**Detection**: Source is config object, environment variable, or constant.

---

## Command Injection False Positives

### Array Arguments (spawn/execFile)

**Pattern**: `spawn()` or `execFile()` with array args doesn't invoke shell.

```javascript
// FALSE POSITIVE - Array args, no shell interpretation
spawn('convert', [inputFile, '-resize', size, outputFile]);
execFile('ls', ['-la', directory]);
```

**Vulnerable pattern** (TRUE POSITIVE): Shell string commands with interpolated user input.

**Detection**: `spawn` or `execFile` with array as second argument.

### Type Coercion

**Pattern**: Numeric input prevents injection.

```javascript
// FALSE POSITIVE - Port is numeric only
const port = parseInt(req.query.port, 10);
// port cannot contain shell metacharacters
```

**Detection**: `parseInt`, `Number()` conversion before shell command.

### Allowlist Validation

**Pattern**: Input validated against known-safe values.

```javascript
// FALSE POSITIVE - Allowlist validation
const allowed = ['pdf', 'png', 'jpg'];
if (!allowed.includes(format)) throw new Error('Invalid');
// format is guaranteed to be one of the safe values
```

**Detection**: `includes()`, `indexOf()`, or switch/case before shell command.

---

## XSS False Positives

### JSON Response

**Pattern**: JSON Content-Type prevents HTML execution.

```javascript
// FALSE POSITIVE - JSON response
res.json({ name: userName });  // Content-Type: application/json
```

**Detection**: `res.json()` or explicit `Content-Type: application/json`.

### Framework Auto-Escaping

**Pattern**: Template engine auto-escapes by default.

```jsx
// FALSE POSITIVE - React JSX auto-escapes
return <div>{userName}</div>;
```

```html
<!-- FALSE POSITIVE - Angular template auto-escapes -->
<div>{{ userName }}</div>
```

**Vulnerable pattern** (TRUE POSITIVE): React's unsafe innerHTML prop, Angular's `[innerHTML]`, Vue's `v-html` directives.

**Detection**: JSX expressions `{}`, Angular `{{ }}`, Vue `{{ }}` without unsafe directives.

### Explicit Encoding

**Pattern**: HTML encoding before output.

```javascript
// FALSE POSITIVE - Encoded output
const safe = escapeHtml(userInput);
res.send('<div>' + safe + '</div>');
```

**Detection**: `escapeHtml`, `htmlEncode`, `encode` function calls.

---

## Path Traversal False Positives

### Path Normalization

**Pattern**: `path.resolve()` or `path.normalize()` before use.

```javascript
// FALSE POSITIVE - Normalized path with validation
const safePath = path.resolve(uploadDir, userFilename);
if (!safePath.startsWith(uploadDir)) throw new Error('Invalid');
fs.readFile(safePath);
```

**Detection**: `path.resolve()`, `path.normalize()` followed by `startsWith()` check.

### Basename Extraction

**Pattern**: Only filename used, directory stripped.

```javascript
// FALSE POSITIVE - Only filename kept
const filename = path.basename(userFilename);
fs.readFile(path.join(uploadDir, filename));
```

**Detection**: `path.basename()` extracts filename before file operation.

---

## SSRF False Positives

### URL Allowlist

**Pattern**: Hostname validated against allowlist.

```javascript
// FALSE POSITIVE - Allowlisted hosts
const allowed = ['api.example.com', 'cdn.example.com'];
const url = new URL(userUrl);
if (!allowed.includes(url.hostname)) throw new Error('Invalid');
fetch(userUrl);
```

**Detection**: `URL` constructor + hostname check before request.

### Fixed Base URL

**Pattern**: Only path component is user-controlled.

```javascript
// FALSE POSITIVE - Fixed base URL
const apiUrl = 'https://api.example.com/users/' + userId;
fetch(apiUrl);
```

**Detection**: Hardcoded `https://` prefix with only path variable.

---

## Deserialization False Positives

### Safe Formats

**Pattern**: JSON parsing is safe (no code in data).

```javascript
// FALSE POSITIVE - JSON is safe
const data = JSON.parse(userInput);
```

**Vulnerable formats** (TRUE POSITIVE): YAML with unsafe loaders, PHP unserialize, Java ObjectInputStream.

**Detection**: `JSON.parse` vs unsafe deserializers.

### Schema Validation

**Pattern**: Input validated before deserialization.

```javascript
// LOWER RISK - Schema validation
const schema = Joi.object({ name: Joi.string(), age: Joi.number() });
const validated = schema.validate(JSON.parse(userInput));
```

**Detection**: Schema validation (Joi, Yup, Zod) before use.

---

## Test/Mock File Exclusions

### Test Files

Files that should be excluded from vulnerability scanning:

```
**/test/**
**/tests/**
**/__tests__/**
**/*.test.js
**/*.spec.js
**/fixtures/**
**/mocks/**
```

### Vendor/Dependencies

```
**/node_modules/**
**/vendor/**
**/third_party/**
**/dist/**
**/build/**
```

### Generated Code

```
**/*.generated.js
**/*.min.js
**/coverage/**
**/.next/**
**/out/**
```

---

## Quick Reference Table

| Vulnerability | False Positive Pattern | Detection Method |
|---------------|------------------------|------------------|
| SQLi | Parameterized query | `?`, `$1`, `:name` + params array |
| SQLi | ORM method | `findById`, `findOne` with object |
| SQLi | Type coercion | `parseInt` before query |
| CMDi | Array args | `spawn(cmd, [args])` |
| CMDi | Allowlist | `includes()` check before command |
| XSS | JSON response | `res.json()` |
| XSS | Auto-escaping | JSX `{}`, Angular `{{ }}` |
| XSS | Encoding | `escapeHtml()` |
| PathTrav | Normalization | `path.resolve()` + `startsWith()` |
| PathTrav | Basename | `path.basename()` |
| SSRF | Allowlist | URL hostname check |
| SSRF | Fixed base | Hardcoded `https://` prefix |

---

## Confidence Adjustments

When a false positive pattern is detected:

| Pattern Strength | Confidence Reduction |
|------------------|---------------------|
| Strong (parameterized query) | -40% |
| Medium (type coercion) | -30% |
| Weak (allowlist - may be bypassable) | -15% |
| Needs verification | 0% (manual review) |
