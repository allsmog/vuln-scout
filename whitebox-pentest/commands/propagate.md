---
name: propagate
description: Pattern propagation - find all instances of a vulnerability pattern throughout the codebase
argument-hint: "<pattern-description> OR <file:line>"
allowed-tools:
  - Glob
  - Grep
  - Read
  - TodoWrite
---

# Pattern Propagation

When you find one vulnerability, search for the same pattern everywhere else. Developers often make the same mistake repeatedly.

## Philosophy

> "If you find one bug, look for the same bug everywhere else." - Common Bug Bounty Wisdom

Why pattern propagation works:
1. Developers copy/paste code
2. Codebases have consistent (bad) patterns
3. Same developer makes same mistakes
4. Frameworks encourage certain anti-patterns
5. One finding often multiplies into many

---

## Usage

### Option 1: Describe the Pattern

```
/whitebox-pentest:propagate "string concatenation in SQL queries"
```

### Option 2: Reference a Known Vulnerability

```
/whitebox-pentest:propagate src/api/users.py:45
```

The command will analyze the code at that location and extract the generalizable pattern.

---

## Phase 1: Pattern Extraction

### If file:line provided

1. Read the specified file and line
2. Analyze the vulnerable code
3. Identify the anti-pattern
4. Extract searchable characteristics

Example analysis:
```python
# Given: src/api/users.py:45
# Code: query = f"SELECT * FROM users WHERE id = {user_id}"

# Extracted pattern:
# - f-string or format() with SQL keywords
# - Variable interpolation in query string
# - Missing parameterization
```

### If description provided

1. Parse the vulnerability description
2. Map to known vulnerability patterns
3. Generate search patterns

Example mapping:
```
Description: "string concatenation in SQL queries"

Patterns:
- f"SELECT.*{
- "SELECT.*" +
- "SELECT.*%s" %
- "SELECT.*".format(
- query.*=.*+.*user
```

---

## Phase 2: Generate Search Patterns

### SQL Injection Patterns

```bash
# f-strings with SQL
grep -rniE 'f"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\{' --include="*.py"

# String concatenation with SQL
grep -rniE '"(SELECT|INSERT|UPDATE|DELETE).*"\s*\+' --include="*.py" --include="*.java" --include="*.js"

# Format strings with SQL
grep -rniE '(SELECT|INSERT|UPDATE|DELETE).*%s.*%' --include="*.py"
grep -rniE '\.format\(.*\).*(SELECT|INSERT|UPDATE|DELETE)' --include="*.py"
```

### Command Injection Patterns

```bash
# Shell commands with user input
grep -rniE '(os\.system|subprocess\.|exec\(|shell_exec|system\().*\+' --include="*.py" --include="*.php"

# Backticks or command substitution
grep -rniE '`.*\$|`.*\+' --include="*.php" --include="*.rb"
```

### XSS Patterns

```bash
# Unescaped output
grep -rniE 'innerHTML\s*=.*\+|document\.write\(' --include="*.js" --include="*.ts"

# Template without escaping
grep -rniE '\{\{.*\|safe\}\}|\{!!.*!!\}' --include="*.html" --include="*.blade.php"
```

### Path Traversal Patterns

```bash
# File operations with user input
grep -rniE '(open|read|write|include|require)\s*\(.*\+' --include="*.py" --include="*.php"

# Path joining with user input
grep -rniE 'os\.path\.join.*request|path\.join.*req\.' --include="*.py" --include="*.js"
```

### IDOR Patterns

```bash
# Direct object reference without ownership check
grep -rniE '\.(get|find|findById)\s*\(\s*\w+_id\s*\)' --include="*.py" --include="*.js" --include="*.java"

# Missing filter by user
grep -rniE 'query\.(get|filter_by)\s*\([^)]*id[^)]*\)' --include="*.py" -A 2 | grep -v "user_id"
```

---

## Phase 3: Codebase Search

### Step 3.1: Execute Search Patterns

Run generated grep patterns across the codebase:
- Include all relevant file types
- Exclude test files (optional, configurable)
- Exclude vendor/node_modules directories

### Step 3.2: Filter Results

Remove false positives:
- Parameterized queries (safe)
- Escaped output (safe)
- Test fixtures
- Comments and documentation

### Step 3.3: Group by Location

Organize findings:
- By file
- By function/class
- By developer (git blame)

---

## Phase 4: Impact Assessment

### Step 4.1: Analyze Each Finding

For each match:
1. Read surrounding context
2. Trace input source
3. Check for sanitization
4. Assess exploitability

### Step 4.2: Categorize Findings

| Category | Criteria |
|----------|----------|
| Confirmed | Same pattern, exploitable |
| Likely | Same pattern, needs verification |
| Possible | Similar pattern, unclear |
| False Positive | Pattern matched but safe |

### Step 4.3: Prioritize

Rank by:
1. Input proximity (direct user input = highest)
2. Authentication requirement
3. Impact severity
4. Ease of exploitation

---

## Output Format

```markdown
# Pattern Propagation Results

## Original Finding

**Location**: src/api/users.py:45
**Pattern**: SQL injection via f-string interpolation
**Code**:
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

## Pattern Description

**Anti-Pattern**: String interpolation in SQL queries
**Search Patterns Used**:
- `f"(SELECT|INSERT|UPDATE|DELETE).*\{`
- `"SELECT.*" + `

## Propagation Results

### Confirmed Instances (Same Pattern)

#### 1. src/api/products.py:78
```python
query = f"SELECT * FROM products WHERE category = {category}"
```
- **Input Source**: request.args['category']
- **Impact**: SQLi in product listing
- **Status**: CONFIRMED

#### 2. src/api/orders.py:123
```python
query = f"UPDATE orders SET status = {status} WHERE id = {order_id}"
```
- **Input Source**: request.json['status']
- **Impact**: SQLi in order update
- **Status**: CONFIRMED

### Likely Instances (Similar Pattern)

#### 3. src/admin/reports.py:45
```python
query = "SELECT * FROM reports WHERE date = '%s'" % date_str
```
- **Input Source**: admin form input
- **Impact**: SQLi (admin only)
- **Status**: LIKELY - needs auth to exploit

### False Positives (Safe)

#### src/utils/db.py:34
```python
# Uses parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```
- **Status**: FALSE POSITIVE - parameterized

## Summary

| Status | Count |
|--------|-------|
| Confirmed | 2 |
| Likely | 1 |
| False Positive | 1 |

## Recommended Actions

1. Fix all CONFIRMED instances immediately
2. Verify LIKELY instances require authentication
3. Consider codebase-wide migration to ORM or parameterized queries
4. Add linting rule to catch this pattern in CI/CD

## Related Patterns to Search

Based on this finding, also check:
- `/whitebox-pentest:propagate "format string in SQL"`
- `/whitebox-pentest:propagate "concatenation in database query"`
```

---

## Common Pattern Templates

### Template: SQL Injection
```
Pattern: String interpolation in SQL
Files: *.py, *.php, *.java, *.js
Regex: (SELECT|INSERT|UPDATE|DELETE).*(\$|{|\+|%s|concat)
Exclude: *test*, *mock*
```

### Template: Command Injection
```
Pattern: User input in system command
Files: *.py, *.php, *.rb, *.js
Regex: (system|exec|popen|shell_exec).*(\+|\$|{)
Exclude: *test*
```

### Template: Path Traversal
```
Pattern: User input in file path
Files: *.py, *.php, *.java, *.js
Regex: (open|read|include|require).*\+.*request
Exclude: *test*, static/*
```

### Template: Missing Auth Check
```
Pattern: Endpoint without authentication decorator
Files: *.py
Regex: @(app|router)\.(get|post|put|delete)
Compare: Against @(login_required|authenticated)
```

---

## Notes

- One finding can become 5-10 with propagation
- Same developer often makes same mistake throughout
- Pattern search is faster than full code review
- False positives are expected - verification is needed
- Consider adding found patterns to CI/CD linting
- Share findings with development team for training
