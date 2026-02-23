---
name: flask-patterns
description: Flask and Jinja2 security anti-patterns including SSTI, unsafe deserialization, debug mode exposure, and secret key issues.
---

# Flask/Jinja2 Security Patterns

## 1. Server-Side Template Injection (SSTI)

**Vulnerable Pattern:** User input passed to `render_template_string()` or string formatting before template rendering.

### Detection

```bash
# Direct SSTI sinks
grep -rn "render_template_string" --include="*.py"

# String formatting before render
grep -rn "render_template.*%" --include="*.py"
grep -rn "render_template.*\.format\(" --include="*.py"
grep -rn "render_template.*f\"" --include="*.py"

# Template string construction
grep -rn "\.replace\(.*\).*render_template" --include="*.py"
```

### Vulnerable Code Patterns

```python
# Direct SSTI
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string(f"Hello {name}!")  # SSTI!

# String replacement before render
@app.route('/report')
def report():
    template = open('report.html').read()
    template = template.replace("{{ user_input }}", request.args.get('input'))
    return render_template_string(template)  # SSTI via replacement!
```

### Filter Bypass Techniques

When input filtering is present, check for bypasses:

| Blocked | Bypass |
|---------|--------|
| `.` (dot) | `\|attr('method')` |
| `_` (underscore) | `\|attr('\x5f\x5f...')` or via request.args |
| `[]` brackets | `\|attr('__getitem__')` |
| `{{` `}}` | `{%print(...)%}` |

---

## 2. Debug Mode in Production

**Vulnerable Pattern:** Flask debug mode enabled exposes Werkzeug debugger console.

### Detection

```bash
# Check for debug=True
grep -rn "debug\s*=\s*True" --include="*.py"
grep -rn "FLASK_DEBUG\s*=\s*1" --include="*.py" --include="*.env"
grep -rn "app\.run.*debug" --include="*.py"
```

### Exploitation

1. Trigger an error (e.g., invalid route parameter)
2. Access `/console` if PIN not required
3. Execute Python code directly

---

## 3. Weak/Exposed Secret Key

**Vulnerable Pattern:** Hardcoded or predictable SECRET_KEY enables session forgery.

### Detection

```bash
# Hardcoded secrets
grep -rn "SECRET_KEY\s*=" --include="*.py"
grep -rn "secret_key\s*=" --include="*.py"

# Common weak values
grep -rniE "SECRET_KEY.*(dev|test|secret|changeme|password|123)" --include="*.py"
```

---

## 4. SQL Injection via Raw Queries

**Vulnerable Pattern:** String formatting in SQLAlchemy raw queries.

### Detection

```bash
# Raw SQL with formatting
grep -rn "execute\s*(" --include="*.py" | grep -E "\"|'.*%|\.format|f\""
grep -rn "text\s*(" --include="*.py" | grep -E "\"|'.*%|\.format|f\""
```

---

## 5. Unsafe Deserialization

**Vulnerable Pattern:** Loading serialized objects from user-controlled data can lead to code execution.

### Detection

```bash
# Find deserialization usage
grep -rn "loads\|load" --include="*.py" | grep -E "pickle|cPickle|marshal|yaml\.load"

# Common patterns with base64
grep -rn "b64decode" --include="*.py"
```

---

## 6. Path Traversal via send_file

**Vulnerable Pattern:** User input in file path without validation.

### Detection

```bash
grep -rn "send_file\|send_from_directory" --include="*.py"
grep -rn "open\s*(" --include="*.py" | grep -E "request\.(args|form|json)"
```

---

## 7. CORS Misconfiguration

**Vulnerable Pattern:** Overly permissive CORS allowing credential theft.

### Detection

```bash
grep -rn "CORS\|Access-Control" --include="*.py"
grep -rn "origins.*\*" --include="*.py"
```

---

## Remediation Patterns

### Secure Template Rendering

```python
# Always use render_template with Jinja2 autoescape
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template('greet.html', name=name)  # Safe - autoescape on
```

### Secure SQL

```python
# Use parameterized queries
from sqlalchemy import text
query = text("SELECT * FROM users WHERE id = :id")
db.execute(query, {"id": user_id})
```

### Secure File Handling

```python
from werkzeug.utils import secure_filename
import os

@app.route('/download')
def download():
    filename = secure_filename(request.args.get('file'))
    safe_path = os.path.join('/uploads', filename)
    if not safe_path.startswith('/uploads/'):
        abort(403)
    return send_file(safe_path)
```

---

## Integration with Chain Detection

Flask SSTI is often reached via:
- SSRF from frontend framework (Next.js, React SSR)
- Internal API calls from reverse proxy
- Microservice-to-microservice communication

When SSTI is found in internal service:
1. Check if any SSRF exists in externally-accessible services
2. Map service topology (docker-compose, supervisord)
3. Verify if SSRF can reach Flask endpoint with controllable input
