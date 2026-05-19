# Python Dangerous Functions

## Command Execution

| Function/Module | Risk | Notes |
|-----------------|------|-------|
| `os.system()` | Critical | Executes shell command |
| `os.popen()` | Critical | Opens pipe to command |
| `subprocess.call()` | Critical | Runs command |
| `subprocess.run()` | Critical | Runs command (Python 3.5+) |
| `subprocess.Popen()` | Critical | Full process control |
| `commands.getoutput()` | Critical | Deprecated, Python 2 |
| `commands.getstatusoutput()` | Critical | Deprecated, Python 2 |

**Grep Pattern:**
```
grep -rniE "(os\.system|os\.popen|subprocess\.(call|run|Popen)|commands\.)" --include="*.py"
```

## Code Execution

| Function | Risk | Notes |
|----------|------|-------|
| `eval()` | Critical | Evaluates expression |
| `exec()` | Critical | Executes statements |
| `compile()` | High | Compiles code object |
| `execfile()` | Critical | Python 2 only |
| `__import__()` | High | Dynamic import |
| `importlib.import_module()` | High | Dynamic import |

**Grep Pattern:**
```
grep -rniE "(eval|exec|compile|execfile|__import__|importlib)" --include="*.py"
```

## Deserialization

| Function/Module | Risk | Notes |
|-----------------|------|-------|
| `pickle.loads()` | Critical | Arbitrary code execution |
| `pickle.load()` | Critical | From file |
| `cPickle.loads()` | Critical | C implementation |
| `yaml.load()` | Critical | Without Loader argument |
| `yaml.unsafe_load()` | Critical | Explicitly unsafe |
| `marshal.loads()` | High | Code object deserialization |
| `shelve.open()` | High | Uses pickle internally |

**Grep Pattern:**
```
grep -rniE "(pickle\.(load|loads)|yaml\.(load|unsafe_load)|marshal\.loads|shelve\.open)" --include="*.py"
```

**Safe alternatives:**
- `yaml.safe_load()` instead of `yaml.load()`
- `json.loads()` instead of `pickle.loads()` where possible

## File Operations

| Function | Risk | Notes |
|----------|------|-------|
| `open()` | Medium | File read/write |
| `os.path.join()` | Low | Check for traversal |
| `shutil.copy()` | High | File copy |
| `shutil.move()` | High | File move |
| `os.remove()` | High | File deletion |
| `os.rename()` | High | File rename/move |

**Grep Pattern:**
```
grep -rniE "(open\(|shutil\.(copy|move)|os\.(remove|rename))" --include="*.py"
```

## SQL Injection

| Pattern | Risk | Notes |
|---------|------|-------|
| String formatting in queries | Critical | `%s` or `.format()` |
| f-strings in queries | Critical | f"SELECT...{var}" |
| `cursor.execute()` with concat | Critical | Check for parameterization |
| Raw SQL in ORMs | High | `raw()`, `extra()` methods |

**Grep Pattern:**
```
grep -rniE "(execute|executemany|raw|extra).*[\"'].*SELECT|INSERT|UPDATE|DELETE" --include="*.py"
```

## SSRF Vectors

| Function/Module | Risk | Notes |
|-----------------|------|-------|
| `requests.get()` | High | If URL user-controlled |
| `requests.post()` | High | If URL user-controlled |
| `urllib.request.urlopen()` | High | Standard library |
| `urllib2.urlopen()` | High | Python 2 |
| `httplib.HTTPConnection` | High | Low-level HTTP |

**Grep Pattern:**
```
grep -rniE "(requests\.(get|post)|urlopen|HTTPConnection)" --include="*.py"
```

## Template Injection (SSTI)

| Framework | Risk | Notes |
|-----------|------|-------|
| `Jinja2 Template` | High | If user controls template |
| `render_template_string()` | Critical | Flask - renders string as template |
| `mako.template.Template` | High | Mako templates |
| `django.template.Template` | Medium | Django templates (less dangerous) |

**Grep Pattern:**
```
grep -rniE "(render_template_string|Template\(|from_string)" --include="*.py"
```

## XML Processing (XXE)

| Function/Module | Risk | Notes |
|-----------------|------|-------|
| `xml.etree.ElementTree` | Medium | Default safe in Python 3.8+ |
| `lxml.etree` | High | Check for resolve_entities |
| `xml.sax` | High | SAX parser |
| `xml.dom.minidom` | Medium | DOM parser |

**Grep Pattern:**
```
grep -rniE "(ElementTree|lxml\.etree|xml\.sax|minidom)" --include="*.py"
```

## Path Traversal

| Pattern | Risk | Notes |
|---------|------|-------|
| `os.path.join(base, user_input)` | High | If not validated |
| `open(user_input)` | High | Direct file access |
| `send_file(user_input)` | High | Flask file serving |

## Input Functions

| Function | Risk | Notes |
|----------|------|-------|
| `input()` | Low | User input (safe in Python 3) |
| `raw_input()` | Low | Python 2 only |
| `input()` Python 2 | Critical | Evaluates input as code |
