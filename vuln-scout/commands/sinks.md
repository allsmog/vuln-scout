---
name: sinks
description: Search for dangerous functions (sinks) and auto-discover output patterns
argument-hint: "[language] [--discover] [--scope name]"
allowed-tools:
  - Glob
  - Grep
  - Read
  - Bash
  - TodoWrite
---

# Sink Search Command

Search the codebase for dangerous functions that could lead to vulnerabilities. Optionally auto-discover logging patterns and sensitive data sources.

## Flags

| Flag | Effect |
|------|--------|
| `--discover` | Auto-discover logging patterns and sensitive sources first |
| `--scope name` | Use pre-created scope file |

## Execution

### Step 1: Determine Language

If language argument provided:
- Use that language's sink patterns

If no language argument:
- Detect from file extensions using Glob
- Search for: *.php, *.java, *.py, *.js, *.ts, *.cs, *.go, *.rb

### Step 1.5: Auto-Discovery Mode (if --discover)

When `--discover` flag is provided, first identify codebase-specific patterns:

**Discover Logging Patterns:**
```bash
# Go
grep -rhoE "\w+\.(Error|Info|Debug|Warn|Fatal|Log)\w*\s*\(" --include="*.go" | sort | uniq -c | sort -rn | head -10

# Python
grep -rhoE "(logging|logger|log)\.(error|info|debug|warning)\s*\(" --include="*.py" | sort | uniq -c | sort -rn | head -10

# JavaScript/TypeScript
grep -rhoE "(console|logger|log)\.(error|info|debug|warn|log)\s*\(" --include="*.js" --include="*.ts" | sort | uniq -c | sort -rn | head -10
```

**Discover Sensitive Sources:**
```bash
# Variable names with sensitive patterns
grep -rniE "\b\w*(secret|password|apikey|token|credential|private.?key)\w*\b" --include="*.go" --include="*.py" --include="*.java" --include="*.js" | grep -v "_test" | head -20
```

**Output discovered patterns** before running standard sink search.

### Step 2: Search for Sinks by Category

For the target language, search these categories in order:

**Command Execution** (Critical):
- PHP: exec, system, passthru, shell_exec, popen, proc_open
- Java: Runtime.exec, ProcessBuilder
- Python: os.system, subprocess, os.popen
- Node.js: child_process
- .NET: Process.Start
- Go: exec.Command
- Ruby: system, exec, backticks

**Code Execution** (Critical):
- PHP: eval, assert, create_function, preg_replace with /e
- Java: ScriptEngine.eval, OGNL, MVEL, SpEL
- Python: eval, exec, compile
- Node.js: eval, Function constructor, vm module
- .NET: CSharpCodeProvider, Assembly.Load
- Ruby: eval, instance_eval, class_eval

**Deserialization** (Critical):
- PHP: unserialize
- Java: readObject, XMLDecoder, XStream
- Python: pickle.loads, yaml.load
- Node.js: node-serialize
- .NET: BinaryFormatter, Deserialize

**SQL** (High):
- String concatenation in queries
- Raw query methods without parameterization

**File Operations** (High):
- Include/require with variables
- File read/write with user input

### Step 3: Present Results

Format output as:

```
## Sink Search Results

### Command Execution (X findings)
- path/to/file.php:42 - exec($cmd)
- path/to/file.php:87 - system($command)

### Code Execution (X findings)
- path/to/file.php:123 - eval($code)

### Deserialization (X findings)
- path/to/file.php:56 - unserialize($data)

### SQL (X findings)
- path/to/file.php:234 - query("SELECT...{$id}")

### File Operations (X findings)
- path/to/file.php:345 - include($page)

---
Total: X potential sinks identified
Recommendation: Trace data flow for each to determine exploitability
```

## Notes

- Show context around each finding (-B 2 -A 2)
- Sort by severity (Command > Code > Deserialization > SQL > File)
- Highlight findings with direct user input ($_GET, $_POST, request.*)
- Suggest next step: trace data flow or run full audit
