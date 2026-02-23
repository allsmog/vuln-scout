---
name: Data Flow Tracing
description: This skill should be used when the user asks to "trace data flow", "follow user input", "source to sink analysis", "track variable", "find input sources", "taint analysis", or needs to understand how user-controlled data flows through an application during whitebox pentesting.
version: 1.0.0
---

# Data Flow Tracing

## Purpose

Guide the process of tracing user-controlled input from entry points (sources) through the application to security-sensitive functions (sinks). This is essential for confirming vulnerability exploitability.

## When to Use

Activate this skill when:
- Confirming if identified sinks receive user input
- Mapping the path from source to sink
- Understanding data transformations and filters
- Determining if sanitization can be bypassed

## Core Concepts

### Sources (Input Entry Points)

**HTTP Sources**:
| Language | Common Sources |
|----------|----------------|
| PHP | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER` |
| Java | `request.getParameter()`, `request.getHeader()`, `@RequestParam` |
| Python | `request.args`, `request.form`, `request.data`, `request.json` |
| Node.js | `req.query`, `req.body`, `req.params`, `req.headers` |
| .NET | `Request.QueryString`, `Request.Form`, `Request["param"]` |

**Other Sources**:
- Database queries (stored user data)
- File contents (user-uploaded or modified)
- Environment variables
- External API responses

### Sinks (Dangerous Functions)

Refer to the **dangerous-functions** skill for comprehensive sink lists.

### Data Transformations

Track how data changes between source and sink:
- Encoding/Decoding (base64, URL, HTML)
- Concatenation with other strings
- Array/object property access
- Type conversions
- String manipulations

## Tracing Methodology

### Step 1: Identify the Sink
Start from the dangerous function identified during code review.

### Step 2: Find Direct Parameters
Identify what variables/parameters are passed to the sink.

```
Example: system($cmd);
Direct parameter: $cmd
```

### Step 3: Trace Backwards
Follow each parameter to its origin:

1. Check function parameters
2. Check variable assignments
3. Check conditional branches
4. Check loop iterations
5. Check included/required files

### Step 4: Identify Sources
Determine where user input enters:

```
$cmd = $_GET['command'];  // Direct source
$cmd = $row['command'];   // Database (check how it was stored)
$cmd = $config['cmd'];    // Config file (check if user-modifiable)
```

### Step 5: Map Transformations
Document all changes to the data:

```
Source: $_GET['input']
  -> urldecode()
  -> str_replace(['../', '..\\'], '', $input)
  -> escapeshellarg()
  -> Sink: exec()
```

### Step 6: Assess Exploitability
Consider:
- Are filters/sanitization bypassable?
- Is the full input controllable?
- Are there alternative paths?

## Tracing Techniques

### Static Analysis (Manual)

**Forward Tracing**: Start from source, follow to sinks
```
$input = $_GET['x'];
$processed = process($input);
dangerous_function($processed);
```

**Backward Tracing**: Start from sink, trace to source
```
dangerous_function($var);
  <- $var = transform($data);
  <- $data = $_POST['param'];
```

### Using IDE Features

- Find all references to variable
- Go to definition
- Find usages
- Call hierarchy

### Using Grep

```bash
# Find where variable is assigned
grep -rn "\$varname\s*=" --include="*.php"

# Find where variable is used
grep -rn "\$varname" --include="*.php"

# Find function calls
grep -rn "functionName\s*(" --include="*.php"
```

## Common Patterns

### Direct Flow
```
$input = $_GET['cmd'];
system($input);  // Vulnerable
```

### Database-Mediated Flow
```
// Store
$db->insert(['cmd' => $_POST['cmd']]);

// Later, retrieve and execute
$row = $db->query("SELECT cmd FROM jobs")->fetch();
system($row['cmd']);  // Vulnerable if original input wasn't sanitized
```

### Configuration Flow
```
// Config loaded from user-modifiable file
$config = parse_ini_file('/var/www/config.ini');
system($config['backup_cmd']);  // Vulnerable if config is modifiable
```

### Multi-File Flow
```
// file1.php
$_SESSION['cmd'] = $_GET['cmd'];

// file2.php
system($_SESSION['cmd']);  // Vulnerable
```

## Sanitization Analysis

### Identify Sanitization Functions
```
$input = htmlspecialchars($_GET['x']);  // XSS protection
$input = escapeshellarg($_GET['x']);    // Command injection protection
$input = intval($_GET['x']);            // Type casting
$input = preg_replace('/[^a-z]/', '', $_GET['x']);  // Whitelist
```

### Assess Bypass Potential

| Sanitization | Bypass Considerations |
|--------------|----------------------|
| Blacklist | Missing characters, encoding |
| Whitelist | Logic errors, regex flaws |
| Type casting | Depends on sink requirements |
| Encoding | Double encoding, context |
| Length limits | Truncation attacks |

### Common Bypass Techniques

- Case variations
- Encoding (URL, Unicode, HTML)
- Null bytes
- Double encoding
- Alternative representations

## Documentation Template

When tracing, document findings:

```markdown
## Finding: [Vulnerability Type]

### Sink
- File: path/to/file.php
- Line: 42
- Function: system($cmd)

### Source
- File: path/to/file.php  
- Line: 35
- Source: $_GET['command']

### Data Flow
1. $_GET['command'] received (line 35)
2. Passed to sanitize() function (line 36)
3. Concatenated with prefix (line 38)
4. Passed to system() (line 42)

### Sanitization
- sanitize() removes semicolons and pipes
- Bypass: Use newline (%0a) or $() syntax

### Exploitability
- Confirmed exploitable
- Payload: `valid_command%0awhoami`
```

## Integration with Other Skills

- Use **dangerous-functions** to identify sinks
- Use **vuln-patterns** for exploitation techniques
- Use **exploit-techniques** to develop PoC
