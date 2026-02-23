# PHP Dangerous Functions

## Command Execution

Functions that execute system commands:

| Function | Risk | Notes |
|----------|------|-------|
| `exec()` | Critical | Returns last line of output |
| `system()` | Critical | Outputs directly, returns last line |
| `passthru()` | Critical | Outputs raw binary data |
| `shell_exec()` | Critical | Returns complete output |
| `popen()` | Critical | Opens process file pointer |
| `proc_open()` | Critical | Full process control |
| `pcntl_exec()` | Critical | Replaces current process |
| Backticks | Critical | Equivalent to shell_exec |

**Grep Pattern:**
```
grep -rniE "(exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(" --include="*.php"
```

## Code Execution

| Function | Risk | Notes |
|----------|------|-------|
| `eval()` | Critical | Executes string as PHP |
| `assert()` | Critical | Can execute code (PHP < 8.0) |
| `create_function()` | Critical | Deprecated, creates anonymous function |
| `call_user_func()` | High | Calls function by name |
| `call_user_func_array()` | High | Calls function with array args |
| `preg_replace()` | Critical | With /e modifier (deprecated) |

**Grep Pattern:**
```
grep -rniE "(eval|assert|create_function|call_user_func)\s*\(" --include="*.php"
```

## File Inclusion

| Function | Risk | Notes |
|----------|------|-------|
| `include` | Critical | LFI/RFI if path controlled |
| `include_once` | Critical | Same as include |
| `require` | Critical | Fatal on failure |
| `require_once` | Critical | Same as require |

**Grep Pattern:**
```
grep -rniE "(include|include_once|require|require_once)\s*[\(\$]" --include="*.php"
```

## File Operations

| Function | Risk | Notes |
|----------|------|-------|
| `file_get_contents()` | High | Reads entire file, supports URLs |
| `file_put_contents()` | Critical | Writes to file |
| `fopen()` | High | Opens file handle |
| `fwrite()` | High | Writes to file handle |
| `readfile()` | Medium | Outputs file contents |
| `move_uploaded_file()` | High | File upload handling |
| `unlink()` | High | Deletes files |

## Deserialization

| Function | Risk | Notes |
|----------|------|-------|
| `unserialize()` | Critical | PHP object injection |
| `maybe_unserialize()` | Critical | WordPress wrapper |

**Grep Pattern:**
```
grep -rniE "(unserialize|maybe_unserialize)\s*\(" --include="*.php"
```

## Database (SQL Injection)

| Pattern | Risk | Notes |
|---------|------|-------|
| String concatenation in queries | Critical | Direct SQLi |
| `mysql_query()` | High | Deprecated, often vulnerable |
| `mysqli_query()` | Medium | Check for parameterization |
| `->query()` | Medium | Check for prepared statements |

## SSRF Vectors

| Function | Risk | Notes |
|----------|------|-------|
| `curl_exec()` | High | If URL is user-controlled |
| `file_get_contents()` | High | Supports http:// wrapper |
| `SoapClient` | High | SSRF via WSDL |

## XML Processing (XXE)

| Function | Risk | Notes |
|----------|------|-------|
| `simplexml_load_string()` | High | If external entities enabled |
| `DOMDocument::loadXML()` | High | Check for LIBXML_NOENT |
