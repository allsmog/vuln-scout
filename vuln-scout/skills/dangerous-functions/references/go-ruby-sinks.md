# Go and Ruby Dangerous Functions

---

# Go Dangerous Functions

## Command Execution

| Function/Package | Risk | Notes |
|------------------|------|-------|
| `exec.Command()` | Critical | Execute command |
| `exec.CommandContext()` | Critical | With context |
| `os/exec` package | Critical | Command execution |
| `syscall.Exec()` | Critical | Low-level exec |

**Grep Pattern:**
```
grep -rniE "(exec\.Command|syscall\.Exec)" --include="*.go"
```

## File Operations

| Function/Package | Risk | Notes |
|------------------|------|-------|
| `os.Open()` | Medium | File open |
| `os.Create()` | High | File create |
| `os.OpenFile()` | High | File open with flags |
| `ioutil.ReadFile()` | Medium | Read entire file |
| `ioutil.WriteFile()` | High | Write entire file |
| `os.Remove()` | High | Delete file |
| `os.Rename()` | High | Move/rename file |
| `filepath.Join()` | Medium | Check traversal |

**Grep Pattern:**
```
grep -rniE "(os\.(Open|Create|OpenFile|Remove)|ioutil\.(Read|Write)File)" --include="*.go"
```

## SQL Injection

| Pattern | Risk | Notes |
|---------|------|-------|
| String formatting in queries | Critical | fmt.Sprintf in SQL |
| `db.Query()` with concat | Critical | Direct concatenation |
| `db.Exec()` with concat | Critical | Direct concatenation |
| `database/sql` without params | High | Check parameterization |

**Grep Pattern:**
```
grep -rniE "(db\.(Query|Exec)|Sprintf.*SELECT|Sprintf.*INSERT)" --include="*.go"
```

## SSRF/HTTP

| Function/Package | Risk | Notes |
|------------------|------|-------|
| `http.Get()` | High | If URL user-controlled |
| `http.Post()` | High | If URL user-controlled |
| `http.NewRequest()` | High | If URL user-controlled |
| `net/http` client | High | HTTP client requests |

**Grep Pattern:**
```
grep -rniE "(http\.(Get|Post|NewRequest))" --include="*.go"
```

## Template Injection

| Package | Risk | Notes |
|---------|------|-------|
| `text/template` | High | No auto-escaping |
| `html/template` | Low | Auto-escapes HTML |
| `template.HTML()` | High | Bypasses escaping |

**Grep Pattern:**
```
grep -rniE "(text/template|template\.HTML)" --include="*.go"
```

## Deserialization

| Function/Package | Risk | Notes |
|------------------|------|-------|
| `encoding/gob` | Medium | Go-specific format |
| `json.Unmarshal()` | Low | Generally safe |
| `yaml.Unmarshal()` | Medium | YAML parsing |
| `xml.Unmarshal()` | Medium | XML parsing |

**Grep Pattern:**
```
grep -rniE "(gob\.(Decode|NewDecoder)|Unmarshal)" --include="*.go"
```

## Unsafe Package

| Function | Risk | Notes |
|----------|------|-------|
| `unsafe.Pointer` | High | Memory manipulation |
| `reflect` package | Medium | Runtime reflection |

**Grep Pattern:**
```
grep -rniE "unsafe\." --include="*.go"
```

## Credential/Secret Logging (CWE-532)

| Pattern | Risk | Notes |
|---------|------|-------|
| Log calls with credential vars | High | Secret exposure in logs |
| SDK session creation errors | High | May contain credentials |
| `%v`/`%+v` with config structs | High | Dumps all fields including secrets |
| Error wrapping with secrets | Medium | Secret propagation up call stack |
| Credential file read errors | Medium | May expose paths or partial data |

**Grep Patterns:**

```bash
# Find credential-related variables in log calls
grep -rniE "(log|print|error|warn|info|debug|fatal)\w*\([^)]*\b(secret|password|key|token|cred|apikey|session)\w*" --include="*.go"

# Find struct dumps that may contain secrets
grep -rniE "(Error|Info|Debug|Warn|Print)(f)?\([^)]*%[+#]?v.*(config|option|session|setting|cred)" --include="*.go"

# SDK session/credential error logging (AWS, GCP, Azure)
grep -rniE "(session|credentials?|NewSession|CredentialsFromJSON).*err" --include="*.go" | grep -iE "log\.|fmt\.(Print|Error)"

# Credential file operations with error logging
grep -rniE "(ReadFile|Open).*cred.*log\.(Error|Warn|Info)" --include="*.go"

# Error messages mentioning credentials
grep -rniE "log\.\w+\(.*[Uu]nable.*[Cc]redential" --include="*.go"
```

**Common Vulnerable Patterns:**

```go
// Pattern 1: SDK session error exposes config
session, err := session.NewSessionWithOptions(opts)  // opts has SecretKey
if err != nil {
    log.Errorf("Failed: %v", err)  // VULNERABLE: err may contain credentials
}

// Pattern 2: Credential file read error
credsJSON, err := ioutil.ReadFile(credsPath)
if err != nil {
    log.Errorf("Unable to read credentials: %v", err)  // VULNERABLE: path exposure
}

// Pattern 3: Config struct dump
log.Debugf("Using config: %+v", config)  // VULNERABLE: dumps SecretKey field
```

---

# Ruby Dangerous Functions

## Command Execution

| Method | Risk | Notes |
|--------|------|-------|
| `system()` | Critical | Shell command |
| `exec()` | Critical | Replace process |
| Backticks | Critical | Capture output |
| `%x{}` | Critical | Command substitution |
| `spawn()` | Critical | Spawn process |
| `IO.popen()` | Critical | Pipe to command |
| `Open3.capture3()` | Critical | Capture stdout/stderr |
| `Kernel.open()` with pipe | Critical | If starts with \| |

**Grep Pattern:**
```
grep -rniE "(system\(|exec\(|\`|%x\{|spawn\(|IO\.popen|Open3|Kernel\.open)" --include="*.rb"
```

## Code Execution

| Method | Risk | Notes |
|--------|------|-------|
| `eval()` | Critical | Evaluate string as code |
| `instance_eval()` | Critical | Evaluate in context |
| `class_eval()` | Critical | Class context |
| `module_eval()` | Critical | Module context |
| `send()` | High | Dynamic method call |
| `public_send()` | High | Public method only |
| `__send__()` | High | Alias for send |
| `constantize` (Rails) | High | String to constant |

**Grep Pattern:**
```
grep -rniE "(eval\(|instance_eval|class_eval|module_eval|\.send\(|constantize)" --include="*.rb"
```

## Deserialization

| Method/Class | Risk | Notes |
|--------------|------|-------|
| `Marshal.load()` | Critical | Ruby object serialization |
| `Marshal.restore()` | Critical | Alias for load |
| `YAML.load()` | Critical | Use safe_load instead |
| `Psych.load()` | Critical | YAML parser |

**Grep Pattern:**
```
grep -rniE "(Marshal\.(load|restore)|YAML\.load|Psych\.load)" --include="*.rb"
```

## File Operations

| Method | Risk | Notes |
|--------|------|-------|
| `File.open()` | Medium | File access |
| `File.read()` | Medium | Read file |
| `File.write()` | High | Write file |
| `File.delete()` | High | Delete file |
| `FileUtils` module | High | File operations |
| `Kernel.open()` | High | Can execute commands |

**Grep Pattern:**
```
grep -rniE "(File\.(open|read|write|delete)|FileUtils|Kernel\.open)" --include="*.rb"
```

## SQL Injection (Rails)

| Pattern | Risk | Notes |
|---------|------|-------|
| String interpolation | Critical | "...#{var}..." |
| `.where()` with string | High | Use hash instead |
| `.find_by_sql()` | High | Raw SQL |
| `.execute()` | High | Raw SQL |
| `.order()` with string | High | Can be exploited |

**Grep Pattern:**
```
grep -rniE "(\.where\(['\"]|find_by_sql|\.execute|\.order\(['\"])" --include="*.rb"
```

## SSRF/HTTP

| Library/Method | Risk | Notes |
|----------------|------|-------|
| `Net::HTTP` | High | If URL user-controlled |
| `open-uri` | High | URL fetching |
| `RestClient` | High | HTTP client |
| `HTTParty` | High | HTTP client |
| `Faraday` | High | HTTP client |

**Grep Pattern:**
```
grep -rniE "(Net::HTTP|open-uri|RestClient|HTTParty|Faraday)" --include="*.rb"
```

## Template Injection (ERB)

| Pattern | Risk | Notes |
|---------|------|-------|
| `ERB.new()` with user input | Critical | ERB template injection |
| `render inline:` | High | Rails inline render |

**Grep Pattern:**
```
grep -rniE "(ERB\.new|render.*inline)" --include="*.rb"
```

## Mass Assignment (Rails)

| Pattern | Risk | Notes |
|---------|------|-------|
| `params.permit!` | High | Permits all params |
| Missing strong params | High | Old Rails apps |

## Path Traversal

| Pattern | Risk | Notes |
|---------|------|-------|
| `File.join()` with user input | High | If not validated |
| `send_file` with user input | High | File download |
| `Rails.root.join()` | Medium | Check validation |
