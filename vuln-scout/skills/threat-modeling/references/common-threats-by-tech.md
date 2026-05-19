# Common Threats by Technology Stack

Technology-specific threats and vulnerabilities. Use this reference when threat modeling applications built with specific languages and frameworks.

---

## Node.js / JavaScript

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Prototype pollution | Modifying `Object.prototype` via user input | Tampering | HIGH |
| ReDoS | Catastrophic backtracking in regex | DoS | HIGH |
| Type coercion | `==` vs `===` comparison bugs | Tampering | MEDIUM |
| Event loop blocking | Sync operations blocking all requests | DoS | MEDIUM |
| Async error handling | Error handling missed in async code | Info Disclosure | MEDIUM |
| DOM XSS via postMessage | Cross-origin message handlers without origin validation | Tampering | CRITICAL |

### Framework-Specific: Express

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Body parser misconfiguration | No size limits | DoS | MEDIUM |
| Missing security headers | No helmet.js | Info Disclosure | MEDIUM |
| Session fixation | express-session misconfiguration | Spoofing | HIGH |
| Static file traversal | Misconfigured express.static | Info Disclosure | HIGH |

### Framework-Specific: React/Angular/Vue

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| XSS via unsafe HTML rendering | User content rendered without escaping | Tampering | HIGH |
| Client-side routing bypass | Security in routes only | Elevation | MEDIUM |
| Sensitive data in state | Secrets in Redux/Vuex | Info Disclosure | HIGH |
| Source map exposure | .map files in production | Info Disclosure | MEDIUM |

### Code Patterns to Search

```bash
# Prototype pollution
grep -rniE "(\[.*\]|\.)__(proto|constructor)__" --include="*.js" --include="*.ts"
grep -rniE "merge|extend|assign.*req\." --include="*.js" --include="*.ts"

# ReDoS candidates
grep -rniE "/(.*\*.*\+|.*\+.*\*|(\.\*)?\{.*,.*\})/" --include="*.js" --include="*.ts"

# Type coercion
grep -rniE "==\s*['\"]|['\"].*==" --include="*.js" --include="*.ts"

# Dynamic code execution patterns
grep -rniE "(Function\(|setTimeout\(.*,|setInterval\(.*,).*req\." --include="*.js" --include="*.ts"

# postMessage handlers (check for missing origin validation)
grep -rniE "addEventListener\s*\(\s*['\"]message['\"]" --include="*.js" --include="*.ts"
grep -rniE "\.onmessage\s*=" --include="*.js" --include="*.ts"
grep -rniE "event\.data" --include="*.js" --include="*.ts"
```

---

## Python

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Unsafe deserialization | yaml.load on user data | Tampering/Elevation | CRITICAL |
| SSTI | User input in Jinja2/Mako templates | Tampering | CRITICAL |
| Command injection | subprocess with shell=True | Tampering | CRITICAL |
| Path traversal | os.path.join with user input | Info Disclosure | HIGH |
| XML External Entities | lxml/xml.etree without safe options | Info Disclosure | HIGH |

### Framework-Specific: Django

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| DEBUG mode in production | DEBUG=True in settings | Info Disclosure | HIGH |
| Secret key exposure | SECRET_KEY in code/repo | Spoofing | CRITICAL |
| Raw SQL queries | `raw()`, `extra()` with user input | Tampering | CRITICAL |
| CSRF bypass | @csrf_exempt decorator | Tampering | HIGH |
| Unsafe redirects | redirect(request.GET['next']) | Spoofing | HIGH |

### Framework-Specific: Flask

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Debug mode | app.run(debug=True) | Info Disclosure | CRITICAL |
| Weak secret key | Short/guessable secret_key | Spoofing | HIGH |
| SSTI in templates | render_template_string(user_input) | Tampering | CRITICAL |
| Missing CORS | No flask-cors configuration | Info Disclosure | MEDIUM |

### Code Patterns to Search

```bash
# Unsafe deserialization
grep -rniE "yaml\.load\(|marshal\.load" --include="*.py"

# SSTI
grep -rniE "render_template_string|Template\(.*\)\.render|jinja.*from_string" --include="*.py"

# Command injection (subprocess with shell)
grep -rniE "subprocess.*shell\s*=\s*True" --include="*.py"

# SQL injection
grep -rniE "\.raw\(|\.extra\(|execute\(.*%" --include="*.py"

# Debug mode
grep -rniE "DEBUG\s*=\s*True|\.run\(.*debug\s*=\s*True" --include="*.py"
```

---

## Java

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Deserialization gadgets | ObjectInputStream with untrusted data | Elevation | CRITICAL |
| XXE | DocumentBuilder without secure config | Info Disclosure | HIGH |
| SpEL injection | User input in Spring Expression Language | Tampering | CRITICAL |
| JNDI injection | lookup() with user-controlled string | Elevation | CRITICAL |
| Path traversal | new File(userInput) | Info Disclosure | HIGH |

### Framework-Specific: Spring

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Actuator exposure | /actuator endpoints public | Info Disclosure | HIGH |
| SpEL in @Value | User input reaches @Value | Tampering | CRITICAL |
| Mass assignment | @RequestBody to entity directly | Tampering | HIGH |
| CSRF disabled | csrf().disable() | Tampering | MEDIUM |
| H2 console exposed | h2-console enabled in production | Elevation | CRITICAL |

### Framework-Specific: Struts

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| OGNL injection | User input in OGNL expressions | Elevation | CRITICAL |
| Double evaluation | %{...} with user input | Elevation | CRITICAL |
| Action redirect | redirectAction: with user input | Spoofing | HIGH |

### Code Patterns to Search

```bash
# Deserialization
grep -rniE "ObjectInputStream|readObject\(\)|XMLDecoder|XStream" --include="*.java"

# XXE
grep -rniE "DocumentBuilder|SAXParser|XMLReader" --include="*.java"

# SpEL injection
grep -rniE "SpelExpressionParser|@Value.*#\{" --include="*.java"

# JNDI
grep -rniE "lookup\(.*\+|InitialContext.*lookup" --include="*.java"

# SQL injection
grep -rniE "createQuery\(.*\+|executeQuery\(.*\+" --include="*.java"
```

---

## PHP

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Type juggling | `==` comparison with unexpected types | Tampering | HIGH |
| Object injection | unserialize() with user data | Elevation | CRITICAL |
| Include vulnerabilities | include/require with user input | Elevation | CRITICAL |
| Dynamic code execution | create_function(), preg_replace /e | Elevation | CRITICAL |
| Command injection | passthru() with user input | Elevation | CRITICAL |

### Framework-Specific: Laravel

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Debug mode | APP_DEBUG=true in production | Info Disclosure | HIGH |
| Mass assignment | $fillable not defined | Tampering | HIGH |
| Route model binding | Implicit binding without auth | Info Disclosure | MEDIUM |
| Blade injection | {!! $userInput !!} | Tampering | HIGH |
| Storage link exposure | storage:link with sensitive files | Info Disclosure | MEDIUM |

### Framework-Specific: WordPress

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Plugin vulnerabilities | Outdated plugins | Various | HIGH |
| Admin exposure | /wp-admin accessible | Spoofing | MEDIUM |
| XMLRPC abuse | xmlrpc.php enabled | DoS | MEDIUM |
| File editor | Theme/plugin editor enabled | Elevation | HIGH |

### Code Patterns to Search

```bash
# Type juggling
grep -rniE "==.*\$_(GET|POST|REQUEST|COOKIE)" --include="*.php"

# Object injection
grep -rniE "unserialize\(.*\$" --include="*.php"

# File inclusion
grep -rniE "(include|require)(_once)?\s*\(?\s*\$" --include="*.php"

# Command injection
grep -rniE "(passthru|shell_exec|popen)\s*\(" --include="*.php"

# SQL injection
grep -rniE "\$wpdb->query\(.*\\\$|mysql_query\(.*\\\$" --include="*.php"
```

---

## Ruby

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Unsafe deserialization | Marshal.load, YAML.load | Elevation | CRITICAL |
| Command injection | backticks, %x{} with user input | Elevation | CRITICAL |
| Dynamic code execution | instance_eval with user input | Elevation | CRITICAL |
| ERB injection | User input in ERB templates | Tampering | HIGH |

### Framework-Specific: Rails

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Mass assignment | permit all or missing strong params | Tampering | HIGH |
| SQL injection | where with string interpolation | Tampering | CRITICAL |
| YAML deserialization | YAML.load on user input | Elevation | CRITICAL |
| Render injection | render inline: user_input | Tampering | HIGH |
| Secret key exposure | secret_key_base in repo | Spoofing | CRITICAL |
| Development mode | Rails.env.development? bypass | Various | HIGH |

### Code Patterns to Search

```bash
# Unsafe deserialization
grep -rniE "(Marshal|YAML)\.load" --include="*.rb"

# Command injection
grep -rniE "(%x\{|`)" --include="*.rb"

# SQL injection
grep -rniE "where\(.*#\{|find_by_sql.*#\{" --include="*.rb"

# Mass assignment
grep -rniE "params\.permit!|attr_accessible" --include="*.rb"

# Render injection
grep -rniE "render.*inline:" --include="*.rb"
```

---

## Go

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Command injection | os/exec with user input | Elevation | CRITICAL |
| Path traversal | filepath.Join doesn't sanitize .. | Info Disclosure | HIGH |
| Template injection | text/template with user input | Tampering | HIGH |
| SSRF | net/http with user-controlled URL | Tampering | HIGH |
| Race conditions | Shared state without mutex | Tampering | MEDIUM |

### Framework-Specific: Gin/Echo

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Binding vulnerabilities | ShouldBind without validation | Tampering | MEDIUM |
| Debug mode | gin.SetMode(gin.DebugMode) | Info Disclosure | MEDIUM |
| CORS misconfiguration | AllowAll CORS | Info Disclosure | MEDIUM |

### Code Patterns to Search

```bash
# Command injection
grep -rniE "exec\.Command\(.*\+" --include="*.go"

# Path traversal
grep -rniE "filepath\.(Join|Clean).*\+" --include="*.go"

# SQL injection
grep -rniE "db\.(Query|Exec)\(.*\+" --include="*.go"

# Template injection
grep -rniE "template\.New.*Parse\(.*\+" --include="*.go"

# SSRF
grep -rniE "http\.(Get|Post)\(.*\+" --include="*.go"
```

---

## .NET / C#

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Deserialization | BinaryFormatter, JsonSerializer | Elevation | CRITICAL |
| XXE | XmlDocument, XmlReader | Info Disclosure | HIGH |
| SQL injection | String concatenation in queries | Tampering | CRITICAL |
| Path traversal | Path.Combine doesn't validate | Info Disclosure | HIGH |

### Framework-Specific: ASP.NET Core

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Developer exception page | UseDeveloperExceptionPage() in prod | Info Disclosure | HIGH |
| Insecure cookie | CookieSecurePolicy.None | Spoofing | HIGH |
| Missing CORS | No CORS policy | Info Disclosure | MEDIUM |
| Over-posting | Model binding without [Bind] | Tampering | HIGH |

### Code Patterns to Search

```bash
# Deserialization
grep -rniE "BinaryFormatter|JsonSerializer\.Deserialize|XmlSerializer" --include="*.cs"

# SQL injection
grep -rniE "SqlCommand\(.*\+|ExecuteReader\(.*\+" --include="*.cs"

# XXE
grep -rniE "XmlDocument|XmlReader|XDocument\.Load" --include="*.cs"

# Path traversal
grep -rniE "Path\.Combine\(.*\+|File\.(Read|Write).*\+" --include="*.cs"
```

---

## Solidity / Smart Contracts

### Language-Specific Threats

| Threat | Description | STRIDE | Severity |
|--------|-------------|--------|----------|
| Reentrancy | External call before state update | Tampering | CRITICAL |
| Integer overflow/underflow | Arithmetic bugs (pre-0.8.0) | Tampering | CRITICAL |
| Access control | Missing/weak onlyOwner checks | Elevation | CRITICAL |
| Unchecked external calls | .call() without success check | Tampering | HIGH |
| Front-running | Transaction ordering exploitation | Tampering | HIGH |
| Flash loan attacks | Single-tx price/state manipulation | Tampering | CRITICAL |
| Oracle manipulation | Price feed tampering | Tampering | CRITICAL |
| Denial of Service | Gas griefing, unbounded loops | DoS | HIGH |
| Signature malleability | ECDSA signature issues | Spoofing | HIGH |
| Storage collision | Proxy upgrade storage conflicts | Tampering | CRITICAL |

### DeFi-Specific Threats

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Price oracle manipulation | Single source, no TWAP | Tampering | CRITICAL |
| Flash loan vulnerability | No same-block checks | Tampering | CRITICAL |
| Slippage attacks | No minAmountOut | Tampering | HIGH |
| Sandwich attacks | Public mempool transactions | Info Disclosure | HIGH |
| Governance attacks | Low quorum, no timelock | Elevation | HIGH |
| Token approval exploits | Unlimited approve() | Tampering | HIGH |

### Proxy/Upgradeable Patterns

| Threat | Indicator | STRIDE | Severity |
|--------|-----------|--------|----------|
| Uninitialized proxy | Missing initializer call | Elevation | CRITICAL |
| Storage collision | Different storage layouts | Tampering | CRITICAL |
| Selfdestruct in impl | delegatecall to destructible | DoS | CRITICAL |
| Function selector clash | Proxy/impl function overlap | Tampering | HIGH |
| Unauthorized upgrade | Missing access control on upgrade | Elevation | CRITICAL |

### Code Patterns to Search

```bash
# Reentrancy (external call before state update)
grep -rniE "\.call\{|\.transfer\(|\.send\(" --include="*.sol"
grep -rniE "\.call\(" --include="*.sol" -A 5 | grep -v "require"

# Access control issues
grep -rniE "function.*(external|public)" --include="*.sol" | grep -v "onlyOwner\|onlyRole\|require.*msg.sender"

# Unchecked arithmetic (pre-0.8)
grep -rniE "pragma solidity.*0\.[0-7]\." --include="*.sol"

# Dangerous functions
grep -rniE "(selfdestruct|delegatecall|tx\.origin)" --include="*.sol"

# Oracle usage
grep -rniE "(latestRoundData|getPrice|oracle)" --include="*.sol"

# Timestamp dependence
grep -rniE "block\.(timestamp|number)" --include="*.sol"

# External calls without checks
grep -rniE "\.call\(" --include="*.sol" | grep -v "(bool.*success|require)"

# Approve patterns
grep -rniE "approve\(.*type\(uint256\)\.max\|approve\(.*\-1\)" --include="*.sol"

# Missing zero-address checks
grep -rniE "function.*(address.*)" --include="*.sol" -A 3 | grep -v "require.*!= address\(0\)"
```

---

## Usage

1. Identify technology stack from `/whitebox-pentest:threats --quick`
2. Find corresponding section above
3. Search codebase using provided patterns
4. Prioritize by severity
5. Trace findings with `/whitebox-pentest:trace`
