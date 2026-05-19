# JavaScript/Node.js Dangerous Functions

## Code Execution

| Function | Risk | Notes |
|----------|------|-------|
| `eval()` | Critical | Evaluates string as code |
| `Function()` constructor | Critical | Creates function from string |
| `setTimeout(string)` | High | If first arg is string |
| `setInterval(string)` | High | If first arg is string |
| `new Function()` | Critical | Dynamic function creation |

**Grep Pattern:**
```
grep -rniE "(eval\(|new Function|setTimeout\(['\"]|setInterval\(['\"])" --include="*.js" --include="*.ts"
```

## Command Execution (Node.js)

| Function | Risk | Notes |
|----------|------|-------|
| `child_process.exec()` | Critical | Shell command execution |
| `child_process.execSync()` | Critical | Synchronous shell |
| `child_process.spawn()` | High | Process spawning |
| `child_process.execFile()` | Medium | File execution |
| `child_process.fork()` | Medium | Node.js process |

**Grep Pattern:**
```
grep -rniE "(child_process|\.exec\(|\.execSync\(|\.spawn\()" --include="*.js" --include="*.ts"
```

## VM Module (Node.js)

| Function | Risk | Notes |
|----------|------|-------|
| `vm.runInContext()` | Critical | Code in context |
| `vm.runInNewContext()` | Critical | Code in new context |
| `vm.runInThisContext()` | Critical | Code in current context |
| `vm.compileFunction()` | High | Compile function |

**Grep Pattern:**
```
grep -rniE "vm\.(runIn|compile)" --include="*.js" --include="*.ts"
```

## Deserialization

| Library/Function | Risk | Notes |
|------------------|------|-------|
| `node-serialize` | Critical | Known RCE gadget |
| `serialize-javascript` | High | Check configuration |
| `js-yaml.load()` | High | Without safe option |

**Grep Pattern:**
```
grep -rniE "(node-serialize|serialize-javascript|js-yaml)" --include="*.js" --include="*.ts"
```

## File Operations (Node.js)

| Function | Risk | Notes |
|----------|------|-------|
| `fs.readFile()` | Medium | File read |
| `fs.readFileSync()` | Medium | Sync file read |
| `fs.writeFile()` | High | File write |
| `fs.writeFileSync()` | High | Sync file write |
| `fs.unlink()` | High | File deletion |
| `require()` with variable | High | Dynamic require |

**Grep Pattern:**
```
grep -rniE "(fs\.(read|write|unlink)|require\([^'\"])" --include="*.js" --include="*.ts"
```

## SQL Injection

| Pattern | Risk | Notes |
|---------|------|-------|
| Template literals in queries | Critical | String interpolation |
| String concat in queries | Critical | Direct concatenation |
| `sequelize.query()` raw | High | Raw SQL queries |
| `knex.raw()` | High | Raw SQL |

**Grep Pattern:**
```
grep -rniE "(\.query\(|\.raw\().*\\\$\{|SELECT.*\+" --include="*.js" --include="*.ts"
```

## SSRF/HTTP Requests (Node.js)

| Module/Function | Risk | Notes |
|-----------------|------|-------|
| `http.request()` | High | If URL user-controlled |
| `https.request()` | High | If URL user-controlled |
| `axios()` | High | If URL user-controlled |
| `fetch()` | High | If URL user-controlled |
| `request()` | High | Deprecated npm package |

**Grep Pattern:**
```
grep -rniE "(http\.request|https\.request|axios|fetch\()" --include="*.js" --include="*.ts"
```

## DOM-Based XSS (Browser)

| Property/Method | Risk | Notes |
|-----------------|------|-------|
| `innerHTML` | High | HTML injection |
| `outerHTML` | High | HTML injection |
| `document.write()` | High | Document write |
| `document.writeln()` | High | Document write |
| `.insertAdjacentHTML()` | High | HTML insertion |

**Grep Pattern:**
```
grep -rniE "(innerHTML|outerHTML|document\.write|insertAdjacentHTML)" --include="*.js" --include="*.ts" --include="*.html"
```

## Cross-Origin Messaging (postMessage) - DOM XSS Sources

**CRITICAL**: postMessage handlers are often overlooked but are a major source of DOM XSS vulnerabilities. Data from `event.data` in message handlers is attacker-controlled from any origin unless `event.origin` is validated.

### Event Handler Sources

| Handler Pattern | Risk | Notes |
|-----------------|------|-------|
| `addEventListener("message", ...)` | Critical | Cross-origin message handler |
| `window.onmessage` | Critical | Direct message handler |
| `self.onmessage` | High | Worker message handler |
| `port.onmessage` | High | MessagePort handler |
| `BroadcastChannel.onmessage` | High | Broadcast channel |

**Grep Pattern (Find message handlers):**
```
grep -rniE "(addEventListener\s*\(\s*['\"]message['\"]|\.onmessage\s*=)" --include="*.js" --include="*.ts" --include="*.html"
```

### Missing Origin Validation (CRITICAL)

A message handler WITHOUT origin validation is vulnerable to any website sending malicious messages.

**Grep Pattern (Find handlers WITHOUT origin check):**
```bash
# Find message handlers, then manually verify origin validation
grep -rniE "addEventListener\s*\(\s*['\"]message['\"]" --include="*.js" --include="*.ts" -A 10 | grep -v "origin"

# Find handlers that use event.data with innerHTML sinks
grep -rniE "event\.data.*innerHTML|innerHTML.*event\.data" --include="*.js" --include="*.ts"

# Find handlers assigning event.data to variables then used unsafely
grep -rniE "=\s*event\.data" --include="*.js" --include="*.ts"
```

### postMessage to DOM Sink Patterns

| Pattern | Risk | Attack Vector |
|---------|------|---------------|
| `event.data` → `innerHTML` | Critical | XSS via cross-origin message |
| `event.data` → DOM write methods | Critical | XSS via cross-origin message |
| `event.data` → `location.href` | High | Open redirect via message |
| `event.data` → HTTP client calls | High | SSRF via cross-origin message |

**Detection Strategy:**
1. Find all message event handlers
2. Check if `event.origin` is validated
3. Trace `event.data` to dangerous sinks
4. Verify the origin check is against a specific trusted domain

### iframe + postMessage Attack Chain

When an attacker can control an iframe's content (via SSRF), they can:
1. Load victim page in iframe
2. Send malicious postMessage to the iframe
3. If victim has vulnerable message handler → XSS execution

**Grep Pattern (Find pages missing frame protection):**
```
grep -rniE "X-Frame-Options|frame-ancestors" --include="*.js" --include="*.ts" --include="*.py"
```

## URL Handling

| Property/Method | Risk | Notes |
|-----------------|------|-------|
| `location.href` | Medium | Open redirect |
| `location.replace()` | Medium | Open redirect |
| `window.open()` | Medium | Open redirect |

**Grep Pattern:**
```
grep -rniE "(location\.(href|replace)|window\.open)" --include="*.js" --include="*.ts"
```

## Template Injection

| Framework | Risk | Notes |
|-----------|------|-------|
| `ejs.render()` | High | If template user-controlled |
| `pug.render()` | High | If template user-controlled |
| `handlebars.compile()` | Medium | Check for prototype pollution |
| `mustache.render()` | Low | Logic-less templates |

**Grep Pattern:**
```
grep -rniE "(ejs\.render|pug\.render|handlebars\.compile)" --include="*.js" --include="*.ts"
```

## Prototype Pollution

| Pattern | Risk | Notes |
|---------|------|-------|
| `Object.assign()` with user input | High | Prototype pollution |
| `_.merge()` lodash | High | Deep merge vulnerability |
| `$.extend()` jQuery | High | Deep extend |
| `JSON.parse()` + merge | Medium | If merged into object |

**Grep Pattern:**
```
grep -rniE "(Object\.assign|_\.merge|\$\.extend|deepmerge)" --include="*.js" --include="*.ts"
```

## Path Traversal (Node.js)

| Pattern | Risk | Notes |
|---------|------|-------|
| `path.join()` with user input | High | If not validated |
| `path.resolve()` with user input | High | If not validated |
| `res.sendFile()` | High | Express file serving |
| `express.static()` | Medium | Static file serving |
