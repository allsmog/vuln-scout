---
name: blade-patterns
description: Laravel Blade template engine security patterns including directive injection, @php abuse, and view composer exploitation.
---

# Laravel Blade Security Patterns

## 1. Blade Template Injection

**Vulnerable Pattern:** User input rendered without proper escaping or passed to dynamic blade compilation.

### Detection

```bash
# Unescaped output (triple braces or {!! !!})
grep -rn "{!!.*!!}" --include="*.blade.php"
grep -rn "@php" --include="*.blade.php"

# Dynamic view compilation
grep -rn "Blade::compileString\|view()->make.*\\\$" --include="*.php"

# Custom directive definitions
grep -rn "Blade::directive" --include="*.php"
```

### Vulnerable Code Patterns

```php
// Unescaped user output
{!! $userInput !!}  // Vulnerable to XSS/injection

// Dynamic compilation
$compiled = Blade::compileString($userTemplate);

// Unsafe view name from user input
return view($request->input('template'));
```

---

## 2. @php Directive Abuse

**Vulnerable Pattern:** @php directive allows arbitrary PHP code in templates.

### Detection

```bash
grep -rn "@php" --include="*.blade.php"
```

### Exploitation

If user input can reach blade compilation:

```blade
@php
system($_GET['cmd']);
@endphp
```

---

## 3. Custom Directive Injection

**Vulnerable Pattern:** Custom Blade directives with unsafe implementations.

### Detection

```bash
grep -rn "Blade::directive.*function.*\\\$" --include="*.php"
```

### Vulnerable Code

```php
// AppServiceProvider.php
Blade::directive('include_unsafe', function ($expression) {
    return "<?php include($expression); ?>";  // LFI!
});

// Template usage
@include_unsafe($userInput)
```

---

## 4. View Composer Injection

**Vulnerable Pattern:** View composers that pass unsanitized data to all views.

### Detection

```bash
grep -rn "View::composer\|view()->composer" --include="*.php"
```

---

## 5. Remediation

```blade
{{-- BEFORE (VULNERABLE) --}}
{!! $userInput !!}

{{-- AFTER (SECURE) - Use escaped output --}}
{{ $userInput }}

{{-- Or explicitly escape --}}
{!! e($userInput) !!}
```

```php
// Disable @php directive in production
// In AppServiceProvider boot():
Blade::withoutComponentTags();
```
