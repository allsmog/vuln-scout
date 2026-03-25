---
name: framework-patterns
description: This skill should be used when the user asks about "framework vulnerabilities", "Next.js security", "Flask security", "Django security", "Rails security", "Spring security", "GraphQL security", "Server Actions", "render_template_string", "SSTI patterns", "redirect SSRF", "mass assignment", "actuator exposure", "SpEL injection", "introspection", or needs to identify framework-specific vulnerability patterns during whitebox pentesting.
---

# Framework Security Patterns

Framework-specific vulnerability patterns that arise from how modern web frameworks handle requests, responses, and data flow. These patterns are more durable than version-specific CVEs.

## Why Framework Patterns Matter

1. **Frameworks have implicit behaviors** - redirect(), Server Actions, template rendering have side effects
2. **Trust assumptions differ** - Internal vs external, server vs client boundaries
3. **Chains emerge** - Framework A's feature enables exploitation of Framework B's weakness

## Pattern Categories

### 1. Request Handling Patterns
- Server Actions (Next.js) - Host header influence on internal requests
- Route Handlers - Missing authentication on API routes
- Middleware bypass - Path normalization differences

### 2. Template/Rendering Patterns
- SSTI (Flask, Jinja2, Django, Twig) - User input in template strings
- XSS via unsafe HTML insertion (React)
- Prototype pollution in SSR

### 3. Redirect Patterns
- Open redirect via unvalidated URLs
- SSRF via server-side redirect (Next.js, PHP)
- Header injection through redirect URLs

### 4. Deserialization Patterns
- Pickle (Python)
- Marshal (Ruby)
- PHP unserialize
- Java ObjectInputStream

## Detection Workflow

1. **Identify frameworks** in use (package.json, requirements.txt, Gemfile)
2. **Search for pattern signatures** specific to each framework
3. **Map data flow** from user input to dangerous framework APIs
4. **Check for sanitization** or validation before reaching sink

## Framework-Specific Skills

- `nextjs-patterns.md` - Next.js Server Actions, redirect, Route Handlers
- `flask-patterns.md` - Flask/Jinja2 SSTI, unsafe deserialization
- `references/django-patterns.md` - Django ORM bypass, template injection, CSRF bypass, settings exposure, mass assignment, open redirect
- `references/rails-patterns.md` - Rails mass assignment, SQL injection, SSTI, command injection, insecure deserialization, unscoped finds, arbitrary file render
- `references/spring-security-patterns.md` - Spring SpEL injection, method security misconfiguration, CORS, CSRF, actuator exposure, mass binding, insecure JWT
- `references/graphql-patterns.md` - GraphQL introspection, query depth/complexity abuse, batching attacks, authorization bypass, error disclosure

## Integration with Audit Workflow

During `/full-audit`:
1. Step 1 identifies frameworks during language detection
2. Step 2 threat model considers framework-specific trust boundaries
3. Step 4 deep dive uses framework-specific sink patterns

## Example: DoxPit Pattern

```
Frontend: Next.js with Server Actions
Backend: Flask with Jinja2 templates

Chain:
1. Server Action uses redirect() → Host header controls internal fetch URL
2. SSRF reaches Flask backend on internal port
3. Flask uses render_template_string() with user input
4. SSTI → RCE via Jinja2 payload
```

This pattern detection focuses on the **code behavior**, not version numbers.
