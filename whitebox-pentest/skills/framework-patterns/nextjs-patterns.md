---
name: nextjs-patterns
description: Next.js security anti-patterns including Server Actions, redirect SSRF, Route Handlers, and middleware bypass vulnerabilities.
---

# Next.js Security Patterns

## 1. Server Action Redirect SSRF

**Vulnerable Pattern:** Server Actions using `redirect()` can be exploited when the Host header is attacker-controlled, causing Next.js to make internal requests to attacker-specified URLs.

### Detection

```bash
# Find Server Actions with redirect
grep -rn '"use server"' --include="*.ts" --include="*.tsx" -A 20 | grep -E "redirect\("

# Find redirect imports
grep -rn "from ['\"]next/navigation['\"]" --include="*.ts" --include="*.tsx" | grep redirect
```

### Vulnerable Code Pattern

```typescript
"use server";
import { redirect } from "next/navigation";

export async function doRedirect() {
  redirect("/error");  // SSRF if Host header is attacker-controlled
}
```

### Why It's Dangerous

1. Attacker sends request with malicious Host header (e.g., `Host: attacker.com`)
2. Next.js internally fetches `http://attacker.com/error`
3. Attacker's server responds with 302 redirect to internal service
4. Next.js follows redirect to internal service (SSRF)

### Exploitation Requirements

- Server Action callable from external request
- No Host header validation
- Internal services accessible from Next.js server

---

## 2. Unprotected Route Handlers

**Vulnerable Pattern:** API Route Handlers (`app/api/**/route.ts`) without authentication checks.

### Detection

```bash
# Find all route handlers
find . -path "*/app/api/*" -name "route.ts" -o -name "route.js"

# Check for missing auth
grep -L "getSession\|getServerSession\|auth\|token\|verify" $(find . -path "*/app/api/*" -name "route.ts")
```

### Vulnerable Code Pattern

```typescript
// app/api/admin/users/route.ts
export async function GET() {
  const users = await db.query("SELECT * FROM users");
  return Response.json(users);  // No auth check!
}
```

---

## 3. Middleware Bypass

**Vulnerable Pattern:** Path-based middleware can be bypassed via path normalization differences.

### Detection

```bash
# Find middleware
find . -name "middleware.ts" -o -name "middleware.js"

# Check matcher patterns
grep -A 10 "matcher" middleware.ts
```

### Bypass Patterns

| Matcher | Bypass |
|---------|--------|
| `/admin/:path*` | `/Admin/secret` (case sensitivity) |
| `/api/:path*` | `/api/../admin` (path traversal) |
| `/(admin|api)/:path*` | `/api%2fadmin` (URL encoding) |

---

## 4. getServerSideProps Data Exposure

**Vulnerable Pattern:** Sensitive data returned from `getServerSideProps` is serialized to client-side `__NEXT_DATA__`.

### Detection

```bash
# Find getServerSideProps
grep -rn "getServerSideProps" --include="*.tsx" --include="*.ts"

# Check what's returned
grep -A 30 "getServerSideProps" pages/*.tsx | grep -E "return.*props"
```

### Vulnerable Code Pattern

```typescript
export async function getServerSideProps() {
  const user = await getUser();
  return {
    props: {
      user,  // Entire user object including sensitive fields!
    }
  };
}
```

**Check:** View page source for `<script id="__NEXT_DATA__">` to see exposed data.

---

## 5. Server Component Data Leakage

**Vulnerable Pattern:** React Server Components can leak sensitive data if not properly isolated.

### Detection

```bash
# Find server components (default in app/ directory)
find ./app -name "*.tsx" -exec grep -l "async function" {} \;

# Check for sensitive data fetching
grep -rn "password\|secret\|token\|apiKey" --include="*.tsx" app/
```

---

## 6. Unsafe Image/File Handling

**Vulnerable Pattern:** `next/image` with unvalidated external domains.

### Detection

```bash
# Check next.config.js for image domains
grep -A 10 "images:" next.config.js

# Find Image usage with external src
grep -rn "<Image.*src=" --include="*.tsx" | grep -v "^/\|^\.\/"
```

---

## Remediation Patterns

### Secure Redirect

```typescript
"use server";
import { redirect } from "next/navigation";
import { headers } from "next/headers";

export async function doRedirect() {
  const headersList = headers();
  const host = headersList.get("host");

  // Validate host
  if (host !== process.env.ALLOWED_HOST) {
    throw new Error("Invalid host");
  }

  redirect("/error");
}
```

### Protected Route Handler

```typescript
import { getServerSession } from "next-auth";

export async function GET() {
  const session = await getServerSession();
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  // ... protected logic
}
```

---

## Integration with Chain Detection

Next.js SSRF often chains with:
- Internal Flask/Django SSTI
- Internal Redis/Memcached command injection
- Cloud metadata endpoints (169.254.169.254)
- Internal admin panels

When SSRF is found, enumerate internal services via:
- `docker-compose.yml`
- `supervisord.conf`
- Kubernetes manifests
- Environment variables
