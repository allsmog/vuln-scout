---
name: nextjs-react
description: This skill should be used when the user asks about "Next.js security", "React security", "Server Components", "Server Actions", "Route Handlers", "RSC vulnerabilities", "SSR security", or needs comprehensive Next.js/React security analysis during whitebox pentesting.
---

# Next.js/React Security Analysis

Comprehensive security patterns for Next.js and React applications, covering both client-side and server-side attack surfaces.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Next.js Application                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Client-Side (Browser)          Server-Side (Node.js)       │
│  ┌──────────────────┐          ┌──────────────────────┐    │
│  │ React Components │          │ Server Components    │    │
│  │ Client Actions   │◄────────►│ Server Actions       │    │
│  │ useEffect/State  │          │ Route Handlers       │    │
│  └──────────────────┘          │ Middleware           │    │
│                                │ getServerSideProps   │    │
│                                └──────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Attack Surface Categories

### 1. Server Actions (`"use server"`)
- SSRF via redirect() with Host header manipulation
- Insecure direct object references
- Missing authentication/authorization
- SQL injection in database operations

### 2. Route Handlers (`app/api/**/route.ts`)
- Unauthenticated API endpoints
- Mass assignment vulnerabilities
- Rate limiting bypass
- CORS misconfiguration

### 3. Server Components
- Data exposure in serialized props
- Sensitive data in `__NEXT_DATA__`
- Server-side XSS in rendered content

### 4. Middleware
- Path-based bypass (normalization)
- Authentication bypass
- Header injection

### 5. Client Components
- XSS via unsanitized rendering
- Prototype pollution
- Open redirects

## Detection Workflow

### Step 1: Map the Application

```bash
# Find all Server Actions
grep -rn '"use server"' --include="*.ts" --include="*.tsx"

# Find all Route Handlers
find . -path "*/app/api/*" \( -name "route.ts" -o -name "route.js" \)

# Find middleware
find . -name "middleware.ts" -o -name "middleware.js"

# Find page components
find ./app -name "page.tsx" -o -name "page.js"
```

### Step 2: Identify Entry Points

```bash
# Server Actions called from forms
grep -rn "action=" --include="*.tsx" | grep -v node_modules

# Server Actions called programmatically
grep -rn "startTransition\|useTransition" --include="*.tsx"

# Route Handler methods
grep -rn "export.*function\s\+\(GET\|POST\|PUT\|DELETE\|PATCH\)" --include="route.ts"
```

### Step 3: Check Authentication

```bash
# Find auth patterns
grep -rn "getServerSession\|getSession\|auth\(\)" --include="*.ts" --include="*.tsx"

# Find unprotected handlers (no auth import)
for f in $(find . -path "*/app/api/*" -name "route.ts"); do
  if ! grep -q "getServerSession\|auth\|verify" "$f"; then
    echo "Potentially unprotected: $f"
  fi
done
```

### Step 4: Trace Data Flow

```bash
# Find request data access
grep -rn "request\.json\|request\.formData\|request\.text" --include="*.ts"

# Find database operations
grep -rn "prisma\.\|db\.\|sql\`\|query\(" --include="*.ts"

# Find external API calls
grep -rn "fetch\(\|axios\.\|got\(" --include="*.ts"
```

## Key Patterns

### SSRF via Server Action Redirect

See `framework-patterns/nextjs-patterns.md` for detailed pattern.

### Unprotected Route Handler

```typescript
// VULNERABLE: No auth check
export async function DELETE(req: Request) {
  const { id } = await req.json();
  await db.user.delete({ where: { id } });  // Anyone can delete!
  return Response.json({ success: true });
}
```

### Server Component Data Leak

```typescript
// VULNERABLE: Sensitive data exposed
async function UserProfile({ userId }: { userId: string }) {
  const user = await db.user.findUnique({ where: { id: userId } });
  // Full user object including password hash goes to client!
  return <ClientProfile user={user} />;
}
```

### Middleware Bypass

```typescript
// VULNERABLE: Case-sensitive matching
export const config = {
  matcher: '/admin/:path*'  // /Admin/secret bypasses!
}
```

## Integration with Chain Detection

Next.js vulnerabilities often enable chains:

| Next.js Vulnerability | Chains To |
|----------------------|-----------|
| Server Action SSRF | Internal Flask/Django SSTI |
| Server Action SSRF | Cloud metadata (169.254.169.254) |
| Route Handler SQLi | Data exfiltration, auth bypass |
| Middleware Bypass | Admin panel access |
| Data Leak | Credential theft, session hijacking |

## Remediation Checklist

- [ ] All Server Actions validate authentication
- [ ] All Route Handlers check authorization
- [ ] Middleware uses case-insensitive matching
- [ ] Server Components filter sensitive fields before passing to client
- [ ] redirect() calls validate Host header or use absolute URLs
- [ ] Database queries use parameterized statements
- [ ] File operations validate paths
