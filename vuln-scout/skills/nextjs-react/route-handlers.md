---
name: route-handlers
description: Security patterns for Next.js Route Handlers (app/api/**/route.ts) including authentication, authorization, and injection vulnerabilities.
---

# Route Handlers Security

Route Handlers are the API layer in Next.js App Router. They handle HTTP requests and are a primary attack surface.

## Route Handler Basics

```typescript
// app/api/users/route.ts
export async function GET(request: Request) {
  const users = await db.user.findMany();
  return Response.json(users);
}

export async function POST(request: Request) {
  const data = await request.json();
  const user = await db.user.create({ data });
  return Response.json(user, { status: 201 });
}
```

## Attack Surface

### 1. Missing Authentication

**Pattern:** Endpoint accessible without login.

```typescript
// VULNERABLE
export async function GET() {
  return Response.json(await db.user.findMany());  // Anyone can list users!
}
```

**Detection:**
```bash
# Find handlers without auth imports
for f in $(find . -path "*/app/api/*" -name "route.ts"); do
  if ! grep -qE "getServerSession|auth\(\)|verify|jwt" "$f"; then
    echo "No auth: $f"
  fi
done
```

### 2. Missing Authorization

**Pattern:** Auth exists but no role/permission check.

```typescript
// VULNERABLE: Authenticated but not authorized
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  // Any logged-in user can delete any resource!
  await db.resource.delete({ where: { id: params.id } });
  return Response.json({ success: true });
}
```

**Detection:**
```bash
grep -rn "DELETE\|PUT\|PATCH" --include="route.ts" -A 20 | grep -v "ownerId\|role\|permission\|isAdmin"
```

### 3. Mass Assignment

**Pattern:** Request body directly used for database update.

```typescript
// VULNERABLE
export async function PUT(req: Request) {
  const data = await req.json();
  // Attacker can set isAdmin: true!
  await db.user.update({ where: { id: data.id }, data });
  return Response.json({ success: true });
}
```

**Detection:**
```bash
grep -rn "req\.json\(\)" --include="route.ts" -A 10 | grep -E "update|create" | grep "data\)"
```

### 4. SQL Injection

**Pattern:** User input in raw queries.

```typescript
// VULNERABLE
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const name = searchParams.get("name");
  const users = await db.$queryRaw`SELECT * FROM users WHERE name = '${name}'`;  // SQLi!
  return Response.json(users);
}
```

### 5. SSRF

**Pattern:** User-controlled URL in fetch.

```typescript
// VULNERABLE
export async function POST(req: Request) {
  const { url } = await req.json();
  const response = await fetch(url);  // SSRF!
  return Response.json(await response.json());
}
```

**Detection:**
```bash
grep -rn "fetch\(" --include="route.ts" -B 5 | grep -E "req\.json|searchParams"
```

### 6. Path Traversal

**Pattern:** Dynamic route params used in file operations.

```typescript
// app/api/files/[...path]/route.ts
// VULNERABLE
export async function GET(req: Request, { params }: { params: { path: string[] } }) {
  const filePath = params.path.join("/");
  const content = await fs.readFile(`./uploads/${filePath}`);  // Path traversal!
  return new Response(content);
}
```

### 7. CORS Misconfiguration

**Pattern:** Permissive CORS headers.

```typescript
// VULNERABLE
export async function GET() {
  return new Response(JSON.stringify(sensitiveData), {
    headers: {
      "Access-Control-Allow-Origin": "*",  // Too permissive!
      "Access-Control-Allow-Credentials": "true",
    },
  });
}
```

## Secure Patterns

### Protected Handler

```typescript
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";

export async function GET() {
  const session = await getServerSession(authOptions);

  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (session.user.role !== "admin") {
    return Response.json({ error: "Forbidden" }, { status: 403 });
  }

  return Response.json(await db.user.findMany());
}
```

### Safe Update (Allowlist)

```typescript
import { z } from "zod";

const updateSchema = z.object({
  name: z.string().optional(),
  email: z.string().email().optional(),
  // isAdmin intentionally NOT included
});

export async function PUT(req: Request) {
  const session = await getServerSession();
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const data = updateSchema.parse(body);  // Only allowed fields

  await db.user.update({
    where: { id: session.user.id },  // Can only update own profile
    data,
  });

  return Response.json({ success: true });
}
```

### Safe File Access

```typescript
import path from "path";

const UPLOADS_DIR = "/app/uploads";

export async function GET(req: Request, { params }: { params: { path: string[] } }) {
  const requestedPath = params.path.join("/");
  const safePath = path.normalize(requestedPath).replace(/^(\.\.[\/\\])+/, "");
  const fullPath = path.join(UPLOADS_DIR, safePath);

  if (!fullPath.startsWith(UPLOADS_DIR)) {
    return Response.json({ error: "Invalid path" }, { status: 400 });
  }

  try {
    const content = await fs.readFile(fullPath);
    return new Response(content);
  } catch {
    return Response.json({ error: "Not found" }, { status: 404 });
  }
}
```

## Checklist

- [ ] All handlers check authentication
- [ ] Destructive operations check authorization (ownership/role)
- [ ] Request body validated against schema (allowlist fields)
- [ ] No raw SQL with user input
- [ ] No fetch() with user-controlled URLs
- [ ] File paths validated and constrained
- [ ] CORS headers appropriate for endpoint sensitivity
- [ ] Rate limiting on sensitive endpoints
