---
name: server-actions
description: Security patterns for Next.js Server Actions including SSRF, authentication bypass, and injection vulnerabilities.
---

# Server Actions Security

Server Actions are server-side functions callable from client components. They introduce unique security considerations.

## What Are Server Actions?

```typescript
"use server";

export async function createUser(formData: FormData) {
  const name = formData.get("name");
  await db.user.create({ data: { name } });
}
```

## Attack Surface

### 1. SSRF via redirect()

**Pattern:** Host header manipulation causes internal SSRF.

```typescript
"use server";
import { redirect } from "next/navigation";

export async function handleError() {
  redirect("/error");  // Host header influences target URL
}
```

**Detection:**
```bash
grep -rn '"use server"' -A 30 --include="*.ts" --include="*.tsx" | grep "redirect("
```

### 2. Missing Authentication

**Pattern:** Server Action performs privileged operation without auth check.

**Detection:**
```bash
# Find Server Actions without session checks
for f in $(grep -rl '"use server"' --include="*.ts" --include="*.tsx"); do
  if ! grep -q "getServerSession\|auth()\|cookies()" "$f"; then
    echo "No auth check: $f"
  fi
done
```

### 3. Insecure Direct Object Reference (IDOR)

**Pattern:** User-supplied ID used without ownership verification.

**Detection:**
```bash
grep -rn '"use server"' -A 30 --include="*.ts" | grep -E "findUnique|findFirst|delete|update" | grep -v "userId\|ownerId\|createdBy"
```

### 4. SQL Injection

**Pattern:** User input interpolated into raw SQL.

**Detection:**
```bash
grep -rn '\$queryRaw\|\.execute\|sql\`' --include="*.ts" | grep -v ":param\|\${"
```

### 5. Path Traversal

**Pattern:** User input used in file path.

**Detection:**
```bash
grep -rn '"use server"' -A 30 --include="*.ts" | grep -E "readFile|writeFile|unlink|readdir"
```

### 6. Command Injection

**Pattern:** User input passed to shell command execution functions.

**Detection:**
```bash
# Find shell execution in Server Actions
grep -rn '"use server"' -A 30 --include="*.ts" | grep -E "child_process|spawn\(|execSync"
```

## Secure Patterns

### Authenticated Server Action

```typescript
"use server";
import { getServerSession } from "next-auth";

export async function deleteUser(userId: string) {
  const session = await getServerSession();
  if (!session) {
    throw new Error("Unauthorized");
  }

  // Check ownership
  const user = await db.user.findUnique({ where: { id: userId } });
  if (user.ownerId !== session.user.id) {
    throw new Error("Forbidden");
  }

  await db.user.delete({ where: { id: userId } });
}
```

### Validated Input

```typescript
"use server";
import { z } from "zod";

const schema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
});

export async function createUser(formData: FormData) {
  const data = schema.parse({
    name: formData.get("name"),
    email: formData.get("email"),
  });

  await db.user.create({ data });
}
```

### Safe File Operations

```typescript
"use server";
import path from "path";

const ALLOWED_DIR = "/app/configs";

export async function readConfig(filename: string) {
  const safeName = path.basename(filename);  // Strip path components
  const fullPath = path.join(ALLOWED_DIR, safeName);

  // Verify still within allowed directory
  if (!fullPath.startsWith(ALLOWED_DIR)) {
    throw new Error("Invalid path");
  }

  return await fs.readFile(fullPath, "utf-8");
}
```

## Checklist

- [ ] All Server Actions check authentication via `getServerSession()` or similar
- [ ] IDOR prevented by verifying resource ownership
- [ ] Input validated with schema (zod, yup)
- [ ] No raw SQL with user input
- [ ] File paths validated and constrained
- [ ] No shell commands with user input
- [ ] redirect() uses absolute URLs or validates Host
