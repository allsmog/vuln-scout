# JavaScript Workspace Patterns

## npm/yarn Workspaces

### Detection
```bash
# Check if package.json has workspaces
grep '"workspaces"' package.json
```

### Configuration
```json
{
  "name": "my-monorepo",
  "private": true,
  "workspaces": [
    "packages/*",
    "apps/*"
  ]
}
```

### List Packages
```bash
# npm 7+
npm query .workspace | jq -r '.[].name'

# yarn
yarn workspaces list --json

# Manual
ls -d packages/*/ apps/*/
```

---

## pnpm Workspaces

### Detection
```bash
ls pnpm-workspace.yaml
```

### Configuration
```yaml
packages:
  - 'packages/*'
  - 'apps/*'
  - '!**/test/**'
```

### List Packages
```bash
pnpm list -r --depth -1 --json | jq '.[].name'
```

---

## Turborepo

### Detection
```bash
ls turbo.json
```

### Configuration
```json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**"]
    },
    "test": {
      "dependsOn": ["build"]
    }
  }
}
```

**Note**: Turborepo uses package.json workspaces for package detection.

### Task Graph
```bash
turbo run build --dry-run --graph
```

---

## Nx

### Detection
```bash
ls nx.json project.json
```

### Configuration (nx.json)
```json
{
  "npmScope": "myorg",
  "affected": {
    "defaultBase": "main"
  },
  "tasksRunnerOptions": {
    "default": {
      "runner": "nx/tasks-runners/default",
      "options": {
        "cacheableOperations": ["build", "test", "lint"]
      }
    }
  }
}
```

### List Projects
```bash
nx show projects
nx graph --file=deps.json
```

### Affected Analysis
```bash
# Show affected projects since main
nx affected:apps --base=main
nx affected:libs --base=main
```

---

## Lerna (Legacy)

### Detection
```bash
ls lerna.json
```

### Configuration
```json
{
  "packages": [
    "packages/*"
  ],
  "version": "independent",
  "npmClient": "yarn",
  "useWorkspaces": true
}
```

### List Packages
```bash
lerna list --json
lerna list --graph
```

---

## Security Considerations

### High-Risk Package Patterns

| Name Pattern | Risk | Reason |
|--------------|------|--------|
| `*-api`, `*-server` | HIGH | External-facing |
| `*-auth`, `*-login` | HIGH | Authentication |
| `*-gateway` | HIGH | API gateway, routing |
| `*-worker`, `*-queue` | MEDIUM | Background processing |
| `*-db`, `*-models` | MEDIUM | Database access |
| `*-shared`, `*-common` | MEDIUM | Vulnerability propagation |
| `*-ui`, `*-web`, `*-app` | LOW | Client-side only |
| `*-config`, `*-utils` | LOW | Utilities |

### Grep Patterns for Workspace Sinks
```bash
# Find which packages have dangerous patterns
for pkg in packages/*/; do
  name=$(basename "$pkg")
  count=$(grep -rniE "(exec|eval|spawn|query)" "$pkg" --include="*.ts" --include="*.js" 2>/dev/null | wc -l)
  if [ "$count" -gt 0 ]; then
    echo "$name: $count potential sinks"
  fi
done
```
