---
name: Workspace Discovery
description: This skill should be used when the user asks to "detect workspaces", "find packages", "list monorepo packages", "workspace structure", "monorepo analysis", or needs to identify workspace/package boundaries in a codebase for focused security analysis.
version: 1.0.0
---

# Workspace Discovery Reference

## Purpose

Provide comprehensive knowledge of monorepo and workspace patterns across package managers and build tools. Enables focused security analysis by identifying logical boundaries within large codebases.

## When to Use

Activate this skill during:
- Initial reconnaissance of a large codebase
- Planning security audit scope for monorepos
- Identifying package boundaries for targeted analysis
- Understanding dependency relationships between packages

## Core Concepts

### Monorepo Types

| Type | Characteristics | Common Tools |
|------|-----------------|--------------|
| **Package-based** | Multiple npm/pip/cargo packages | npm workspaces, yarn, pnpm |
| **Application-based** | Multiple apps sharing code | Turborepo, Nx, Lerna |
| **Module-based** | Language modules in subdirs | Go modules, Maven modules |
| **Hybrid** | Mix of above | Custom setups |

### Workspace Benefits for Security

1. **Scoping**: Analyze one package at a time
2. **Prioritization**: Focus on high-risk packages first
3. **Propagation**: Track vulnerabilities across shared code
4. **Reporting**: Generate per-package security reports

## Detection Patterns

### JavaScript/TypeScript Ecosystems

#### npm/yarn Workspaces
```json
// package.json
{
  "workspaces": [
    "packages/*",
    "apps/*"
  ]
}
```

**Detection command**:
```bash
grep -l '"workspaces"' package.json && cat package.json | grep -A 10 '"workspaces"'
```

#### pnpm Workspaces
```yaml
# pnpm-workspace.yaml
packages:
  - 'packages/*'
  - 'apps/*'
  - '!**/test/**'
```

**Detection command**:
```bash
cat pnpm-workspace.yaml 2>/dev/null
```

#### Turborepo
```json
// turbo.json
{
  "pipeline": {
    "build": { "dependsOn": ["^build"] },
    "test": { "dependsOn": ["build"] }
  }
}
```

**Detection command**:
```bash
ls turbo.json 2>/dev/null && echo "Turborepo detected - uses package.json workspaces"
```

#### Nx
```json
// nx.json
{
  "npmScope": "myorg",
  "tasksRunnerOptions": { ... }
}
```

**Detection command**:
```bash
ls nx.json 2>/dev/null && cat nx.json | head -20
```

#### Lerna (Legacy)
```json
// lerna.json
{
  "packages": ["packages/*"],
  "version": "independent"
}
```

**Detection command**:
```bash
cat lerna.json 2>/dev/null | grep -A 5 '"packages"'
```

### Go Ecosystem

#### Go Workspaces (1.18+)
```go
// go.work
go 1.21

use (
    ./cmd/api
    ./cmd/worker
    ./pkg/shared
)
```

**Detection command**:
```bash
cat go.work 2>/dev/null
```

#### Multiple go.mod (Pre-workspaces)
```bash
find . -name "go.mod" -maxdepth 4 | head -20
```

### Java/JVM Ecosystem

#### Maven Multi-Module
```xml
<!-- pom.xml (parent) -->
<modules>
    <module>api</module>
    <module>worker</module>
    <module>shared</module>
</modules>
```

**Detection command**:
```bash
grep -A 10 '<modules>' pom.xml 2>/dev/null
```

#### Gradle Multi-Project
```groovy
// settings.gradle
rootProject.name = 'myproject'
include ':api'
include ':worker'
include ':shared'
```

**Detection command**:
```bash
grep "include" settings.gradle 2>/dev/null
grep "include" settings.gradle.kts 2>/dev/null
```

### Rust Ecosystem

#### Cargo Workspaces
```toml
# Cargo.toml
[workspace]
members = [
    "crates/api",
    "crates/worker",
    "crates/shared",
]
```

**Detection command**:
```bash
grep -A 10 '\[workspace\]' Cargo.toml 2>/dev/null
```

### Python Ecosystem

#### Poetry Monorepo
```toml
# pyproject.toml
[tool.poetry]
packages = [
    { include = "api", from = "packages" },
    { include = "worker", from = "packages" },
]
```

**Detection command**:
```bash
grep -A 5 'packages' pyproject.toml 2>/dev/null
```

#### Multiple setup.py/pyproject.toml
```bash
find . -name "setup.py" -o -name "pyproject.toml" | grep -v node_modules | head -20
```

### PHP Ecosystem

#### Composer Path Repositories
```json
// composer.json
{
  "repositories": [
    { "type": "path", "url": "./packages/*" }
  ]
}
```

**Detection command**:
```bash
grep -A 5 '"repositories"' composer.json 2>/dev/null | grep path
```

## Workspace Analysis Workflow

### Step 1: Detect Workspace Type

Run detection commands in order:
```bash
# JavaScript
ls package.json pnpm-workspace.yaml turbo.json nx.json lerna.json 2>/dev/null

# Go
ls go.work 2>/dev/null || find . -name "go.mod" -maxdepth 3 2>/dev/null | wc -l

# Java
ls pom.xml settings.gradle settings.gradle.kts 2>/dev/null

# Rust
grep '\[workspace\]' Cargo.toml 2>/dev/null

# Python
find . -name "pyproject.toml" -maxdepth 3 2>/dev/null | wc -l
```

### Step 2: Extract Workspace Paths

Parse the detected configuration to list actual workspace directories.

### Step 3: Analyze Each Workspace

For each workspace, collect:
- **Name**: Package/project name
- **Path**: Relative directory path
- **Language**: Primary programming language
- **Files**: Count of source files
- **Lines**: Estimated lines of code
- **Dependencies**: Internal workspace dependencies

### Step 4: Risk Assessment

Score each workspace:

| Factor | Points | Criteria |
|--------|--------|----------|
| **External-facing** | +3 | API, web server, CLI |
| **Auth/authz logic** | +3 | Login, permissions, sessions |
| **Database access** | +2 | ORM, raw queries |
| **File operations** | +2 | Upload, download, file processing |
| **Background jobs** | +1 | Workers, queues, cron |
| **Shared library** | +1 | Used by multiple packages |
| **UI only** | -1 | Frontend, no backend logic |

### Step 5: Prioritized Scan Order

Order workspaces by:
1. Risk score (highest first)
2. Dependency order (dependencies before dependents)
3. Size (smaller packages analyzed faster)

## Integration with Tools

### Repomix Integration
```bash
# Scope specific workspace
npx repomix packages/api --output .claude/scope-api.md

# Scope multiple workspaces
npx repomix packages/api packages/auth --output .claude/scope-critical.md
```

### Codemap Integration
```bash
# View workspace dependencies
codemap --deps packages/api

# Full dependency graph
codemap --deps --json > deps.json
```

### Security Scanning
```bash
# Scan specific workspace
/whitebox-pentest:scan packages/api

# Audit specific workspace
/whitebox-pentest:full-audit packages/auth
```

## Reference Files

See language-specific patterns:
- `references/javascript-workspaces.md` - npm, yarn, pnpm, turborepo, nx, lerna
- `references/jvm-workspaces.md` - Maven, Gradle, Kotlin
- `references/systems-workspaces.md` - Go, Rust, C/C++

## Notes

- Workspace detection is heuristic - some custom setups may not be detected
- Nested workspaces (workspaces within workspaces) require recursive analysis
- Some tools (Nx, Bazel) have complex project detection requiring tool-specific commands
- Always verify detected workspaces against actual directory structure
