---
name: trace
description: Trace data flow from sources to a specific sink with explicit evidence requirements
argument-hint: "<function_or_file:line> [--language js|ts|py|go|java] [--scope name]"
allowed-tools:
  - Glob
  - Grep
  - Read
---

# Data Flow Trace Command

Trace attacker-controlled input to a sink and document whether it is a verified vulnerability, a hotspot that still needs proof, or a false positive.

## Required Evidence

Every trace must include these four evidence buckets:

1. **Source evidence**
   - Exact code line where attacker-controlled data enters.
   - Why that source is user-controlled or externally influenced.

2. **Hop chain**
   - Every variable handoff or function call from source to sink.
   - File:line references for each step.

3. **Control evidence**
   - Validation, encoding, normalization, or allowlist logic seen on the path.
   - Whether the control applies to all paths or only some branches.

4. **Exploitability evidence**
   - Why the sink remains reachable with controlled input.
   - Constraints that would block or narrow exploitation.

## Workflow

### Step 1: Parse the target

Accept:
- `function_name`
- `file:line`
- `$variable`

### Step 2: Resolve the sink

Read the target location and capture:
- Sink function or statement
- Parameters reaching the sink
- Immediate code context

### Step 3: Build the trace

For each sink argument:
- Find its last assignment
- Follow callers or field propagation across files
- Stop only when you reach a trusted source, an untrusted source, or a dead end

### Step 4: Classify the result

- **Finding**: attacker-controlled input reaches the sink and controls remain ineffective or absent
- **Hotspot**: risky sink/pivot is present, but attacker control or exploit path is still unproven
- **False positive**: a control clearly makes the path safe for this vulnerability class

## Language-specific tracing templates

### JavaScript / TypeScript
- Sources: `req.body`, `req.params`, `req.query`, `headers`, `cookies`, browser `postMessage`
- Controls: parameterized SQL, `DOMPurify`, `path.resolve` plus prefix check, URL allowlists
- Notes: treat `redirect()` and framework handlers as hotspots until attacker control is shown

### Python
- Sources: `request.args`, `request.form`, `request.json`, Flask/Django route params
- Controls: parameter binding, Jinja auto-escaping, `urllib.parse`, allowlists
- Notes: `render_template_string` is a hotspot unless user-controlled template data reaches it

### Go
- Sources: `r.URL.Query()`, `r.FormValue()`, request body decoders, path params
- Controls: prepared queries, `filepath.Clean` plus prefix check, strict command argument lists
- Notes: confirm values survive struct binding and helper wrappers

### Java
- Sources: `@RequestParam`, `@PathVariable`, `@RequestBody`, servlet request accessors
- Controls: `PreparedStatement`, bean validation, `URI` parsing plus allowlists
- Notes: distinguish string-built SQL from ORM/query-builder APIs

## Output format

```markdown
## Data Flow Trace: [target]

**Classification**: [finding | hotspot | false_positive]
**Vulnerability Type**: [sql-injection | ssrf | xss | ...]

### Source evidence
- [file:line] `source expression`
- Why it is attacker-controlled: [...]

### Hop chain
1. [file:line] `assignment or call`
2. [file:line] `next hop`
3. [file:line] `sink`

### Control evidence
- [file:line] `control`
- Coverage: [all paths | partial | none]
- Assessment: [effective | ineffective | unknown]

### Exploitability evidence
- Reachable: [yes | no | uncertain]
- Constraints: [...]
- Final rationale: [...]
```

## Notes

- Prefer evidence over speculation.
- If attacker control is not proven, classify as `hotspot`, not `finding`.
- If you cannot complete the hop chain, say where the trace broke and why.
