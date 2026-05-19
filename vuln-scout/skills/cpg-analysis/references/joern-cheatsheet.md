# Joern / CPGQL Cheatsheet

Quick reference for Joern Code Property Graph analysis.

## Installation

```bash
# Install Joern
curl -L "https://github.com/joernio/joern/releases/latest/download/joern-install.sh" | bash

# Add to PATH
export PATH="$HOME/bin/joern:$PATH"
```

## Basic Commands

```bash
# Parse codebase into CPG
joern-parse /path/to/code --output cpg.bin

# Parse specific language
joern-parse /path/to/code --language javascript --output cpg.bin

# Start REPL
joern

# Run script
joern --script analysis.sc

# Run script with parameters
joern --script analysis.sc --params cpgFile=cpg.bin,vulnType=sqli
```

## REPL Commands

```scala
// Import CPG
importCpg("cpg.bin")

// Save CPG
save

// Close CPG
close

// List loaded CPGs
workspace

// Help
help
```

## Node Types

| Node | Description | Example |
|------|-------------|---------|
| `cpg.method` | Functions/methods | `def login()` |
| `cpg.call` | Function calls | `query(sql)` |
| `cpg.parameter` | Function parameters | `req, res` |
| `cpg.local` | Local variables | `let x = 1` |
| `cpg.literal` | Literal values | `"hello"`, `42` |
| `cpg.identifier` | Variable references | `x`, `user` |
| `cpg.fieldAccess` | Property access | `req.body` |
| `cpg.returns` | Return statements | `return user` |
| `cpg.controlStructure` | if/for/while | `if (x) {}` |
| `cpg.assignment` | Assignments | `x = y` |

## Common Traversals

### Filtering

```scala
// By name (regex)
cpg.method.name(".*login.*")

// By code content
cpg.call.code(".*SELECT.*")

// By file
cpg.method.filename(".*auth.*")

// By line number
cpg.call.lineNumber(42)
```

### Navigation

```scala
// Get method containing a call
cpg.call.name("query").method

// Get calls within a method
cpg.method.name("login").call

// Get caller methods
cpg.method.name("query").caller

// Get callee methods
cpg.method.name("login").callee

// Get arguments
cpg.call.name("query").argument

// Get nth argument (1-indexed)
cpg.call.name("query").argument(1)
```

### Type Checks

```scala
// Check if identifier
.isIdentifier

// Check if literal
.isLiteral

// Check if call
.isCall

// Check if parameter
.isParameter
```

### Boolean Operators

```scala
// Where (filter)
cpg.call.where(_.argument.isLiteral)

// Where not
cpg.call.whereNot(_.argument.isLiteral)

// Or
cpg.call.name("query").or(_.name("execute"))

// And
cpg.call.name("query").and(_.argument.isIdentifier)
```

## Data Flow Analysis

### Reachability

```scala
// Check if source reaches sink
val sources = cpg.parameter.name("input")
val sinks = cpg.call.name("query")

// Simple reachability
sinks.argument.reachableBy(sources).l

// With full path
sinks.argument.reachableByFlows(sources).p
```

### Taint Tracking

```scala
// Define sources and sinks
val sources = cpg.parameter.name("req.*")
val sinks = cpg.call.name("query|execute")

// Find tainted flows
sinks.argument
  .reachableBy(sources)
  .location.l
```

### Path Printing

```scala
// Print paths
sinks.argument.reachableByFlows(sources).p

// Pretty print paths
sinks.argument.reachableByFlows(sources).passesNot("sanitize").p
```

## Output Methods

| Method | Output |
|--------|--------|
| `.l` | List of results |
| `.head` | First result |
| `.size` | Count |
| `.p` | Pretty print |
| `.toJson` | JSON format |
| `.location` | File:line info |

## Location Info

```scala
cpg.call.name("query").location.l
// Returns: List(Location(filename, lineNumber, ...))

cpg.call.name("query").location.map(l =>
  s"${l.filename}:${l.lineNumber}"
).l
```

## Script Template

```scala
// analysis.sc
@main def main(cpgFile: String, vulnType: String = "sqli") = {
  loadCpg(cpgFile)

  vulnType match {
    case "sqli" => findSqli()
    case "cmdi" => findCmdi()
    case _ => println(s"Unknown: $vulnType")
  }
}

def findSqli() = {
  val sources = cpg.parameter.name("req.*|body.*")
  val sinks = cpg.call.name("query|execute")

  sinks.argument.reachableBy(sources).location.l.foreach { loc =>
    println(s"[SQLi] ${loc.filename}:${loc.lineNumber}")
  }
}

def findCmdi() = {
  val sources = cpg.parameter
  val sinks = cpg.call.name("spawn|execSync")

  sinks.argument.reachableBy(sources).location.l.foreach { loc =>
    println(s"[CMDi] ${loc.filename}:${loc.lineNumber}")
  }
}
```

## Language-Specific Notes

### JavaScript/TypeScript

```scala
// Arrow functions
cpg.method.name("<lambda>")

// Template literals
cpg.call.name("<operator>.formatString")

// Object spread
cpg.call.name("<operator>.spread")

// Destructuring
cpg.local.name("_destructured_")
```

### Python

```scala
// f-strings
cpg.call.name("<operator>.formatString")

// Class methods
cpg.method.where(_.parameter.name("self"))

// Decorators
cpg.annotation.name("route")
```

### Java

```scala
// Annotations
cpg.annotation.name("RequestMapping")

// Instance methods
cpg.method.isConstructor

// Inheritance
cpg.typeDecl.inheritsFromTypeFullName(".*Controller")
```

## Performance Tips

1. **Filter early**: Apply `.name()` filters before traversals
2. **Limit results**: Use `.head(10)` during exploration
3. **Cache CPGs**: Reuse parsed CPG files
4. **Incremental**: Use `joern-parse --update` for changes

## Common Issues

| Issue | Solution |
|-------|----------|
| Out of memory | Increase heap: `JAVA_OPTS="-Xmx8g" joern` |
| Slow parsing | Exclude node_modules, vendor dirs |
| Missing flows | Check language support, try `--language` flag |
| Query timeout | Simplify query, filter earlier |
