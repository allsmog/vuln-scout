# CPGQL Vulnerability Query Patterns

Common Joern CPGQL patterns for detecting security vulnerabilities.

## SQL Injection

### Find raw SQL queries with user input

```scala
// Sources: HTTP request parameters
val sources = cpg.parameter.name("req|request|params|query|body")

// Sinks: Database query functions
val sinks = cpg.call.name("query|execute|raw|rawQuery")

// Find flows
sinks.argument.reachableBy(sources).location.l
```

### Find string concatenation in queries

```scala
cpg.call.name("query")
  .argument
  .isCall
  .name("<operator>.addition")
  .where(_.argument.isIdentifier)
  .location.l
```

## Command Injection

### Find shell execution with dynamic input

```scala
val sources = cpg.parameter.name(".*")
val sinks = cpg.call.name("spawn|execSync|spawnSync|execFile")

sinks.argument.reachableBy(sources).location.l
```

### Template literal in shell commands

```scala
cpg.call.name("execSync")
  .argument(1)
  .isCall
  .name("<operator>.formatString")
  .location.l
```

## Path Traversal

### File operations with user input

```scala
val sources = cpg.parameter.name("path|file|filename|name")
val sinks = cpg.call.name("readFile|readFileSync|writeFile|createReadStream")

sinks.argument(1).reachableBy(sources).location.l
```

### Missing path validation

```scala
cpg.call.name("readFile|readFileSync")
  .where(_.argument(1).reachableBy(cpg.parameter))
  .whereNot(_.inAst.isCall.name("resolve|normalize|basename"))
  .location.l
```

## NoSQL Injection

### MongoDB queries with user input

```scala
val sources = cpg.parameter.name("req.*|body.*|query.*")
val sinks = cpg.call.name("find|findOne|findById|updateOne|deleteOne")

sinks.argument.reachableBy(sources).location.l
```

## Hardcoded Secrets

### Literal strings in sensitive assignments

```scala
cpg.assignment
  .where(_.target.code("(?i).*(password|secret|key|token|api_key).*"))
  .where(_.source.isLiteral)
  .location.l
```

### Secrets in function calls

```scala
cpg.call.name("(?i).*(auth|connect|sign|encrypt).*")
  .argument
  .isLiteral
  .code(".*[a-zA-Z0-9]{16,}.*")
  .location.l
```

## Cross-Site Scripting (XSS)

### User input to HTML output

```scala
val sources = cpg.parameter.name("req|request")
val sinks = cpg.call.name("send|write|render|html")

sinks.argument.reachableBy(sources).location.l
```

## Insecure Deserialization

### Unsafe deserialization calls

```scala
cpg.call.name("unserialize|deserialize|load|loads")
  .where(_.argument.reachableBy(cpg.parameter))
  .location.l
```

## Server-Side Request Forgery (SSRF)

### HTTP requests with user-controlled URLs

```scala
val sources = cpg.parameter.name("url|uri|host|target")
val sinks = cpg.call.name("fetch|request|get|post|axios")

sinks.argument(1).reachableBy(sources).location.l
```

## Mass Assignment / Object Injection

### Spread operator with request body

```scala
cpg.call.name("<operator>.spread")
  .where(_.argument.reachableBy(cpg.parameter.name("body")))
  .location.l
```

## Weak Cryptography

### MD5/SHA1 usage

```scala
cpg.call.name("createHash")
  .argument
  .isLiteral
  .code("\"md5\"|\"sha1\"")
  .location.l
```

## JWT Vulnerabilities

### None algorithm or weak signing

```scala
cpg.call.name("sign|verify")
  .where(_.argument.isLiteral.code(".*none.*|.*HS256.*"))
  .location.l
```

## Data Flow Analysis Helpers

### Get full flow path (for reporting)

```scala
def getFlowPath(source: Traversal[Parameter], sink: Traversal[Call]) = {
  sink.argument.reachableByFlows(source).p
}
```

### Check for sanitizers in path

```scala
val sources = cpg.parameter.name("userInput")
val sinks = cpg.call.name("dangerousSink")
val sanitizers = cpg.call.name("sanitize|escape|encode")

// Find flows that bypass sanitizers
sinks.argument
  .reachableBy(sources)
  .whereNot(_.inAst.isCall.name("sanitize|escape|encode"))
  .location.l
```

## Output Formatting

### Get location with code context

```scala
cpg.call.name("query")
  .location
  .map(loc => s"${loc.filename}:${loc.lineNumber} - ${loc.node.code}")
  .l
```

### Export as JSON

```scala
import io.circe.syntax._

cpg.call.name("query")
  .location
  .map(loc => Map(
    "file" -> loc.filename,
    "line" -> loc.lineNumber,
    "code" -> loc.node.code
  ))
  .l
  .asJson
```
