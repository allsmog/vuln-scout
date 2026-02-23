# Java Dangerous Functions

## Command Execution

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `Runtime.getRuntime().exec()` | Critical | Executes system commands |
| `ProcessBuilder.start()` | Critical | More control over process |
| `ProcessBuilder.command()` | Critical | Sets command to execute |

**Grep Pattern:**
```
grep -rniE "(Runtime.*exec|ProcessBuilder)" --include="*.java"
```

## Code/Expression Evaluation

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `ScriptEngine.eval()` | Critical | JavaScript/Groovy execution |
| `GroovyShell.evaluate()` | Critical | Groovy code execution |
| `OGNL.getValue()` | Critical | Struts2 RCE vector |
| `MVEL.eval()` | Critical | Expression language |
| `SpelExpressionParser` | High | Spring Expression Language |
| `ELProcessor.eval()` | High | EL injection |

**Grep Pattern:**
```
grep -rniE "(ScriptEngine|GroovyShell|OGNL|MVEL|SpelExpression|ELProcessor)" --include="*.java"
```

## Deserialization

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `ObjectInputStream.readObject()` | Critical | Java deserialization |
| `XMLDecoder.readObject()` | Critical | XML-based deserialization |
| `XStream.fromXML()` | Critical | XML serialization library |
| `ObjectMapper.readValue()` | High | Jackson with polymorphism |
| `Yaml.load()` | High | SnakeYAML deserialization |

**Grep Pattern:**
```
grep -rniE "(ObjectInputStream|XMLDecoder|XStream|readObject|fromXML)" --include="*.java"
```

## JNDI Injection (Log4Shell style)

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `InitialContext.lookup()` | Critical | JNDI lookup |
| `Context.lookup()` | Critical | JNDI lookup |
| `JndiTemplate.lookup()` | Critical | Spring JNDI |

**Grep Pattern:**
```
grep -rniE "(InitialContext|Context).*lookup|JndiTemplate" --include="*.java"
```

## File Operations

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `FileInputStream` | Medium | File read |
| `FileOutputStream` | High | File write |
| `Files.readAllBytes()` | Medium | NIO file read |
| `Files.write()` | High | NIO file write |
| `FileUtils.readFileToString()` | Medium | Commons IO |
| `new File()` | Medium | Path traversal risk |

**Grep Pattern:**
```
grep -rniE "(FileInputStream|FileOutputStream|Files\.(read|write)|FileUtils)" --include="*.java"
```

## SQL Injection

| Pattern | Risk | Notes |
|---------|------|-------|
| `Statement.executeQuery()` | High | Often with string concat |
| `Statement.execute()` | High | Check for concatenation |
| `createQuery()` with string concat | High | JPA/Hibernate |
| `createNativeQuery()` | High | Native SQL queries |

**Grep Pattern:**
```
grep -rniE "(executeQuery|executeUpdate|createQuery|createNativeQuery)" --include="*.java"
```

## SSRF Vectors

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `URL.openConnection()` | High | If URL user-controlled |
| `HttpClient.execute()` | High | Apache HttpClient |
| `RestTemplate.getForObject()` | High | Spring RestTemplate |
| `WebClient` | High | Spring WebFlux |

**Grep Pattern:**
```
grep -rniE "(openConnection|HttpClient|RestTemplate|WebClient)" --include="*.java"
```

## XML Processing (XXE)

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `DocumentBuilderFactory` | High | Check for secure config |
| `SAXParserFactory` | High | Check for secure config |
| `XMLInputFactory` | High | StAX parser |
| `TransformerFactory` | High | XSLT processing |

**Grep Pattern:**
```
grep -rniE "(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)" --include="*.java"
```

## Path Traversal

| Pattern | Risk | Notes |
|---------|------|-------|
| `new File(userInput)` | High | Direct path use |
| `Paths.get(userInput)` | High | NIO path |
| `getServletContext().getRealPath()` | Medium | Web app paths |

## Template Injection

| Framework | Risk | Notes |
|-----------|------|-------|
| Freemarker `Template` | High | SSTI vector |
| Velocity `Template` | High | SSTI vector |
| Thymeleaf `TemplateEngine` | Medium | Check for preprocessing |
