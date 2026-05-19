# .NET/C# Dangerous Functions

## Command Execution

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `Process.Start()` | Critical | Starts external process |
| `ProcessStartInfo` | Critical | Process configuration |
| `System.Diagnostics.Process` | Critical | Process management |

**Grep Pattern:**
```
grep -rniE "(Process\.Start|ProcessStartInfo|System\.Diagnostics\.Process)" --include="*.cs"
```

## Code Execution

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `CSharpCodeProvider` | Critical | Dynamic compilation |
| `CompileAssemblyFromSource()` | Critical | Compiles C# code |
| `Assembly.Load()` | Critical | Loads assembly |
| `Assembly.LoadFrom()` | Critical | Loads from file |
| `Activator.CreateInstance()` | High | Dynamic instantiation |
| `Type.InvokeMember()` | High | Reflection invocation |

**Grep Pattern:**
```
grep -rniE "(CSharpCodeProvider|CompileAssembly|Assembly\.Load|Activator\.CreateInstance)" --include="*.cs"
```

## Deserialization

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `BinaryFormatter.Deserialize()` | Critical | Known gadget chains |
| `ObjectStateFormatter` | Critical | ViewState deserialization |
| `LosFormatter` | Critical | ViewState deserialization |
| `NetDataContractSerializer` | Critical | Type-aware serializer |
| `SoapFormatter` | Critical | SOAP deserialization |
| `XmlSerializer` with type | High | If type is user-controlled |
| `DataContractSerializer` | Medium | Check for known types |
| `JavaScriptSerializer` | High | With TypeResolver |
| `Json.NET TypeNameHandling` | Critical | If not None |
| `fastJSON` | High | Type handling |

**Grep Pattern:**
```
grep -rniE "(BinaryFormatter|ObjectStateFormatter|LosFormatter|NetDataContractSerializer|SoapFormatter|Deserialize)" --include="*.cs"
```

## SQL Injection

| Pattern | Risk | Notes |
|---------|------|-------|
| `SqlCommand` with string concat | Critical | Direct SQLi |
| `SqlDataAdapter` with concat | Critical | Direct SQLi |
| `ExecuteReader()` | High | Check query construction |
| `ExecuteNonQuery()` | High | Check query construction |
| `ExecuteScalar()` | High | Check query construction |
| String interpolation in SQL | Critical | $"SELECT...{var}" |

**Grep Pattern:**
```
grep -rniE "(SqlCommand|SqlDataAdapter|Execute(Reader|NonQuery|Scalar))" --include="*.cs"
```

## File Operations

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `File.ReadAllText()` | Medium | File read |
| `File.WriteAllText()` | High | File write |
| `File.ReadAllBytes()` | Medium | Binary read |
| `File.WriteAllBytes()` | High | Binary write |
| `FileStream` | Medium | File access |
| `StreamReader` | Medium | Text file read |
| `StreamWriter` | High | Text file write |
| `Path.Combine()` | Medium | Check for traversal |

**Grep Pattern:**
```
grep -rniE "(File\.(Read|Write)|FileStream|StreamReader|StreamWriter)" --include="*.cs"
```

## SSRF/HTTP Requests

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `HttpClient` | High | If URL user-controlled |
| `WebClient` | High | If URL user-controlled |
| `HttpWebRequest` | High | If URL user-controlled |
| `WebRequest.Create()` | High | If URL user-controlled |

**Grep Pattern:**
```
grep -rniE "(HttpClient|WebClient|HttpWebRequest|WebRequest\.Create)" --include="*.cs"
```

## XML Processing (XXE)

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `XmlDocument.Load()` | High | Check DtdProcessing |
| `XmlReader.Create()` | High | Check XmlReaderSettings |
| `XmlTextReader` | Critical | DTD enabled by default |
| `XPathDocument` | High | XML parsing |
| `XslCompiledTransform` | High | XSLT processing |

**Grep Pattern:**
```
grep -rniE "(XmlDocument|XmlReader|XmlTextReader|XPathDocument|XslCompiledTransform)" --include="*.cs"
```

## LDAP Injection

| Class/Method | Risk | Notes |
|--------------|------|-------|
| `DirectorySearcher` | High | If filter user-controlled |
| `DirectoryEntry` | Medium | LDAP connection |

**Grep Pattern:**
```
grep -rniE "(DirectorySearcher|DirectoryEntry)" --include="*.cs"
```

## Path Traversal

| Pattern | Risk | Notes |
|---------|------|-------|
| `Path.Combine()` with user input | High | If not validated |
| `Server.MapPath()` | High | Web path mapping |
| `Request.PhysicalPath` | High | Request path |

## Unsafe Code

| Pattern | Risk | Notes |
|---------|------|-------|
| `unsafe` keyword | High | Pointer manipulation |
| `Marshal` class | High | Unmanaged memory |
| `DllImport` | High | Native code calls |
| `PInvoke` | High | Platform invocation |

**Grep Pattern:**
```
grep -rniE "(unsafe|Marshal\.|DllImport|extern)" --include="*.cs"
```

## ViewState

| Pattern | Risk | Notes |
|---------|------|-------|
| `EnableViewStateMac = false` | Critical | ViewState tampering |
| `ViewStateUserKey` not set | High | CSRF via ViewState |

## Regex DoS

| Pattern | Risk | Notes |
|---------|------|-------|
| Complex regex with user input | Medium | ReDoS vulnerability |
| `Regex.Match()` without timeout | Medium | Potential DoS |
