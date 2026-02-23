# STRIDE Threats by Component Type

This reference provides STRIDE threat analysis templates for common application component types. Use this when performing systematic threat enumeration.

---

## API Endpoints / REST Controllers

### Spoofing
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Missing authentication | No `@auth` decorator, no token check | HIGH |
| Weak authentication | Basic auth, API key in URL | MEDIUM |
| Session hijacking | No secure cookie flags | HIGH |
| JWT algorithm confusion | `alg: none` accepted | CRITICAL |

### Tampering
| Threat | Indicator | Severity |
|--------|-----------|----------|
| SQL injection | String concatenation in queries | CRITICAL |
| NoSQL injection | `$where`, `$regex` with user input | CRITICAL |
| Command injection | User input in `exec`, `system` | CRITICAL |
| Parameter pollution | Multiple same-name params | MEDIUM |
| Mass assignment | `user.update(req.body)` | HIGH |

### Repudiation
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Missing audit logs | No logging on sensitive actions | MEDIUM |
| Mutable logs | Logs stored without integrity protection | MEDIUM |
| No transaction signing | Financial ops without proof | HIGH |

### Information Disclosure
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Verbose errors | Stack traces in responses | MEDIUM |
| IDOR | Direct object access without ownership check | HIGH |
| Data exposure | Sensitive fields in API responses | HIGH |
| Directory listing | Static file servers without index | LOW |

### Denial of Service
| Threat | Indicator | Severity |
|--------|-----------|----------|
| No rate limiting | Missing throttle middleware | MEDIUM |
| ReDoS | Complex regex on user input | HIGH |
| Large payload | No body size limit | MEDIUM |
| Resource exhaustion | Unbounded queries/loops | HIGH |

### Elevation of Privilege
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Missing authorization | No role check on endpoint | HIGH |
| Broken access control | Role check bypassable | CRITICAL |
| Privilege escalation | User can modify own role | CRITICAL |
| Function-level missing | Admin endpoint publicly accessible | CRITICAL |

---

## Authentication Systems

### Spoofing
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Credential stuffing | No account lockout | HIGH |
| Brute force | No rate limiting on login | HIGH |
| Default credentials | Hardcoded admin/admin | CRITICAL |
| Password spraying | No detection of distributed attacks | MEDIUM |
| Session fixation | Session ID not regenerated on login | HIGH |

### Tampering
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Token modification | JWT without signature validation | CRITICAL |
| Cookie tampering | No HMAC on session cookies | HIGH |
| Password reset poisoning | Host header injection in reset emails | HIGH |

### Repudiation
| Threat | Indicator | Severity |
|--------|-----------|----------|
| No login audit | Failed logins not logged | MEDIUM |
| Session tracking | No record of active sessions | LOW |

### Information Disclosure
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Username enumeration | Different responses for valid/invalid users | MEDIUM |
| Password in logs | Credentials logged | CRITICAL |
| Timing attacks | Observable timing difference in auth | MEDIUM |
| Weak password storage | MD5, SHA1, unsalted hashes | CRITICAL |

### Denial of Service
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Account lockout DoS | Attacker can lock out legitimate users | MEDIUM |
| Expensive hashing | Bcrypt cost too high | LOW |
| MFA flooding | SMS/email bombing possible | MEDIUM |

### Elevation of Privilege
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Role in token | Editable role claim in JWT | CRITICAL |
| Insecure direct object reference | Access other users' sessions | HIGH |
| OAuth misconfiguration | Open redirect, token leakage | HIGH |

---

## File Upload Handlers

### Spoofing
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Upload impersonation | No user association with uploads | MEDIUM |

### Tampering
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Path traversal | `../` in filename not sanitized | CRITICAL |
| Content-type bypass | Only MIME type checked, not content | HIGH |
| Zip slip | Archive extraction without path validation | CRITICAL |
| Polyglot files | File valid as multiple types | HIGH |

### Information Disclosure
| Threat | Indicator | Severity |
|--------|-----------|----------|
| XXE via XML | XML parsing with external entities | CRITICAL |
| EXIF data leakage | Image metadata not stripped | LOW |
| SVG script injection | SVG files served without sanitization | HIGH |

### Denial of Service
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Large file upload | No size limits | MEDIUM |
| Zip bomb | Compressed file ratio not checked | HIGH |
| Image processing DoS | Pixel flood, decompression bomb | HIGH |
| YAML bomb | Billion laughs in YAML | HIGH |

### Elevation of Privilege
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Web shell upload | Executable files uploadable | CRITICAL |
| Config overwrite | Can upload to sensitive paths | CRITICAL |
| .htaccess upload | Apache config injection | CRITICAL |

---

## Database Access Layer

### Spoofing
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Connection impersonation | Shared DB credentials | MEDIUM |

### Tampering
| Threat | Indicator | Severity |
|--------|-----------|----------|
| SQL injection | String concatenation | CRITICAL |
| NoSQL injection | Operator injection (`$gt`, `$ne`) | CRITICAL |
| ORM injection | Raw queries in ORM | HIGH |
| Second-order injection | Stored payload executed later | HIGH |

### Repudiation
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Missing audit trail | No `created_at`, `updated_by` | MEDIUM |
| No soft delete | Hard deletes without logging | LOW |

### Information Disclosure
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Error-based SQLi | Database errors exposed | HIGH |
| Connection string exposure | Credentials in code/logs | CRITICAL |
| Backup exposure | Database dumps accessible | CRITICAL |
| Verbose logging | Query params logged | MEDIUM |

### Denial of Service
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Unbounded queries | No LIMIT on user queries | MEDIUM |
| N+1 queries | ORM misuse causing query explosion | MEDIUM |
| Lock contention | Long transactions blocking others | MEDIUM |

### Elevation of Privilege
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Privilege escalation via DB | User can modify own permissions | CRITICAL |
| Stored procedure abuse | Unsafe stored procs callable | HIGH |

---

## External API Integrations

### Spoofing
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Man-in-the-middle | TLS verification disabled | HIGH |
| DNS rebinding | No host validation | HIGH |
| Webhook spoofing | No signature verification | HIGH |

### Tampering
| Threat | Indicator | Severity |
|--------|-----------|----------|
| SSRF | User-controlled URL in API call | CRITICAL |
| Response injection | API response used unsanitized | HIGH |
| Header injection | User input in HTTP headers | HIGH |

### Information Disclosure
| Threat | Indicator | Severity |
|--------|-----------|----------|
| API key exposure | Keys in code/logs | CRITICAL |
| Credential leakage | Auth headers in error messages | HIGH |
| Over-fetching | Requesting more data than needed | MEDIUM |

### Denial of Service
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Cascading failure | No circuit breaker | MEDIUM |
| Timeout issues | No timeout on external calls | MEDIUM |
| Rate limit bypass | Proxying requests to hit rate limits | MEDIUM |

### Elevation of Privilege
| Threat | Indicator | Severity |
|--------|-----------|----------|
| OAuth token theft | Tokens stored insecurely | HIGH |
| Scope escalation | Requesting more permissions than needed | MEDIUM |

---

## Message Queues / Background Workers

### Spoofing
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Message injection | Unauthenticated queue access | HIGH |
| Producer impersonation | No message signing | MEDIUM |

### Tampering
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Message modification | No integrity protection | HIGH |
| Deserialization attacks | Unsafe deserialize on messages | CRITICAL |
| Job parameter injection | User data in job params unsanitized | HIGH |

### Repudiation
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Untracked jobs | No job completion logging | MEDIUM |
| Missing dead letter | Failed jobs not preserved | LOW |

### Information Disclosure
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Sensitive data in queue | PII in message payloads | HIGH |
| Queue monitoring exposure | Admin interface public | HIGH |

### Denial of Service
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Queue flooding | No rate limiting on job creation | HIGH |
| Poison message | Malformed message crashes worker | HIGH |
| Resource exhaustion | Unbounded job processing | MEDIUM |

### Elevation of Privilege
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Job type injection | User controls job class/type | CRITICAL |
| Worker privilege | Workers run with excessive permissions | HIGH |

---

## Caching Layer (Redis, Memcached)

### Spoofing
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Unauthenticated access | No AUTH configured | HIGH |
| Session hijacking | Session IDs guessable | HIGH |

### Tampering
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Cache poisoning | User-controlled cache keys | HIGH |
| Session manipulation | Session data modifiable | CRITICAL |
| Redis command injection | User input in Redis commands | CRITICAL |

### Information Disclosure
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Cache data exposure | Sensitive data cached | HIGH |
| KEYS enumeration | KEYS command enabled | MEDIUM |

### Denial of Service
| Threat | Indicator | Severity |
|--------|-----------|----------|
| Cache exhaustion | No eviction policy | MEDIUM |
| Slow operations | O(n) commands on large datasets | MEDIUM |

### Elevation of Privilege
| Threat | Indicator | Severity |
|--------|-----------|----------|
| ACL bypass | Cache used for authorization checks | HIGH |
| Config injection | CONFIG SET possible | CRITICAL |

---

## Usage

1. Identify component type in target application
2. Find corresponding section above
3. Check each threat indicator in code
4. Document findings with severity
5. Use `/whitebox-pentest:trace` for high-severity findings
