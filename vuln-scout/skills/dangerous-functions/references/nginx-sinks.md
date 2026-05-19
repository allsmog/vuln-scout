# Nginx Dangerous Configurations

## Cache Poisoning Vectors

Configurations that can enable web cache deception or cache poisoning:

| Directive | Risk | Notes |
|-----------|------|-------|
| `proxy_cache` | High | Enables caching, check what's cached |
| `proxy_cache_valid` | High | Sets cache TTL, authenticated content risk |
| `proxy_cache_key` | Critical | If doesn't include user identity, cache pollution |
| `location ~* \.(css\|js\|png)$` + cache | Critical | Caches by extension, enables cache deception |

**Grep Pattern:**
```bash
# Find cache configurations
grep -rniE "proxy_cache|proxy_cache_valid|proxy_cache_key" --include="*.conf" --include="nginx.conf"

# CRITICAL: Check if static extensions are cached
grep -rniE "location.*\.(css|js|png|jpg|jpeg|gif|ico)" -A10 --include="*.conf" | grep -iE "proxy_cache"
```

### Dangerous Pattern: Extension-Based Caching

```nginx
# VULNERABLE: Caches based on extension without auth check
location ~* \.(css|js|png|jpg|jpeg|gif|ico)$ {
    proxy_cache cache;
    proxy_cache_valid 200 3m;
    proxy_pass http://backend;
}
```

**Attack Vector:**
1. Victim visits `/profile.png` (authenticated)
2. Nginx caches the JSON response (thinks it's a PNG)
3. Attacker requests `/profile.png`
4. Gets victim's cached profile data

**Secure Configuration:**
```nginx
location ~* \.(css|js|png|jpg|jpeg|gif|ico)$ {
    proxy_cache cache;
    proxy_cache_valid 200 3m;
    # Bypass cache for authenticated requests
    proxy_cache_bypass $http_authorization $cookie_session;
    proxy_no_cache $http_authorization $cookie_session;
    proxy_pass http://backend;
}
```

---

## SSRF Amplification

| Directive | Risk | Notes |
|-----------|------|-------|
| `proxy_pass` with variable | Critical | If user controls upstream |
| `resolver` + `$host` | High | DNS rebinding possible |
| `upstream` with user input | Critical | Internal network access |

**Grep Pattern:**
```bash
# Check for variable-based proxy_pass
grep -rniE "proxy_pass.*\$" --include="*.conf"

# Check resolver configuration
grep -rniE "resolver" --include="*.conf"
```

---

## Information Disclosure

| Directive | Risk | Notes |
|-----------|------|-------|
| `autoindex on` | Medium | Directory listing enabled |
| `server_tokens on` | Low | Version disclosure |
| `error_page` misconfiguration | Medium | Path disclosure |

**Grep Pattern:**
```bash
grep -rniE "autoindex\s+on|server_tokens" --include="*.conf"
```

---

## Access Control Bypass

| Directive | Risk | Notes |
|-----------|------|-------|
| `if ($uri ~ ...)` | High | Regex bypass possible |
| `location = /admin` vs `location /admin` | Medium | Path normalization issues |
| Missing `internal` on sensitive locations | High | Direct access possible |

**Grep Pattern:**
```bash
# Check for regex-based access control
grep -rniE "if.*\$uri|if.*\$request_uri" --include="*.conf"

# Check internal locations
grep -rniE "location.*(admin|internal|private|api)" --include="*.conf"
```

---

## Header Injection

| Directive | Risk | Notes |
|-----------|------|-------|
| `proxy_set_header` with user input | High | Header injection |
| `add_header` without `always` | Medium | Missing on error pages |
| `X-Forwarded-For` trusting | High | IP spoofing |

**Grep Pattern:**
```bash
# Check header handling
grep -rniE "proxy_set_header|add_header|X-Forwarded" --include="*.conf"

# Check trust settings
grep -rniE "set_real_ip_from|real_ip_header" --include="*.conf"
```

---

## SSL/TLS Misconfigurations

| Directive | Risk | Notes |
|-----------|------|-------|
| `ssl_protocols` with TLSv1.0/1.1 | Medium | Weak protocols |
| `ssl_ciphers` with weak ciphers | Medium | Export/NULL/RC4 |
| `ssl_verify_client` disabled | Medium | Missing mTLS |

**Grep Pattern:**
```bash
grep -rniE "ssl_protocols|ssl_ciphers|ssl_verify" --include="*.conf"
```

---

## Request Smuggling

| Directive | Risk | Notes |
|-----------|------|-------|
| `proxy_http_version 1.0` | High | CL.TE smuggling |
| Missing `proxy_set_header Connection ""` | Medium | Connection header issues |
| `proxy_buffering off` | Medium | Timing-based attacks |

**Grep Pattern:**
```bash
grep -rniE "proxy_http_version|proxy_buffering|chunked" --include="*.conf"
```

---

## Rate Limiting Bypass

| Directive | Risk | Notes |
|-----------|------|-------|
| `limit_req` too permissive | Medium | Brute force possible |
| Missing rate limiting on auth endpoints | High | Credential stuffing |
| `limit_req_zone` based on $binary_remote_addr | Medium | Bypassable with X-Forwarded-For |

**Grep Pattern:**
```bash
grep -rniE "limit_req|limit_conn|limit_rate" --include="*.conf"
```

---

## Common Vulnerable Patterns

### Pattern 1: Cache Everything Static
```nginx
# DANGEROUS
location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
    proxy_cache cache;
    proxy_cache_valid 200 30m;
    proxy_pass http://app;
}
```

### Pattern 2: Permissive Upstream Proxy
```nginx
# DANGEROUS if $backend_url is user-controlled
location /proxy {
    set $backend_url $arg_url;
    proxy_pass $backend_url;
}
```

### Pattern 3: Missing Internal Restriction
```nginx
# DANGEROUS - should have 'internal;'
location /internal-api {
    proxy_pass http://internal-service;
}
```

---

## Security Checklist

- [ ] Cache configuration excludes authenticated content
- [ ] No extension-based caching of dynamic paths
- [ ] Proxy variables not user-controlled
- [ ] Directory listing disabled
- [ ] Internal locations marked as `internal`
- [ ] TLS 1.2+ only
- [ ] Rate limiting on auth endpoints
- [ ] Security headers present
