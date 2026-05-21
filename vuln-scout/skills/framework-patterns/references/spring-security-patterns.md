---
name: spring-security-patterns
description: Spring Security and Spring Boot anti-patterns including SpEL injection, method security misconfiguration, CORS issues, CSRF bypass, actuator exposure, mass binding, and insecure JWT handling.
---

# Spring Security Patterns

## 1. SpEL Injection in @PreAuthorize

**Vulnerable Pattern:** Dynamic Spring Expression Language (SpEL) expressions constructed from user input in `@PreAuthorize`, `@PostAuthorize`, `@Value`, or `SpelExpressionParser`.

### Detection

```bash
# SpEL in security annotations with string concatenation
grep -rn "@PreAuthorize" --include="*.java" --include="*.kt"
grep -rn "@PostAuthorize" --include="*.java" --include="*.kt"
grep -rn "@PreFilter\|@PostFilter" --include="*.java" --include="*.kt"

# SpelExpressionParser usage
grep -rn "SpelExpressionParser" --include="*.java" --include="*.kt"
grep -rn "ExpressionParser" --include="*.java" --include="*.kt"

# Dynamic SpEL construction
grep -rn "parseExpression(" --include="*.java" --include="*.kt"

# @Value with externalized input
grep -rn "@Value.*#\{" --include="*.java" --include="*.kt"
```

### Vulnerable Code Patterns

```java
// SpEL injection via user input in expression - RCE
@RestController
public class AdminController {
    @Autowired
    private SpelExpressionParser parser;

    @GetMapping("/check")
    public boolean checkAccess(@RequestParam String expression) {
        Expression exp = parser.parseExpression(expression);
        return (Boolean) exp.getValue();
        // expression=T(java.lang.Runtime).getRuntime().exec('id')
    }
}

// Dynamic security evaluator with user-controlled rule
@Component
public class DynamicSecurityEvaluator {
    public boolean evaluate(String rule, Authentication auth) {
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext ctx = new StandardEvaluationContext();
        ctx.setVariable("auth", auth);
        return parser.parseExpression(rule).getValue(ctx, Boolean.class);
        // SpEL INJECTION if rule comes from user input!
    }
}
```

### False Positives

- Static `@PreAuthorize("hasRole('ADMIN')")` with hardcoded expressions
- `@PreAuthorize("#id == authentication.principal.id")` referencing method parameters (safe -- SpEL parameter references are not user-controlled strings)
- `SpelExpressionParser` used only on configuration values, not user input

### Remediation

```java
// Never pass user input to SpEL parser
// Use static expressions in annotations
@PreAuthorize("hasRole('ADMIN')")
public void adminOnly() { }

// If dynamic evaluation is needed, use a whitelist
private static final Set<String> ALLOWED_RULES = Set.of(
    "hasRole('ADMIN')", "hasRole('USER')", "isAuthenticated()"
);

public boolean evaluate(String rule) {
    if (!ALLOWED_RULES.contains(rule)) {
        throw new SecurityException("Invalid security rule");
    }
    return parser.parseExpression(rule).getValue(Boolean.class);
}

// Use SimpleEvaluationContext to restrict SpEL capabilities
SimpleEvaluationContext ctx = SimpleEvaluationContext
    .forReadOnlyDataBinding().build();
parser.parseExpression(expression).getValue(ctx, Boolean.class);
```

---

## 2. Method Security Misconfiguration

**Vulnerable Pattern:** Enabling `@EnableGlobalMethodSecurity` without `prePostEnabled = true`, or missing `@EnableMethodSecurity` entirely, causing security annotations to be silently ignored.

### Detection

```bash
# Check method security configuration
grep -rn "@EnableGlobalMethodSecurity" --include="*.java" --include="*.kt"
grep -rn "@EnableMethodSecurity" --include="*.java" --include="*.kt"

# Verify prePostEnabled
grep -rn "prePostEnabled" --include="*.java" --include="*.kt"

# Find @PreAuthorize usage (may be silently ignored if not enabled)
grep -rn "@PreAuthorize\|@PostAuthorize\|@Secured\|@RolesAllowed" --include="*.java" --include="*.kt"

# Check for JSR-250 annotations without jsr250Enabled
grep -rn "@RolesAllowed" --include="*.java" --include="*.kt"
grep -rn "jsr250Enabled" --include="*.java" --include="*.kt"
```

### Vulnerable Code Patterns

```java
// @EnableGlobalMethodSecurity without prePostEnabled
@Configuration
@EnableGlobalMethodSecurity  // Missing prePostEnabled = true!
public class SecurityConfig { }

// Controller uses @PreAuthorize but it is silently ignored
@RestController
public class AdminController {
    @PreAuthorize("hasRole('ADMIN')")  // DOES NOTHING without prePostEnabled!
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
}

// Using @Secured but securedEnabled not set
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
// securedEnabled = false by default
public class SecurityConfig { }

@Secured("ROLE_ADMIN")  // Silently ignored!
public void adminAction() { }
```

### Remediation

```java
// Spring Boot 3.x / Spring Security 6.x (recommended)
@Configuration
@EnableMethodSecurity  // prePostEnabled=true by default in Spring Security 6+
public class SecurityConfig { }

// Spring Boot 2.x / Spring Security 5.x (legacy)
@Configuration
@EnableGlobalMethodSecurity(
    prePostEnabled = true,   // Enables @PreAuthorize, @PostAuthorize
    securedEnabled = true,   // Enables @Secured
    jsr250Enabled = true     // Enables @RolesAllowed
)
public class SecurityConfig { }
```

---

## 3. CORS Misconfiguration

**Vulnerable Pattern:** Allowing all origins with `allowedOrigins("*")` combined with `allowCredentials(true)`, or reflecting the Origin header without validation.

### Detection

```bash
# CORS configuration
grep -rn "allowedOrigins\|addAllowedOrigin" --include="*.java" --include="*.kt"
grep -rn "allowCredentials" --include="*.java" --include="*.kt"

# @CrossOrigin annotation
grep -rn "@CrossOrigin" --include="*.java" --include="*.kt"

# CorsConfiguration
grep -rn "CorsConfiguration" --include="*.java" --include="*.kt"

# Properties-based CORS
grep -rn "cors\." --include="*.properties" --include="*.yml" --include="*.yaml"

# Origin reflection (copying request origin to response)
grep -rn "getHeader.*Origin\|setHeader.*Access-Control-Allow-Origin" --include="*.java"
```

### Vulnerable Code Patterns

```java
// Wildcard origin with credentials - browser rejects but signals misconfiguration
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("*"));
    config.setAllowCredentials(true);  // Contradicts * origin!
    config.setAllowedMethods(List.of("*"));
    config.setAllowedHeaders(List.of("*"));

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
}

// Origin reflection without validation
@Component
public class CorsFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req,
            HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String origin = req.getHeader("Origin");
        res.setHeader("Access-Control-Allow-Origin", origin);  // Reflects any origin!
        res.setHeader("Access-Control-Allow-Credentials", "true");
        chain.doFilter(req, res);
    }
}

// @CrossOrigin with wildcard on sensitive endpoint
@CrossOrigin(origins = "*")
@GetMapping("/api/user/profile")
public UserProfile getProfile() { return null; }
```

### Remediation

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of(
        "https://app.example.com",
        "https://admin.example.com"
    ));
    config.setAllowCredentials(true);
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
}
```

---

## 4. CSRF Disabled

**Vulnerable Pattern:** Disabling CSRF protection entirely without assessing whether the application uses session-based or token-based authentication.

### Detection

```bash
# CSRF disabled in security config
grep -rn "csrf().disable()" --include="*.java" --include="*.kt"
grep -rn "csrf(csrf -> csrf.disable())" --include="*.java" --include="*.kt"
grep -rn "csrf(AbstractHttpConfigurer::disable)" --include="*.java" --include="*.kt"

# Check authentication type to assess risk
grep -rn "SessionCreationPolicy\.STATELESS" --include="*.java" --include="*.kt"
grep -rn "httpBasic\|formLogin\|oauth2Login\|sessionManagement" --include="*.java" --include="*.kt"
grep -rn "JwtAuthenticationFilter\|BearerTokenAuthenticationFilter" --include="*.java" --include="*.kt"
```

### Vulnerable Code Patterns

```java
// CSRF disabled on session-based app - VULNERABLE
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())  // DANGEROUS if using sessions!
        .formLogin(form -> form.loginPage("/login"))
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        );
    return http.build();
}
```

### Assessment Criteria

| Authentication Type | CSRF Required? | Notes |
|---------------------|----------------|-------|
| Session cookies (formLogin) | YES | Browser auto-attaches cookies |
| JWT in Authorization header | NO | Not auto-attached by browser |
| HTTP Basic | Depends | If browser caches credentials, yes |
| OAuth2 with cookies | YES | Cookie-based sessions |
| API-only (no browser) | NO | No cross-site context |

### False Positives

- CSRF disabled + `SessionCreationPolicy.STATELESS` + JWT authentication (stateless API)
- CSRF disabled on specific paths (e.g., webhooks) while enabled globally
- Non-browser API consumed only by backend services

### Remediation

```java
// For session-based apps: keep CSRF enabled
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers("/api/webhooks/**")  // Only exempt webhooks
        )
        .formLogin(Customizer.withDefaults());
    return http.build();
}

// For stateless JWT APIs: disable is acceptable
@Bean
public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session ->
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
}
```

---

## 5. Actuator Endpoint Exposure

**Vulnerable Pattern:** Exposing Spring Boot Actuator endpoints (`/actuator/*`) without authentication, leaking environment variables, heap dumps, and configuration.

### Detection

```bash
# Actuator exposure configuration
grep -rn "management\.endpoints\.web\.exposure" --include="*.properties" --include="*.yml" --include="*.yaml"
grep -rn "management\.endpoint\." --include="*.properties" --include="*.yml" --include="*.yaml"

# Check for wildcard exposure
grep -rn "exposure\.include.*\*" --include="*.properties" --include="*.yml" --include="*.yaml"

# Actuator security configuration
grep -rn "actuator" --include="*.java" --include="*.kt" | grep -i "security\|auth\|permit"

# Check for actuator dependency
grep -rn "spring-boot-starter-actuator" --include="*.xml" --include="*.gradle" --include="*.kts"

# Custom actuator base path
grep -rn "management\.endpoints\.web\.base-path\|management\.server\.port" --include="*.properties" --include="*.yml"
```

### Vulnerable Code Patterns

```yaml
# application.yml - ALL actuator endpoints exposed
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    env:
      enabled: true
    heapdump:
      enabled: true
```

```properties
# application.properties - equivalent
management.endpoints.web.exposure.include=*
management.endpoint.env.enabled=true
management.endpoint.heapdump.enabled=true
```

```java
// Security config permitting actuator without auth
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/**").permitAll()  // EXPOSED!
            .anyRequest().authenticated()
        );
    return http.build();
}
```

### High-Risk Endpoints

| Endpoint | Risk | Exposure |
|----------|------|----------|
| `/actuator/env` | Critical | Environment variables, secrets, API keys |
| `/actuator/heapdump` | Critical | Full heap dump, contains passwords in memory |
| `/actuator/configprops` | High | All configuration properties |
| `/actuator/mappings` | Medium | All URL mappings (attack surface enumeration) |
| `/actuator/beans` | Medium | All Spring beans (architecture disclosure) |
| `/actuator/jolokia` | Critical | JMX access, potential RCE |
| `/actuator/shutdown` | Critical | Graceful shutdown (DoS) |
| `/actuator/loggers` | High | Change log levels at runtime (info disclosure) |
| `/actuator/threaddump` | Medium | Thread dump with sensitive data |

### Remediation

```yaml
# Expose only safe endpoints
management:
  endpoints:
    web:
      exposure:
        include: health, info, metrics, prometheus
  endpoint:
    health:
      show-details: when_authorized
    env:
      enabled: false
    heapdump:
      enabled: false
    shutdown:
      enabled: false
```

```java
// Require authentication for actuator
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/actuator/health", "/actuator/info").permitAll()
            .requestMatchers("/actuator/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        );
    return http.build();
}
```

---

## 6. Mass Binding

**Vulnerable Pattern:** Using `@ModelAttribute` to bind request parameters directly to domain objects without restricting which fields can be set.

### Detection

```bash
# @ModelAttribute without @InitBinder
grep -rn "@ModelAttribute" --include="*.java" --include="*.kt"

# Check for @InitBinder field restrictions
grep -rn "@InitBinder" --include="*.java" --include="*.kt"
grep -rn "setAllowedFields\|setDisallowedFields" --include="*.java" --include="*.kt"

# Direct binding from request params to entity
grep -rn "BeanUtils\.copyProperties\|BeanUtils\.populate" --include="*.java"

# Jackson deserialization without @JsonIgnoreProperties
grep -rn "@RequestBody" --include="*.java" --include="*.kt"
grep -rn "@JsonIgnoreProperties\|@JsonIgnore" --include="*.java" --include="*.kt"
```

### Vulnerable Code Patterns

```java
// @ModelAttribute binds all matching parameters - MASS ASSIGNMENT
@PostMapping("/register")
public String register(@ModelAttribute User user) {
    // Attacker sends: name=John&email=john@x.com&role=ADMIN&active=true
    userRepository.save(user);  // role and active are set by attacker!
    return "redirect:/login";
}

// @RequestBody without field restrictions
@PostMapping("/api/users")
public ResponseEntity<User> createUser(@RequestBody User user) {
    // JSON body can include any field: {"name":"John","isAdmin":true}
    return ResponseEntity.ok(userRepository.save(user));
}
```

### False Positives

- DTOs (Data Transfer Objects) that only contain safe fields
- `@ModelAttribute` with explicit `@InitBinder` restricting fields
- Entities with `@JsonIgnore` on sensitive fields

### Remediation

```java
// Use DTOs instead of binding directly to entities
public record UserRegistrationDTO(
    @NotBlank String name,
    @Email String email,
    @Size(min = 8) String password
) {}

@PostMapping("/register")
public String register(@Valid @ModelAttribute UserRegistrationDTO dto) {
    User user = new User();
    user.setName(dto.name());
    user.setEmail(dto.email());
    user.setPassword(passwordEncoder.encode(dto.password()));
    user.setRole("USER");  // Server-controlled
    userRepository.save(user);
    return "redirect:/login";
}

// Or use @InitBinder to whitelist fields
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email", "password");
}

// For @RequestBody, use @JsonIgnoreProperties
@JsonIgnoreProperties({"id", "role", "isAdmin", "createdAt"})
public class UserRequest {
    private String name;
    private String email;
}
```

---

## 7. Insecure JWT Handling

**Vulnerable Pattern:** Missing signature verification, accepting `alg: none`, using weak algorithms, or exposing secrets in JWT configuration.

### Detection

```bash
# JWT dependencies
grep -rn "jjwt\|java-jwt\|nimbus-jose\|spring-security-oauth2-jose" --include="*.xml" --include="*.gradle" --include="*.kts"

# JWT parsing without verification
grep -rn "Jwts\.parser()\|JWT\.decode\|JWTParser\|SignedJWT" --include="*.java" --include="*.kt"

# Hardcoded secrets
grep -rn "secretKey\|signingKey\|jwtSecret" --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml"
grep -rn "\.signWith(" --include="*.java" --include="*.kt"

# Algorithm configuration
grep -rn "SignatureAlgorithm\.\|Algorithm\." --include="*.java" --include="*.kt"

# Token parsing without signature verification
grep -rn "parseClaimsJwt\b" --include="*.java"
# Note: parseClaimsJwt (no trailing 's') does NOT verify the signature
grep -rn "unsecured\|noneAlgorithm\|Algorithm\.none" --include="*.java" --include="*.kt"
```

### Vulnerable Code Patterns

```java
// parseClaimsJwt (without trailing 's') does NOT verify signature!
Claims claims = Jwts.parser()
    .parseClaimsJwt(token)  // Should be parseClaimsJws() with key!
    .getBody();

// Hardcoded weak secret
private static final String SECRET = "mySecretKey123";  // Weak and hardcoded!

public Claims parseToken(String token) {
    return Jwts.parser()
        .setSigningKey(SECRET.getBytes())
        .parseClaimsJws(token)
        .getBody();
}

// HMAC with short key
@Bean
public JwtDecoder jwtDecoder() {
    SecretKey key = new SecretKeySpec(
        "short".getBytes(), "HmacSHA256"
    );
    return NimbusJwtDecoder.withSecretKey(key).build();
}

// Accepting algorithm from token header (algorithm confusion attack)
public Claims parseToken(String token) {
    String[] parts = token.split("\\.");
    String header = new String(Base64.getDecoder().decode(parts[0]));
    String alg = parseAlgorithm(header);  // Attacker controls algorithm!
    // If attacker sets alg=HS256 with public RSA key as secret...
}
```

### False Positives

- `parseClaimsJws()` (with trailing 's') with proper signing key -- SAFE
- JWT validation delegated to Spring Security OAuth2 Resource Server (handles verification)
- Tokens validated by an external identity provider (Keycloak, Auth0) via JWKS

### Remediation

```java
// Use parseClaimsJws with strong key
@Component
public class JwtTokenProvider {
    private final SecretKey key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret) {
        // Ensure key is at least 256 bits for HS256
        this.key = Keys.hmacShaKeyFor(
            secret.getBytes(StandardCharsets.UTF_8)
        );
    }

    public Claims parseToken(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)  // Note: Jws not Jwt
            .getBody();
    }
}

// Spring Security OAuth2 Resource Server (recommended)
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .decoder(jwtDecoder())
            )
        );
    return http.build();
}

@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withJwkSetUri(
        "https://idp.example.com/.well-known/jwks.json"
    ).build();
}
```

---

## 8. Path Traversal via Resource Handling

**Vulnerable Pattern:** Serving static resources or file downloads with user-controlled paths.

### Detection

```bash
# Resource handling with user input
grep -rn "ResourceHttpRequestHandler\|ClassPathResource\|FileSystemResource" --include="*.java"
grep -rn "new File(" --include="*.java" | grep -E "param\|request\|path"

# File download endpoints
grep -rn "InputStreamResource\|ByteArrayResource" --include="*.java" | grep -E "param\|request"

# Path variable in file operations
grep -rn "@PathVariable.*path\|@RequestParam.*file\|@RequestParam.*path" --include="*.java"
```

### Remediation

```java
@GetMapping("/download")
public ResponseEntity<Resource> download(@RequestParam String filename) {
    // Sanitize filename
    String safe = Paths.get(filename).getFileName().toString();
    Path filePath = Paths.get("/uploads").resolve(safe).normalize();

    if (!filePath.startsWith("/uploads")) {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }

    Resource resource = new FileSystemResource(filePath);
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_DISPOSITION,
            "attachment; filename=\"" + safe + "\"")
        .body(resource);
}
```

---

## Security Audit Commands

```bash
# Comprehensive grep sweep for Spring security issues
grep -rniE "(\.csrf\(\)\.disable|csrf\.disable|permitAll|@CrossOrigin|allowedOrigins.*\*|SpelExpressionParser|parseClaimsJwt\b|exposure\.include.*\*|@ModelAttribute)" --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml"

# Check Spring Security filter chain ordering
grep -rn "SecurityFilterChain\|WebSecurityConfigurerAdapter\|@Order" --include="*.java" --include="*.kt"

# Find all security configurations
find . -name "*.java" -path "*Security*" -o -name "*.java" -path "*security*"
```

---

## Integration with Chain Detection

Spring Security vulnerabilities often chain with:
- Actuator `/env` endpoint leaking database credentials or API keys
- Actuator `/heapdump` containing JWT secrets or session tokens
- SpEL injection escalating from expression evaluation to RCE
- Mass binding setting `isAdmin=true` on user registration
- CSRF bypass + session fixation for account takeover

When a Spring vulnerability is found:
1. Check `application.properties` / `application.yml` for all profiles (dev, staging, prod)
2. Inspect `SecurityFilterChain` ordering -- first matching chain wins
3. Verify actuator endpoints are not exposed on the public interface
4. Check for multiple `SecurityFilterChain` beans that may conflict
5. Review custom `AuthenticationProvider` implementations for logic flaws
6. Inspect `@ControllerAdvice` for error handlers that leak stack traces

## CWE References

| Vulnerability | CWE | Name |
|---------------|-----|------|
| SpEL Injection | CWE-917 | Expression Language Injection |
| Method Security Bypass | CWE-862 | Missing Authorization |
| CORS Misconfiguration | CWE-942 | Permissive Cross-domain Policy |
| CSRF Disabled | CWE-352 | Cross-Site Request Forgery |
| Actuator Exposure | CWE-215 | Insertion of Sensitive Information Into Debugging Code |
| Mass Binding | CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| Insecure JWT | CWE-347 | Improper Verification of Cryptographic Signature |
| Path Traversal | CWE-22 | Path Traversal |
