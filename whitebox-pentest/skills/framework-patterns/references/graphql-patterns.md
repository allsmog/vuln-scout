---
name: graphql-patterns
description: GraphQL security anti-patterns across Apollo Server, Graphene, Strawberry, and Spring GraphQL including introspection exposure, query depth/complexity abuse, batching attacks, authorization bypass, and error disclosure.
---

# GraphQL Security Patterns

## 1. Introspection Enabled in Production

**Vulnerable Pattern:** GraphQL introspection queries (`__schema`, `__type`) left enabled in production, exposing the full API schema including hidden or internal types and fields.

### Detection

```bash
# Apollo Server / graphql-yoga / Express GraphQL
grep -rn "introspection" --include="*.ts" --include="*.js" --include="*.json"
grep -rn "introspection:\s*true" --include="*.ts" --include="*.js"

# Check for missing introspection disable (default is enabled in most frameworks)
grep -rn "ApolloServer\|createYoga\|graphqlHTTP\|createHandler" --include="*.ts" --include="*.js"

# Graphene (Python)
grep -rn "introspection" --include="*.py"
grep -rn "GraphQLView" --include="*.py"

# Strawberry (Python)
grep -rn "introspection" --include="*.py"

# Spring GraphQL
grep -rn "introspection" --include="*.java" --include="*.kt" --include="*.properties" --include="*.yml"
grep -rn "spring.graphql.schema.introspection" --include="*.properties" --include="*.yml"

# Test for introspection accessibility
# curl -X POST -H "Content-Type: application/json" \
#   -d '{"query":"{__schema{types{name}}}"}' http://target/graphql
```

### Vulnerable Code Patterns

```typescript
// Apollo Server - introspection enabled by default in dev, must explicitly disable in prod
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Missing: introspection: false
});

// Express GraphQL - introspection enabled by default
app.use('/graphql', graphqlHTTP({
  schema,
  graphiql: true,  // Also exposes interactive query editor!
}));
```

```python
# Graphene - introspection enabled by default
app.add_url_rule('/graphql', view_func=GraphQLView.as_view(
    'graphql',
    schema=schema,
    graphiql=True,  # Interactive editor exposed
))

# Strawberry - introspection enabled by default
schema = strawberry.Schema(query=Query)
```

```yaml
# Spring GraphQL - introspection enabled by default
spring:
  graphql:
    schema:
      introspection:
        enabled: true  # Or simply not set (defaults to true)
    graphiql:
      enabled: true  # GraphiQL IDE exposed
```

### Exploitation

```graphql
# Full schema dump
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
    mutationType { fields { name } }
    queryType { fields { name } }
  }
}

# Enumerate specific type
{
  __type(name: "User") {
    fields {
      name
      type { name }
    }
  }
}
```

### Remediation

```typescript
// Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});

// graphql-yoga
const yoga = createYoga({
  schema,
  graphiql: process.env.NODE_ENV !== 'production',
  // Disable introspection via plugin or validation rule
});
```

```python
# Graphene-Django
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'MIDDLEWARE': ['graphql_utils.middleware.DisableIntrospectionMiddleware'],
}

# Strawberry
from strawberry.extensions import DisableValidation
schema = strawberry.Schema(
    query=Query,
    extensions=[DisableIntrospectionExtension],
)
```

```yaml
# Spring GraphQL
spring:
  graphql:
    schema:
      introspection:
        enabled: false
    graphiql:
      enabled: false
```

---

## 2. No Query Depth Limit

**Vulnerable Pattern:** Deeply nested queries that exploit recursive relationships to cause exponential resolver execution and denial of service.

### Detection

```bash
# Check for depth limiting libraries
grep -rn "depthLimit\|maxDepth\|depth-limit\|QueryDepthLimiter" --include="*.ts" --include="*.js" --include="*.py" --include="*.java"

# graphql-depth-limit package
grep -rn "graphql-depth-limit" --include="package.json"

# Apollo Server validation rules
grep -rn "validationRules" --include="*.ts" --include="*.js"

# Graphene depth limiting
grep -rn "MaxQueryDepthMiddleware\|depth_limit" --include="*.py"

# Spring GraphQL
grep -rn "maxQueryDepth\|queryDepthLimit" --include="*.java" --include="*.yml" --include="*.properties"
```

### Vulnerable Schema Pattern

```graphql
# Schema with recursive types (no depth limit = DoS)
type User {
  id: ID!
  name: String!
  friends: [User!]!     # Recursive!
  posts: [Post!]!
}

type Post {
  id: ID!
  author: User!         # Back-reference, enables deep nesting
  comments: [Comment!]!
}

type Comment {
  author: User!         # Another back-reference
  replies: [Comment!]!  # Self-recursive!
}
```

### Exploitation

```graphql
# Exponential query - each level multiplies resolver calls
{
  users {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                name
              }
            }
          }
        }
      }
    }
  }
}
```

### Remediation

```typescript
// Apollo Server with graphql-depth-limit
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)],  // Max 5 levels deep
});

// graphql-yoga
import { createYoga } from 'graphql-yoga';
import { useDepthLimit } from '@graphql-yoga/plugin-depth-limit';

const yoga = createYoga({
  schema,
  plugins: [useDepthLimit({ maxDepth: 5 })],
});
```

```python
# Graphene with custom middleware
class DepthLimitMiddleware:
    def __init__(self, max_depth=5):
        self.max_depth = max_depth

    def resolve(self, next, root, info, **args):
        depth = self._get_depth(info.field_nodes[0])
        if depth > self.max_depth:
            raise GraphQLError(f"Query depth {depth} exceeds maximum {self.max_depth}")
        return next(root, info, **args)
```

---

## 3. No Query Complexity Limit

**Vulnerable Pattern:** No cost analysis on queries, allowing expensive operations (large lists, computed fields) without limits.

### Detection

```bash
# Query complexity libraries
grep -rn "queryComplexity\|costAnalysis\|complexityLimit\|QueryComplexity" --include="*.ts" --include="*.js" --include="*.py" --include="*.java"

# graphql-query-complexity package
grep -rn "graphql-query-complexity" --include="package.json"

# Cost directives in schema
grep -rn "@cost\|@complexity" --include="*.graphql" --include="*.gql"

# Pagination limits
grep -rn "first:\|last:\|limit:" --include="*.graphql" --include="*.gql" --include="*.ts" --include="*.js"
```

### Vulnerable Code Pattern

```graphql
# No pagination limits
type Query {
  users: [User!]!              # Returns ALL users
  posts(authorId: ID!): [Post!]!  # Returns ALL posts for author
}
```

```typescript
// Resolver without pagination enforcement
const resolvers = {
  Query: {
    users: () => db.users.findAll(),  // No limit!
    posts: (_, { authorId }) => db.posts.findAll({ where: { authorId } }),  // No limit!
  }
};
```

### Remediation

```typescript
// Apollo Server with graphql-query-complexity
import { createComplexityRule, simpleEstimator, fieldExtensionsEstimator } from 'graphql-query-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    createComplexityRule({
      maximumComplexity: 1000,
      estimators: [
        fieldExtensionsEstimator(),
        simpleEstimator({ defaultComplexity: 1 }),
      ],
      onComplete: (complexity) => {
        console.log('Query complexity:', complexity);
      },
    }),
  ],
});

// Enforce pagination
type Query {
  users(first: Int = 20, after: String): UserConnection!
}
```

---

## 4. Batching Attacks

**Vulnerable Pattern:** GraphQL endpoints accepting arrays of queries in a single request, bypassing per-request rate limiting and enabling brute-force attacks.

### Detection

```bash
# Check for batching configuration
grep -rn "allowBatchedHttpRequests\|batching\|batch" --include="*.ts" --include="*.js" --include="*.py" --include="*.java"

# Apollo Server 4 batching
grep -rn "allowBatchedHttpRequests" --include="*.ts" --include="*.js"

# Test: send array of queries
# curl -X POST -H "Content-Type: application/json" \
#   -d '[{"query":"{me{id}}"},{"query":"{me{id}}"}]' http://target/graphql
```

### Exploitation

```json
// Login brute-force via batch - bypasses per-request rate limit
[
  {"query": "mutation { login(email: \"admin@x.com\", password: \"password1\") { token } }"},
  {"query": "mutation { login(email: \"admin@x.com\", password: \"password2\") { token } }"},
  {"query": "mutation { login(email: \"admin@x.com\", password: \"password3\") { token } }"},
  // ... 100 more attempts in a single HTTP request
]

// Aliased query batching (single query, multiple operations)
{
  a1: login(email: "admin@x.com", password: "pass1") { token }
  a2: login(email: "admin@x.com", password: "pass2") { token }
  a3: login(email: "admin@x.com", password: "pass3") { token }
}
```

### Remediation

```typescript
// Apollo Server 4 - disable batching
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: false,
});

// Rate limit at resolver level (not just HTTP level)
import { rateLimitDirective } from 'graphql-rate-limit-directive';

const { rateLimitDirectiveTypeDefs, rateLimitDirectiveTransformer } =
  rateLimitDirective();

// Limit alias-based batching
const MAX_ALIASES = 5;
function aliasLimitPlugin() {
  return {
    requestDidStart() {
      return {
        didResolveOperation({ document }) {
          const definitions = document.definitions;
          for (const def of definitions) {
            if (def.selectionSet) {
              const aliases = def.selectionSet.selections.length;
              if (aliases > MAX_ALIASES) {
                throw new GraphQLError(`Too many aliases: ${aliases}`);
              }
            }
          }
        },
      };
    },
  };
}
```

---

## 5. Authorization Bypass via Nested Queries

**Vulnerable Pattern:** Authorization checks applied at the top-level query/mutation but missing on nested field resolvers, allowing data access through relationship traversal.

### Detection

```bash
# Find resolver files
grep -rn "Resolvers\|resolvers\|@ResolveField\|@Resolver" --include="*.ts" --include="*.js" --include="*.py" --include="*.java"

# Check for auth checks in resolvers
grep -rn "authorize\|isAuthenticated\|hasRole\|@AuthGuard\|@login_required\|@permission_required" --include="*.ts" --include="*.js" --include="*.py" --include="*.java"

# Find nested resolvers (type resolvers as opposed to query resolvers)
grep -rn "Query:\|Mutation:" --include="*.ts" --include="*.js" -A 50 | grep -v "Query:\|Mutation:" | grep -E "^\s+\w+:"

# Graphene - check for resolve_ methods without permissions
grep -rn "def resolve_" --include="*.py"

# Spring GraphQL - @SchemaMapping without @PreAuthorize
grep -rn "@SchemaMapping\|@QueryMapping\|@MutationMapping" --include="*.java" --include="*.kt"
```

### Vulnerable Code Patterns

```typescript
// Top-level has auth, nested resolver does not
const resolvers = {
  Query: {
    me: (_, __, { user }) => {
      if (!user) throw new AuthenticationError('Not authenticated');
      return getUserById(user.id);
    },
  },
  User: {
    // No auth check! Any authenticated user can traverse to any other user's data
    organization: (parent) => getOrganization(parent.orgId),
    salary: (parent) => getSalary(parent.id),  // Sensitive!
    ssn: (parent) => getSSN(parent.id),  // Very sensitive!
  },
  Organization: {
    // No auth check! Traverse org -> members -> sensitive data
    members: (parent) => getMembers(parent.id),
    billingInfo: (parent) => getBilling(parent.id),  // Sensitive!
  },
};
```

### Exploitation

```graphql
# Authenticated as regular user, traverse to other users' data
{
  me {
    organization {
      members {        # All org members exposed
        salary         # Including their salaries!
        ssn            # And SSNs!
      }
      billingInfo {    # And org billing details
        cardNumber
      }
    }
  }
}
```

### Remediation

```typescript
const resolvers = {
  Query: {
    me: (_, __, { user }) => {
      if (!user) throw new AuthenticationError('Not authenticated');
      return getUserById(user.id);
    },
  },
  User: {
    salary: (parent, _, { user }) => {
      // Only the user themselves or admins can see salary
      if (parent.id !== user.id && !user.isAdmin) {
        throw new ForbiddenError('Access denied');
      }
      return getSalary(parent.id);
    },
    ssn: (parent, _, { user }) => {
      if (parent.id !== user.id) {
        throw new ForbiddenError('Access denied');
      }
      return getSSN(parent.id);
    },
  },
  Organization: {
    billingInfo: (parent, _, { user }) => {
      if (!user.isOrgAdmin(parent.id)) {
        throw new ForbiddenError('Access denied');
      }
      return getBilling(parent.id);
    },
  },
};
```

---

## 6. Field-Level Authorization Missing

**Vulnerable Pattern:** All fields visible to all authenticated users, with no field-level visibility controls based on roles or permissions.

### Detection

```bash
# Schema directives for authorization
grep -rn "@auth\|@hasRole\|@isAuthenticated\|@requireAuth" --include="*.graphql" --include="*.gql"

# Custom directives in schema
grep -rn "directive @" --include="*.graphql" --include="*.gql"

# GraphQL Shield (Node.js)
grep -rn "graphql-shield\|shield\|rule\|allow\|deny" --include="*.ts" --include="*.js"

# Check for sensitive fields exposed without restrictions
grep -rn "password\|secret\|token\|apiKey\|ssn\|creditCard\|cardNumber" --include="*.graphql" --include="*.gql"
```

### Remediation

```typescript
// graphql-shield for field-level authorization
import { shield, rule, allow, deny } from 'graphql-shield';

const isAuthenticated = rule()((parent, args, ctx) => ctx.user !== null);
const isAdmin = rule()((parent, args, ctx) => ctx.user?.role === 'ADMIN');
const isOwner = rule()((parent, args, ctx) => parent.userId === ctx.user?.id);

const permissions = shield({
  Query: {
    '*': isAuthenticated,
    publicPosts: allow,
  },
  User: {
    email: isOwner,
    salary: isAdmin,
    ssn: deny,  // Never exposed via API
  },
  Mutation: {
    deleteUser: isAdmin,
  },
});
```

---

## 7. SQL Injection via Arguments

**Vulnerable Pattern:** GraphQL resolver arguments passed directly to raw database queries without parameterization.

### Detection

```bash
# Raw queries in resolvers
grep -rn "rawQuery\|raw(\|execute(" --include="*.ts" --include="*.js" --include="*.py" --include="*.java" | grep -E "args\.|input\.|param"

# Template literals in SQL within resolvers
grep -rn "SELECT\|INSERT\|UPDATE\|DELETE" --include="*.ts" --include="*.js" | grep '`.*\${'

# Python resolvers with string formatting in SQL
grep -rn "execute\|raw\|text(" --include="*.py" | grep -E "%s.*arg|\.format.*arg|f\""

# Java resolvers with string concatenation in SQL
grep -rn "createQuery\|nativeQuery\|createNativeQuery" --include="*.java" | grep -E "\+.*arg\|\".*\+.*param"
```

### Vulnerable Code Patterns

```typescript
// SQL injection via resolver argument (Node.js)
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      const result = await db.raw(`SELECT * FROM users WHERE id = '${id}'`);  // SQLI!
      return result.rows[0];
    },
    search: async (_, { term }) => {
      return db.raw(`SELECT * FROM posts WHERE title LIKE '%${term}%'`);  // SQLI!
    },
  },
};
```

```python
# SQL injection via resolver argument (Graphene)
class Query(graphene.ObjectType):
    user = graphene.Field(UserType, id=graphene.ID(required=True))

    def resolve_user(self, info, id):
        cursor = connection.cursor()
        cursor.execute(f"SELECT * FROM users WHERE id = {id}")  # SQLI!
        return cursor.fetchone()
```

```java
// SQL injection via resolver argument (Spring GraphQL)
@QueryMapping
public User user(@Argument String id) {
    String query = "SELECT * FROM users WHERE id = '" + id + "'";  // SQLI!
    return jdbcTemplate.queryForObject(query, userRowMapper);
}
```

### Remediation

```typescript
// Parameterized queries
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      const result = await db.raw('SELECT * FROM users WHERE id = ?', [id]);
      return result.rows[0];
    },
    search: async (_, { term }) => {
      return db('posts').where('title', 'like', `%${term}%`);  // Knex parameterizes
    },
  },
};
```

```python
# Parameterized query
def resolve_user(self, info, id):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", [id])
    return cursor.fetchone()
```

```java
// Parameterized query
@QueryMapping
public User user(@Argument String id) {
    return jdbcTemplate.queryForObject(
        "SELECT * FROM users WHERE id = ?", userRowMapper, id
    );
}
```

---

## 8. Error Disclosure

**Vulnerable Pattern:** Detailed error messages with stack traces, internal paths, or database schema information returned in GraphQL error responses.

### Detection

```bash
# Error formatting configuration
grep -rn "formatError\|includeStacktraceInErrorResponses\|debug.*true\|stacktrace" --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.yml"

# Apollo Server debug mode
grep -rn "debug:\s*true\|includeStacktraceInErrorResponses" --include="*.ts" --include="*.js"

# Spring GraphQL error configuration
grep -rn "spring.graphql.schema.inspection\|exception-handling" --include="*.yml" --include="*.properties"

# Custom error handling
grep -rn "GraphQLError\|ApolloError\|formatError" --include="*.ts" --include="*.js" --include="*.py"
```

### Vulnerable Code Patterns

```typescript
// Apollo Server with debug enabled
const server = new ApolloServer({
  typeDefs,
  resolvers,
  includeStacktraceInErrorResponses: true,  // Leaks internals!
});

// No error formatting - raw errors exposed
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Missing formatError - database errors, file paths, etc. exposed
});
```

### Exploitation

```json
// Error response leaking internal information
{
  "errors": [
    {
      "message": "ER_NO_SUCH_TABLE: Table 'myapp_prod.users_v2' doesn't exist",
      "locations": [{"line": 2, "column": 3}],
      "path": ["user"],
      "extensions": {
        "code": "INTERNAL_SERVER_ERROR",
        "stacktrace": [
          "Error: ER_NO_SUCH_TABLE",
          "    at /app/src/resolvers/user.ts:42:15",
          "    at processTicksAndRejections (node:internal/process/task_queues:95:5)"
        ]
      }
    }
  ]
}
```

### Remediation

```typescript
// Apollo Server - sanitize errors in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  includeStacktraceInErrorResponses: process.env.NODE_ENV !== 'production',
  formatError: (formattedError, error) => {
    // Log full error internally
    console.error(error);

    // Return sanitized error to client
    if (formattedError.extensions?.code === 'INTERNAL_SERVER_ERROR') {
      return {
        message: 'An internal error occurred',
        extensions: { code: 'INTERNAL_SERVER_ERROR' },
      };
    }
    return formattedError;
  },
});
```

```python
# Graphene-Django - custom error formatting
GRAPHENE = {
    'SCHEMA': 'myapp.schema.schema',
    'MIDDLEWARE': ['myapp.middleware.ErrorFormattingMiddleware'],
}

class ErrorFormattingMiddleware:
    def resolve(self, next, root, info, **args):
        try:
            return next(root, info, **args)
        except Exception as e:
            logger.exception("GraphQL resolver error")
            raise GraphQLError("An internal error occurred")
```

```yaml
# Spring GraphQL
spring:
  graphql:
    schema:
      inspection:
        enabled: false
server:
  error:
    include-stacktrace: never
    include-message: never
```

---

## Security Audit Commands

```bash
# Comprehensive grep sweep for GraphQL security issues
grep -rniE "(introspection:\s*true|graphiql:\s*true|allowBatchedHttpRequests:\s*true|includeStacktraceInErrorResponses|debug:\s*true)" --include="*.ts" --include="*.js" --include="*.py" --include="*.java" --include="*.yml" --include="*.properties"

# Check for missing security controls
grep -rniE "(depthLimit|maxDepth|queryComplexity|costAnalysis)" --include="*.ts" --include="*.js" --include="*.py" --include="*.java"

# Find all GraphQL resolver files
find . \( -name "*resolver*" -o -name "*schema*" -o -name "*typeDef*" \) -not -path "*/node_modules/*"

# Check for raw queries in resolver files
grep -rn "SELECT\|INSERT\|UPDATE\|DELETE" --include="*resolver*" --include="*schema*"
```

---

## Integration with Chain Detection

GraphQL vulnerabilities often chain with:
- Introspection revealing hidden admin mutations
- Nested query traversal bypassing REST-layer authorization
- Batching enabling credential stuffing at scale
- SQL injection via resolver arguments for data exfiltration
- Error disclosure revealing database schema for targeted SQL injection

When a GraphQL vulnerability is found:
1. Dump the full schema via introspection (if enabled)
2. Identify all mutations that modify state (especially admin operations)
3. Map recursive type relationships for depth attack vectors
4. Check if resolvers share a database connection pool (DoS amplification)
5. Verify authorization at every resolver, not just top-level queries
6. Test both array batching and alias batching independently

## CWE References

| Vulnerability | CWE | Name |
|---------------|-----|------|
| Introspection Exposure | CWE-200 | Exposure of Sensitive Information |
| No Depth Limit (DoS) | CWE-400 | Uncontrolled Resource Consumption |
| No Complexity Limit | CWE-400 | Uncontrolled Resource Consumption |
| Batching Attacks | CWE-307 | Improper Restriction of Excessive Authentication Attempts |
| Auth Bypass (Nested) | CWE-862 | Missing Authorization |
| Field-Level Auth Missing | CWE-863 | Incorrect Authorization |
| SQL Injection via Args | CWE-89 | SQL Injection |
| Error Disclosure | CWE-209 | Generation of Error Message Containing Sensitive Information |
