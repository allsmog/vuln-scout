#!/usr/bin/env python3
"""Ground truth definitions for benchmark applications.

Each benchmark app has a list of known vulnerabilities with their locations.
These are used by run_benchmark.py to measure precision and recall.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KnownVuln:
    """A known vulnerability in a benchmark application."""
    type: str          # sql-injection, xss, command-injection, etc.
    file: str          # Relative file path (partial match OK)
    line: int = 0      # Line number (0 = match any line in file)
    severity: str = "" # Expected severity (empty = any)
    description: str = ""
    alt_types: list[str] = field(default_factory=list)  # Alternative type names that also match


# Type aliases -- different tools/agents may use different names for the same vuln
TYPE_ALIASES: dict[str, set[str]] = {
    "xss": {"reflected-xss", "stored-xss", "dom-xss", "cross-site-scripting"},
    "path-traversal": {"file-inclusion", "lfi", "rfi", "directory-traversal"},
    "file-upload": {"unrestricted-file-upload", "arbitrary-file-upload"},
    "auth-bypass": {"brute-force", "authentication-bypass", "broken-authentication"},
    "command-injection": {"os-command-injection", "rce"},
    "sql-injection": {"sqli", "blind-sql-injection"},
    "ssrf": {"server-side-request-forgery"},
    "idor": {"insecure-direct-object-reference", "broken-access-control", "bola"},
    "deserialization": {"insecure-deserialization", "unsafe-deserialization"},
    "csrf": {"cross-site-request-forgery"},
    "xxe": {"xml-external-entity"},
    "code-injection": {"eval-injection", "remote-code-execution"},
    "stored-xss-risk": {"stored-xss", "persistent-xss"},
    "insecure-randomness": {"weak-random", "predictable-random"},
}


# ---------------------------------------------------------------------------
# OWASP Juice Shop (Node.js/TypeScript)
# https://github.com/juice-shop/juice-shop
# ---------------------------------------------------------------------------

JUICE_SHOP_VULNS: list[KnownVuln] = [
    # SQL Injection
    KnownVuln("sql-injection", "routes/login.ts", description="Login SQL injection via email field"),
    KnownVuln("code-injection", "routes/userProfile.ts", description="Code injection via dynamic evaluation in user profile"),
    KnownVuln("sql-injection", "routes/search.ts", description="Product search SQL injection via template literal"),

    # XSS
    KnownVuln("xss", "search-result.component", description="DOM XSS in search via [innerHTML]"),
    KnownVuln("stored-xss-risk", "routes/fileUpload.ts", description="Stored XSS via file upload filename"),

    # Path Traversal
    KnownVuln("path-traversal", "routes/fileServer.ts", description="Path traversal in file serving"),
    KnownVuln("path-traversal", "routes/keyServer.ts", description="Key server path traversal"),

    # SSRF
    KnownVuln("ssrf", "routes/profileImageUrlUpload.ts", description="SSRF via profile image URL"),

    # Broken Auth / IDOR
    KnownVuln("idor", "routes/basket.ts", description="Horizontal privilege escalation via IDOR in basket"),
    KnownVuln("idor", "routes/order.ts", description="IDOR in order access"),

    # Hardcoded Secrets
    KnownVuln("hardcoded-secret", "lib/insecurity.ts", description="Hardcoded JWT secret / private key"),

    # Deserialization
    KnownVuln("deserialization", "routes/b2bOrder.ts", description="Unsafe deserialization in B2B order"),

    # XXE
    KnownVuln("xxe", "routes/fileUpload.ts", description="XXE in file upload XML processing"),
]


# ---------------------------------------------------------------------------
# DVWA (PHP)
# https://github.com/digininja/DVWA
# ---------------------------------------------------------------------------

DVWA_VULNS: list[KnownVuln] = [
    # SQL Injection
    KnownVuln("sql-injection", "vulnerabilities/sqli/source/low.php", description="Classic SQL injection"),
    KnownVuln("sql-injection", "vulnerabilities/sqli_blind/source/low.php", description="Blind SQL injection"),

    # XSS
    KnownVuln("xss", "vulnerabilities/xss_r/source/low.php", description="Reflected XSS"),
    KnownVuln("xss", "vulnerabilities/xss_s/source/low.php", description="Stored XSS"),
    KnownVuln("xss", "vulnerabilities/xss_d/source/low.php", description="DOM XSS"),

    # Command Injection
    KnownVuln("command-injection", "vulnerabilities/exec/source/low.php", description="OS command injection via ping"),

    # File Upload
    KnownVuln("file-upload", "vulnerabilities/upload/source/low.php", description="Unrestricted file upload"),

    # Path Traversal
    KnownVuln("path-traversal", "vulnerabilities/fi/source/low.php", description="File inclusion / path traversal"),

    # CSRF
    KnownVuln("csrf", "vulnerabilities/csrf/source/low.php", description="CSRF in password change"),

    # Brute Force
    KnownVuln("auth-bypass", "vulnerabilities/brute/source/low.php", description="No brute force protection"),
]


# ---------------------------------------------------------------------------
# WebGoat (Java/Spring)
# https://github.com/WebGoat/WebGoat
# ---------------------------------------------------------------------------

WEBGOAT_VULNS: list[KnownVuln] = [
    # SQL Injection
    KnownVuln("sql-injection", "SqlInjectionLesson", description="SQL injection lessons"),
    KnownVuln("sql-injection", "SqlInjectionChallenge", description="Advanced SQL injection challenge"),

    # XSS
    KnownVuln("xss", "CrossSiteScripting", description="XSS lessons"),

    # XXE
    KnownVuln("xxe", "SimpleXXE", description="XML External Entity"),

    # Path Traversal
    KnownVuln("path-traversal", "ProfileUpload", description="Path traversal via file upload"),

    # Deserialization
    KnownVuln("deserialization", "InsecureDeserialization", description="Insecure deserialization"),

    # SSRF
    KnownVuln("ssrf", "SSRFTask", description="Server-side request forgery"),

    # JWT
    KnownVuln("insecure-randomness", "JWTSecretKeyEndpoint", description="JWT with weak secret"),
]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

BENCHMARKS: dict[str, dict[str, Any]] = {
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "repo": "https://github.com/juice-shop/juice-shop.git",
        "language": "typescript",
        "vulns": JUICE_SHOP_VULNS,
    },
    "dvwa": {
        "name": "DVWA",
        "repo": "https://github.com/digininja/DVWA.git",
        "language": "php",
        "vulns": DVWA_VULNS,
    },
    "webgoat": {
        "name": "WebGoat",
        "repo": "https://github.com/WebGoat/WebGoat.git",
        "language": "java",
        "vulns": WEBGOAT_VULNS,
    },
}
