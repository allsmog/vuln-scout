#!/usr/bin/env python3
"""Extended vulnerability class detectors.

Provides detection logic for vulnerability classes not covered by the
default Semgrep/CodeQL rulesets:
  - Race conditions / TOCTOU
  - Prototype pollution (JavaScript)
  - File upload vulnerabilities
  - OAuth/OIDC flaws
  - Request smuggling indicators
  - WebSocket vulnerabilities
  - Mass assignment (deep)
  - CORS misconfiguration (deep)

Each detector scans source files and returns normalized findings.
"""
from __future__ import annotations

import dataclasses
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

log = logging.getLogger("vuln-scout")

# Populated by run_all_detectors with any per-detector exceptions caught
# during the last invocation. Consumers (scan_orchestrator, mobile_scan)
# read this after the call to surface failures in the output artifact.
LAST_DETECTOR_FAILURES: list[dict[str, Any]] = []

_EXCLUDED_DIRS = frozenset({
    "node_modules", "vendor", "dist", "build", ".git",
    "__pycache__", ".joern", ".claude", "skills", "references",
    "docs", "examples", "agents", "commands", "hooks",
    "test", "tests", "__tests__", "fixtures",
    # iOS dependency / build directories (added during audit pass):
    # without these, iOS scans walk third-party CocoaPods / Carthage
    # / Swift Package Manager / Xcode build output and emit findings
    # for code the operator can't fix.
    "Pods", "Carthage", ".swiftpm", "DerivedData",
})

_LANG_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".kts",
    ".rb", ".php", ".cs", ".rs", ".sol", ".mjs", ".cjs", ".swift", ".m", ".mm",
}


# The scanner's own plugin directory name -- used to skip self-referential scans
_PLUGIN_DIR_NAMES = frozenset({"vuln-scout", "whitebox-pentest", ".claude-plugin"})


# Third-party library package path segments commonly seen in decompiled mobile apps
# and other source trees. Detector findings inside these paths are almost always noise
# (Kotlin/Java stdlib internals, AndroidX, Google SDKs, vendored analytics, etc.).
#
# Two kinds of prefixes:
#   * Single-segment ("kotlin",) — matches ONLY when the path begins with that
#     segment, i.e. directly under the scan root. This prevents accidental
#     matches on user code like ``com/myapp/android/...`` which contains
#     ``android`` mid-path but is *not* third-party.
#   * Multi-segment ("com","google","android") — matches anywhere as a
#     consecutive run, since these full namespace tuples are unambiguous.
_THIRD_PARTY_PATH_PREFIXES: tuple[tuple[str, ...], ...] = (
    # Kotlin / JVM stdlib (root-only)
    ("kotlin",), ("kotlinx",), ("java",), ("javax",), ("j$",),
    ("scala",), ("groovy",), ("dagger",), ("javassist",), ("tslib",),
    ("okhttp3",), ("okio",), ("retrofit2",), ("androidx",),
    # jadx "no package" bucket — proguard/R8-stripped classes with single-letter
    # names live here. Empirically these are always third-party SDK code whose
    # original package got minified away (Nimbus JOSE, Braintree internals,
    # Stripe helpers, etc.), so user-actionable signal is essentially zero.
    ("defpackage",),
    # Multi-segment package roots
    ("com", "android", "support"),
    ("com", "android", "internal"),
    ("com", "android", "tools"),
    ("com", "android", "billingclient"),
    ("com", "android", "installreferrer"),
    ("com", "google", "android"),
    ("com", "google", "firebase"),
    ("com", "google", "protobuf"),
    ("com", "google", "common"),
    ("com", "google", "errorprone"),
    ("com", "google", "gson"),
    ("com", "google", "auto"),
    ("com", "google", "j2objc"),
    ("com", "google", "tagmanager"),
    ("com", "google", "ads"),
    ("com", "google", "mlkit"),
    ("com", "google", "crypto"),
    ("com", "google", "cloud"),
    ("com", "squareup"),
    ("com", "bumptech", "glide"),
    ("com", "facebook"),
    ("com", "fasterxml"),
    ("com", "lexisnexisrisk"),
    ("com", "iovation"),
    ("com", "threatmetrix"),
    ("com", "shape"),
    ("com", "incognia"),
    ("com", "auth0"),
    ("com", "okta"),
    ("com", "onelogin"),
    ("com", "rudderstack"),
    ("com", "amplitude"),
    ("com", "segment"),
    ("com", "datadog"),
    ("com", "adjust"),
    ("com", "stripe"),
    ("com", "braintree"),
    ("com", "paypal"),
    ("com", "intellij"),
    ("com", "mapbox"),
    ("com", "mapquest"),
    ("com", "amazonaws"),
    ("com", "amazon"),
    ("com", "newrelic"),
    ("com", "appsflyer"),
    ("com", "mixpanel"),
    ("com", "bugsnag"),
    ("com", "crashlytics"),
    ("io", "reactivex"),
    ("io", "grpc"),
    ("io", "netty"),
    ("io", "sentry"),
    ("io", "bitdrift"),
    ("com", "usebutton"),
    ("com", "stripe", "android"),
    ("com", "stripe", "core"),
    ("com", "salesforce"),
    ("com", "zendesk"),
    ("com", "twilio"),
    ("io", "intercom"),
    ("io", "branch"),
    ("io", "embrace"),
    ("io", "opentelemetry"),
    ("io", "opentracing"),
    ("org", "joda"),
    ("org", "maplibre"),
    ("org", "bouncycastle"),
    ("org", "spongycastle"),
    ("org", "apache"),
    ("org", "json"),
    ("org", "jsoup"),
    ("org", "slf4j"),
    ("org", "checkerframework"),
    ("org", "intellij"),
    ("org", "jetbrains"),
    ("kotlinx", "android"),
)

# Single-segment prefixes are forced to match only at the path root (depth 0)
# to avoid swallowing user code that happens to contain a generic name mid-path
# (e.g. com/myapp/android/...).
_THIRD_PARTY_ROOT_ONLY: frozenset[str] = frozenset({
    p[0] for p in _THIRD_PARTY_PATH_PREFIXES if len(p) == 1
})


def _path_starts_with(parts: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    if len(prefix) > len(parts):
        return False
    for i in range(len(parts) - len(prefix) + 1):
        if parts[i : i + len(prefix)] == prefix:
            return True
    return False


# Path components that mark a conventional "source root" inside a project tree.
# When walking absolute paths, any prefix preceding one of these is treated as
# infrastructure (decompiler output dir, IDE workspace, gradle layout) and the
# third-party namespace check restarts at that boundary.
_SOURCE_ROOT_MARKERS: frozenset[str] = frozenset({
    "sources", "source", "src", "java", "main", "app",
    "jadx_out", "jadx_out2", "apktool_out",
    "decompiled", "android-decompiled", "user_only", "app_only",
    # iOS conventions — SwiftPM uses capitalized "Sources", Xcode
    # template projects use "App/" and "Application/". Without these
    # markers, _effective_parts can't strip the prefix and 3rd-party
    # path detection misfires for iOS source trees.
    "Sources", "App", "Application", "ios", "iOS",
})


def _effective_parts(path: Path) -> tuple[str, ...]:
    """Strip leading components up to and including the last source-root marker.

    Lets the namespace check work on relative-style parts even when callers
    pass absolute paths. Falls back to the full parts tuple if no marker is
    present.
    """
    parts = path.parts
    last_marker = -1
    for i, p in enumerate(parts):
        if p in _SOURCE_ROOT_MARKERS:
            last_marker = i
    if last_marker >= 0 and last_marker + 1 < len(parts):
        return parts[last_marker + 1 :]
    return parts


def _is_third_party_path(path: Path) -> bool:
    """Heuristic: skip findings inside common 3rd-party namespaces.

    Single-segment prefixes (``kotlin``, ``java``, etc.) match only when they
    appear as the first *effective* path component (post source-root stripping)
    since these names also occur as sub-segments of legitimate user code
    (e.g. ``com/myapp/android/...``). Multi-segment prefixes match anywhere as
    a consecutive run.
    """
    eparts = _effective_parts(path)
    if eparts and eparts[0] in _THIRD_PARTY_ROOT_ONLY:
        return True
    for prefix in _THIRD_PARTY_PATH_PREFIXES:
        if len(prefix) == 1:
            continue
        if _path_starts_with(eparts, prefix):
            return True
    return False


def _is_excluded(path: Path, root: Path | None = None) -> bool:
    # Check parts RELATIVE to the scan root if provided — otherwise the
    # exclusion list matches against ancestors of the root (e.g., a
    # scan target at /Users/me/build/app would have every file
    # excluded because "build" is in _EXCLUDED_DIRS). This was a real
    # silent-empty-scan bug for users whose project path happened to
    # contain one of the excluded names.
    if root is not None:
        try:
            rel = path.relative_to(root)
            parts = rel.parts
        except ValueError:
            # path isn't under root — fall back to all parts.
            parts = path.parts
    else:
        parts = path.parts
    if any(part in _EXCLUDED_DIRS for part in parts):
        return True
    # Skip the scanner's own plugin directory to avoid self-referential findings
    if any(part in _PLUGIN_DIR_NAMES for part in parts):
        return True
    # Skip well-known third-party library paths in decompiled / bundled trees
    if _is_third_party_path(path):
        return True
    return False


# ---------------------------------------------------------------------------
# Shared file index – one traversal for all detectors
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class FileIndex:
    """Pre-computed file index for a source tree.  One rglob, many consumers."""

    root: Path
    _by_suffix: dict[str, list[Path]] = dataclasses.field(default_factory=dict)

    @classmethod
    def build(cls, root: Path) -> FileIndex:
        by_suffix: dict[str, list[Path]] = {}
        for f in root.rglob("*"):
            if not f.is_file() or _is_excluded(f, root=root):
                continue
            by_suffix.setdefault(f.suffix, []).append(f)
        return cls(root=root, _by_suffix=by_suffix)

    def files_with_suffixes(self, suffixes: set[str]) -> Iterator[Path]:
        """Yield all indexed files whose suffix is in *suffixes*."""
        for suffix in suffixes:
            yield from self._by_suffix.get(suffix, [])


def _scan_files(
    root: Path,
    extensions: set[str],
    patterns: list,
    file_index: FileIndex | None = None,
) -> list[dict[str, Any]]:
    """Generic scanner: apply regex patterns to matching files and return findings.

    Each pattern tuple is (regex, vuln_type, title, message, severity[, kind]).
    The optional 6th element ``kind`` defaults to ``"finding"``.
    """
    findings: list[dict[str, Any]] = []
    if file_index is not None:
        file_iter = file_index.files_with_suffixes(extensions)
    else:
        file_iter = (
            f for f in root.rglob("*")
            if f.is_file() and f.suffix in extensions and not _is_excluded(f)
        )
    for f in file_iter:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(root))
        for i, line in enumerate(text.splitlines(), 1):
            for entry in patterns:
                pattern, vuln_type, title, message, severity = entry[:5]
                kind = entry[5] if len(entry) > 5 else "finding"
                if pattern.search(line):
                    findings.append(_make_finding(
                        vuln_type, title, rel, i, line.strip()[:200],
                        message, severity, kind,
                    ))
    return findings


def _make_finding(vuln_type: str, title: str, file: str, line: int,
                  excerpt: str, message: str, severity: str,
                  kind: str = "finding",
                  metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": "",
        "stable_key": "",
        "kind": kind,
        "severity": severity,
        "type": vuln_type,
        "title": title,
        "file": file,
        "line": line,
        "verdict": "unverified",
        "confidence": "medium",
        "source_tool": "vuln-class-detector",
        "message": message,
        "evidence": [{
            "type": "pattern-match",
            "label": vuln_type,
            "path": file,
            "line": line,
            "excerpt": excerpt,
        }],
    }
    if metadata:
        finding["metadata"] = {k: v for k, v in metadata.items() if v not in (None, [], "")}
    return finding


def _make_code_contract_finding(
    vuln_type: str,
    title: str,
    file: str,
    line: int,
    excerpt: str,
    message: str,
    severity: str = "medium",
    trigger_conditions: list[str] | None = None,
    impact: str | None = None,
    validation_steps: list[str] | None = None,
    confidence: str = "high",
) -> dict[str, Any]:
    finding = _make_finding(
        vuln_type, title, file, line, excerpt, message, severity, "finding"
    )
    finding["confidence"] = confidence
    finding["analysis_style"] = "code-contract"
    finding["verification"] = {
        "trigger_conditions": trigger_conditions or [],
        "impact": impact or "Security impact depends on server-side validation and caller reachability.",
        "validation_steps": validation_steps or [],
    }
    return finding


# ---------------------------------------------------------------------------
# Race Conditions / TOCTOU
# ---------------------------------------------------------------------------

def detect_race_conditions(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect potential race conditions and TOCTOU patterns.

    Limited to high-signal patterns. The earlier ``volatile``/``static``
    heuristic matched virtually every Kotlin/Java singleton in decompiled
    APKs without yielding actionable leads, so it has been removed.

    The SQL-TOCTOU pattern now scans server-side languages only (Python/JS/Go/Ruby/PHP)
    since Android Room's ``wzd.f("SELECT … WHERE foo=?")`` builder uses bound
    parameters and was previously generating ~50 false positives per APK.
    """
    fs_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php"}
    fs_patterns = [
        # Filesystem TOCTOU: check then use -- real vulnerability
        (re.compile(r'(?:os\.path\.exists|os\.access|Path.*\.exists)\s*\('),
         "race-condition", "TOCTOU: filesystem check-then-use",
         "File existence check followed by file operation creates a race condition (CWE-367)", "medium"),
        # Database TOCTOU: SELECT/UPDATE with concatenated user input
        # Looks for a SELECT/UPDATE keyword followed (anywhere in the line) by
        # ``" + identifier`` -- the canonical "build SQL by concat" shape.
        (re.compile(r"""(?:SELECT|UPDATE)\b[^;]*["'`]\s*\+\s*[A-Za-z_$][\w$]*(?:(?!BEGIN|TRANSACTION|FOR\s+UPDATE).)*$""", re.IGNORECASE),
         "race-condition", "Database TOCTOU: SELECT/UPDATE with concatenated user input",
         "User input concatenated into SELECT/UPDATE without explicit transactional gate (CWE-367)", "medium"),
        # Threading/goroutine -- informational audit points, not confirmed vulns
        (re.compile(r'(?:threading\.Thread|multiprocessing\.Process)\s*\('),
         "race-condition", "Potential race condition in concurrent code",
         "Concurrent access without visible locking may cause race conditions (CWE-362)", "low", "hotspot"),
        (re.compile(r'\bgo\s+\w+\s*\('),
         "race-condition", "Goroutine without visible synchronization",
         "Goroutine accessing shared state without mutex/channel may race (CWE-362)", "low", "hotspot"),
    ]
    return _scan_files(root, fs_exts, fs_patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# Prototype Pollution (JavaScript)
# ---------------------------------------------------------------------------

def detect_prototype_pollution(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect prototype pollution patterns in JavaScript/TypeScript."""
    js_exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    patterns = [
        # Object.assign with user input
        (re.compile(r'Object\.assign\s*\(\s*\{?\}?\s*,\s*(?:req\.|params\.|body\.|query\.)'),
         "prototype-pollution", "Prototype pollution via Object.assign",
         "User-controlled object merged into target without prototype sanitization (CWE-1321)", "high"),
        # Lodash/underscore deep merge with user input
        (re.compile(r'(?:_\.merge|_\.defaultsDeep|lodash\.merge)\s*\('),
         "prototype-pollution", "Prototype pollution via deep merge",
         "Deep merge function with potentially user-controlled input (CWE-1321)", "medium"),
        # NOTE: for-in loops removed -- too broad, matches all JS for-in (36 FPs on Juice Shop)
        # Direct __proto__ access
        (re.compile(r'__proto__|constructor\s*\[\s*["\']prototype'),
         "prototype-pollution", "Direct prototype chain access",
         "Direct access to __proto__ or constructor.prototype (CWE-1321)", "high"),
    ]
    return _scan_files(root, js_exts, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# File Upload Vulnerabilities
# ---------------------------------------------------------------------------

def detect_file_upload_vulns(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect unsafe file upload handling.

    Restricted to web frameworks. The earlier ``.save()`` heuristic was
    language-agnostic and matched hundreds of unrelated DAO/Room calls in
    decompiled Java/Kotlin — limiting to file types where Flask/Django
    upload contexts make sense kills that noise without losing real
    web-side findings.
    """
    web_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".php"}
    patterns = [
        # Upload handler presence is an audit point, not a confirmed vuln
        (re.compile(r'(?:multer|formidable|busboy)\s*\('),
         "file-upload", "File upload handler (review extension validation)",
         "File upload handler detected -- verify extension/MIME validation (CWE-434)", "low", "hotspot"),
        # Path join with user-controlled filename -- more likely a real issue
        (re.compile(r'(?:path\.join|os\.path\.join|filepath\.Join)\s*\([^)]*(?:filename|originalname|name)'),
         "file-upload", "Path construction with user-controlled filename",
         "User-controlled filename in path join without basename extraction (CWE-22)", "high"),
        # Python/Flask file save without secure_filename -- only meaningful in web contexts
        (re.compile(r'request\.files\b[^.]*\.\w+\.save\s*\(\s*(?!.*secure_filename)'),
         "file-upload", "File save without secure_filename",
         "File saved without secure_filename sanitization (CWE-434)", "medium"),
    ]
    return _scan_files(root, web_exts, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# OAuth/OIDC Flaws
# ---------------------------------------------------------------------------

def detect_oauth_flaws(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect common OAuth/OIDC implementation flaws."""
    patterns = [
        # Missing state parameter
        (re.compile(r'(?:authorize_url|authorization_url|auth_url)\s*(?:=|\.)\s*(?!.*state)'),
         "oauth-flaw", "OAuth authorization without state parameter",
         "Missing CSRF protection via state parameter in OAuth flow (CWE-352)", "high"),
        # Token in URL query parameter
        (re.compile(r'(?:access_token|token)\s*=.*(?:query|params|searchParams|url)'),
         "oauth-flaw", "Access token in URL query parameter",
         "Access token exposed in URL, may be logged or leaked via Referer (CWE-598)", "medium"),
        # No PKCE (code_challenge)
        (re.compile(r'(?:grant_type\s*=\s*["\']authorization_code)(?!.*code_challenge)'),
         "oauth-flaw", "Authorization code flow without PKCE",
         "Authorization code flow without PKCE is vulnerable to code interception (CWE-345)", "medium"),
        # Implicit grant (deprecated)
        (re.compile(r'response_type\s*=\s*["\']token'),
         "oauth-flaw", "OAuth implicit grant flow (deprecated)",
         "Implicit grant exposes tokens in URL fragment, use authorization code + PKCE instead", "medium"),
    ]
    return _scan_files(root, _LANG_EXTENSIONS, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# Request Smuggling Indicators
# ---------------------------------------------------------------------------

def detect_request_smuggling(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect request smuggling indicators in proxy/server configs.

    Restricted to non-Java server / proxy contexts because the
    ``Transfer-Encoding`` literal also appears in decompiled OkHttp/Retrofit
    internals (which jadx renames to default-package classes that we can't
    cleanly exclude by path).
    """
    config_exts = {".conf", ".cfg", ".yml", ".yaml", ".toml", ".json", ".py", ".js", ".ts", ".go"}
    patterns = [
        # Custom Transfer-Encoding handling -- only flag in proxy/server code, not client libs
        (re.compile(r'(?:res|response|req|request)\.headers?\.set\s*\(\s*[\'"]?[Tt]ransfer-[Ee]ncoding'),
         "request-smuggling", "Manual Transfer-Encoding handling",
         "Manual Transfer-Encoding header writes can enable HTTP request smuggling (CWE-444)", "medium"),
        # Proxy pass without normalization
        (re.compile(r'proxy_pass\s+http'),
         "request-smuggling", "Reverse proxy without path normalization",
         "Proxy pass may forward ambiguous requests enabling smuggling (CWE-444)", "low"),
        # Custom HTTP parsing
        (re.compile(r'(?:Content-Length|content.length)\s*(?:=|:)\s*(?:parseInt|Number|int\(|strconv\.Atoi)'),
         "request-smuggling", "Manual Content-Length parsing",
         "Custom Content-Length parsing may disagree with backend parser (CWE-444)", "medium"),
    ]
    return _scan_files(root, config_exts, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# WebSocket Vulnerabilities
# ---------------------------------------------------------------------------

def detect_websocket_vulns(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect WebSocket security issues."""
    ws_exts = {".js", ".ts", ".tsx", ".jsx", ".py", ".go", ".java", ".rb"}
    patterns = [
        # Missing origin validation
        (re.compile(r"""(?:WebSocket|ws)\s*\.?\s*(?:Server|on\s*\(\s*['"]connection)"""),
         "websocket-vuln", "WebSocket server without visible origin validation",
         "WebSocket connection without origin validation enables cross-site hijacking (CWE-346)", "medium"),
        # User input to eval/exec in WebSocket handler
        (re.compile(r"""on\s*\(\s*['"]message['"][^)]*\)\s*(?:=>|{)[^}]*(?:eval|Function)\s*\("""),
         "websocket-vuln", "Code execution in WebSocket message handler",
         "WebSocket message handler with dynamic code execution (CWE-94)", "critical"),
    ]
    return _scan_files(root, ws_exts, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# Mass Assignment (deep)
# ---------------------------------------------------------------------------

def detect_mass_assignment(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect mass assignment vulnerabilities across frameworks."""
    patterns = [
        # Express/Node: Object.assign(model, req.body) or spread
        (re.compile(r'(?:Object\.assign|\.\.\.req\.body|\.\.\.request\.body)'),
         "mass-assignment", "Mass assignment via request body spread",
         "Request body directly assigned to model without field filtering (CWE-915)", "medium"),
        # Rails: params without permit
        (re.compile(r'\.(?:create|update|new)\s*\(\s*params(?!\s*\.\s*(?:require|permit))'),
         "mass-assignment", "Rails mass assignment without strong parameters",
         "Model create/update with unfiltered params (CWE-915)", "high"),
        # Django: ModelForm without fields restriction
        (re.compile(r'class\s+\w+\s*\(\s*(?:forms\.ModelForm|ModelForm)\s*\)'),
         "mass-assignment", "Django ModelForm (check fields restriction)",
         "ModelForm without explicit fields may expose all model fields (CWE-915)", "low"),
    ]
    return _scan_files(root, _LANG_EXTENSIONS, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# CORS Misconfiguration (deep)
# ---------------------------------------------------------------------------

def detect_cors_misconfig(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect CORS misconfigurations.

    The earlier ``(?:allow_origin|allowed_origins|origin).*null`` pattern was
    swallowing every Java/Kotlin line that happened to mention ``origin`` and
    ``null`` (toString builders, deeplink mappers, etc.). Tightened to require
    an actual CORS header / config token.
    """
    cors_exts = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".php",
                 ".conf", ".yml", ".yaml", ".toml", ".json"}
    patterns = [
        # Wildcard origin
        (re.compile(r"""Access-Control-Allow-Origin\s*[:=].{0,40}\*"""),
         "cors-misconfig", "CORS wildcard origin",
         "Access-Control-Allow-Origin: * may be too permissive (CWE-942)", "medium"),
        # Origin reflection without validation
        (re.compile(r"""(?:origin|Origin)\s*(?:=|:)\s*(?:req\.|request\.|headers|ctx\.)"""),
         "cors-misconfig", "CORS origin reflection",
         "Origin header reflected without allowlist validation (CWE-942)", "high"),
        # Null origin explicitly allowed in CORS config (also handles
        # ``setHeader('Access-Control-Allow-Origin', 'null')`` and YAML/JSON forms).
        (re.compile(r"""(?:Access-Control-Allow-Origin|allow_origin|allowed_origins)(?:[^,)]{0,80})?\s*[,:=]\s*['"]null['"]""", re.IGNORECASE),
         "cors-misconfig", "CORS null origin allowed",
         "Null origin allowed in CORS, exploitable via sandboxed iframe (CWE-942)", "high"),
    ]
    return _scan_files(root, cors_exts, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# SQL Injection (template literal / string concat)
# ---------------------------------------------------------------------------

def detect_sql_injection(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect SQL injection via template literals and string concatenation.

    Catches patterns that Semgrep's generic ``auto`` ruleset misses,
    particularly ORM-specific patterns like Sequelize's .query() with
    template literal interpolation.
    """
    js_exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    patterns = [
        # Template literal with SQL keywords + ${} interpolation (JS/TS)
        (re.compile(r"""\.(?:query|execute)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*\$\{""", re.IGNORECASE),
         "sql-injection", "SQL injection via template literal interpolation",
         "SQL keywords with ${} interpolation in query call (CWE-89)", "high"),
        # f-string with SQL keywords (Python) -- backup for rule_generator
        (re.compile(r"""\.(?:query|execute|raw)\s*\(\s*f['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)""", re.IGNORECASE),
         "sql-injection", "SQL injection via f-string",
         "SQL keywords with f-string interpolation in query call (CWE-89)", "high"),
        # String concat with SQL keywords + user input reference
        (re.compile(r"""(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"'`]*["']\s*\+\s*(?:req\.|request\.|params\.|body\.|query\.|args\.)""", re.IGNORECASE),
         "sql-injection", "SQL injection via string concatenation with user input",
         "SQL string concatenated with request input (CWE-89)", "high"),
        # SQL keyword phrase + a separate concat pattern on the same line.
        # Two-stage check via a lookahead to keep the regex robust against
        # nested single quotes (``WHERE id='"+uid+"'``).
        (re.compile(
            r"""(?=.*(?:SELECT\b[^;]{1,400}?\bFROM\b"""
            r"""|INSERT\s+INTO\b"""
            r"""|UPDATE\s+[\w.`"]+\s+SET\b"""
            r"""|DELETE\s+FROM\b))"""
            r""".*["'][^"]{0,40}?["']?\s*\+\s*\w+\s*\+\s*["']?""",
            re.IGNORECASE,
        ),
         "sql-injection", "SQL injection via string concatenation",
         "SQL string built with concatenation (CWE-89)", "medium"),
    ]
    return _scan_files(root, _LANG_EXTENSIONS, patterns, file_index=file_index)


# ---------------------------------------------------------------------------
# SSRF (two-pass: fetch/request with variable from user input)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PHP-Specific Injection Patterns (fallback for Semgrep PHP gaps)
# ---------------------------------------------------------------------------

def detect_php_injection(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect classic PHP injection patterns using superglobal → sink tracing.

    PHP superglobals ($_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES) make
    source-to-sink connections visible even to regex, because the source
    is a distinctive token. This catches what Semgrep's free-tier PHP
    rules miss.
    """
    php_exts = {".php"}
    findings: list[dict[str, Any]] = []

    # PHP user input sources
    src = r"""\$_(GET|POST|REQUEST|COOKIE)\s*\["""

    file_iter = file_index.files_with_suffixes(php_exts) if file_index else root.rglob("*.php")
    for f in file_iter:
        if file_index is None and _is_excluded(f):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(root))
        lines = text.splitlines()

        for i, line in enumerate(lines):
            # --- PHP SQL Injection ---
            # Pattern: "$var" inside SQL string with superglobal nearby
            if re.search(r"""(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\$\w+""", line, re.IGNORECASE):
                # Check if any superglobal is used within 10 lines above
                window = "\n".join(lines[max(0, i - 10):i + 1])
                if re.search(src, window):
                    # Check it's not parameterized
                    if not re.search(r"""(?:prepare|bind_param|bindParam|bindValue|\?\s*,|\?\s*\))""", window):
                        findings.append(_make_finding(
                            "sql-injection",
                            "PHP SQL injection: superglobal in SQL query",
                            rel, i + 1, line.strip()[:200],
                            "PHP superglobal interpolated into SQL string without parameterization (CWE-89)",
                            "high",
                        ))

            # --- PHP Reflected XSS ---
            # Pattern: echo/print/.= with superglobal, no htmlspecialchars
            if re.search(r"""(?:echo|print\b|\.=)""", line):
                if re.search(src, line):
                    if not re.search(r"""(?:htmlspecialchars|htmlentities|htmlEncode|strip_tags|e\()""", line):
                        findings.append(_make_finding(
                            "xss",
                            "PHP reflected XSS: superglobal echoed without encoding",
                            rel, i + 1, line.strip()[:200],
                            "PHP superglobal output without htmlspecialchars/htmlentities (CWE-79)",
                            "high",
                        ))

            # --- PHP File Inclusion (LFI/RFI) ---
            # Pattern: include/require with superglobal
            if re.search(r"""(?:include|require|include_once|require_once)\s*\(?\s*\$""", line):
                window = "\n".join(lines[max(0, i - 5):i + 1])
                if re.search(src, window):
                    findings.append(_make_finding(
                        "path-traversal",
                        "PHP file inclusion with user input (LFI/RFI)",
                        rel, i + 1, line.strip()[:200],
                        "PHP include/require with superglobal enables local/remote file inclusion (CWE-98)",
                        "high",
                    ))

            # --- PHP File Upload (no validation) ---
            if re.search(r"""move_uploaded_file\s*\(""", line):
                window = "\n".join(lines[max(0, i - 10):i + 5])
                if not re.search(r"""(?:mime|type|extension|getimagesize|finfo|in_array|pathinfo)""", window, re.IGNORECASE):
                    findings.append(_make_finding(
                        "file-upload",
                        "PHP file upload without type validation",
                        rel, i + 1, line.strip()[:200],
                        "move_uploaded_file() without MIME/extension validation (CWE-434)",
                        "high",
                    ))

    return findings


def detect_ssrf_two_pass(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect SSRF via variable assignment from user input then HTTP request.

    Single-line regex can't catch patterns like:
        const url = req.body.imageUrl   // line N
        await fetch(url)                 // line N+5

    This does a two-pass analysis: find fetch/request calls with a variable,
    then check if that variable was assigned from user input nearby.
    """
    findings: list[dict[str, Any]] = []
    exts = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".php"}

    # Patterns for HTTP request functions with a variable (not a string literal)
    request_pattern = re.compile(r'(?:fetch|axios\.?\w*|requests?\.\w+|http\.(?:Get|Post)|got|needle|urllib\w*\.?\w*)\s*\(\s*(\w+)\s*[,)]')
    # Patterns for user input assignment
    user_input_pattern = re.compile(r'(?:req\.|request\.|params\.|body\.|query\.|args\.|form\.|GET\[|POST\[)')

    file_iter = file_index.files_with_suffixes(exts) if file_index else root.rglob("*")
    for f in file_iter:
        if file_index is None and (not f.is_file() or f.suffix not in exts or _is_excluded(f)):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue

        rel = str(f.relative_to(root))
        lines = text.splitlines()

        for i, line in enumerate(lines):
            m = request_pattern.search(line)
            if not m:
                continue
            var_name = m.group(1)
            # Skip if the argument is a string literal or common non-user variable
            if var_name in ("url", "uri", "endpoint", "target", "href", "link"):
                # These COULD be user-controlled -- check assignment
                pass
            elif var_name in ("this", "self", "config", "options", "baseUrl", "BASE_URL"):
                continue  # Likely not user-controlled

            # Look backwards up to 15 lines for assignment of this variable from user input
            start = max(0, i - 15)
            context = "\n".join(lines[start:i + 1])
            assign_pattern = re.compile(rf'(?:const|let|var|{var_name})\s+{var_name}\s*=\s*.*{user_input_pattern.pattern}')
            if assign_pattern.search(context):
                findings.append(_make_finding(
                    "ssrf",
                    f"SSRF: user-controlled URL passed to HTTP request",
                    rel, i + 1, line.strip()[:200],
                    f"Variable '{var_name}' assigned from user input and passed to HTTP request function (CWE-918)",
                    "high",
                ))

    return findings


# ---------------------------------------------------------------------------
# CI/CD Pipeline Security
# ---------------------------------------------------------------------------

def detect_cicd_vulns(root: Path) -> list[dict[str, Any]]:
    """Detect CI/CD pipeline security issues."""
    ci_exts = {".yml", ".yaml"}
    findings: list[dict[str, Any]] = []

    # Check GitHub Actions workflows
    gh_dir = root / ".github" / "workflows"
    if gh_dir.is_dir():
        for f in gh_dir.rglob("*.yml"):
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            rel = str(f.relative_to(root))
            for i, line in enumerate(text.splitlines(), 1):
                # Expression injection in workflow
                if re.search(r'\$\{\{\s*github\.event\.\w+\.\w+\.(?:title|body|head_ref)', line):
                    findings.append(_make_finding(
                        "cicd-injection",
                        "GitHub Actions expression injection",
                        rel, i, line.strip()[:200],
                        "Untrusted event data in workflow expression enables command injection",
                        "critical",
                    ))
                # pull_request_target with checkout
                if "pull_request_target" in line:
                    findings.append(_make_finding(
                        "cicd-injection",
                        "pull_request_target trigger (review carefully)",
                        rel, i, line.strip()[:200],
                        "pull_request_target with code checkout runs untrusted PR code in privileged context",
                        "high",
                    ))

    return findings


# ---------------------------------------------------------------------------
# IDOR / Missing Ownership Check
# ---------------------------------------------------------------------------

def detect_missing_ownership_check(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect endpoints that query by req.params.id without ownership validation.

    Pattern: req.params.id → Model.findOne({where: {id}}) → no ENFORCED check
    that the result belongs to the authenticated user.

    Key insight: an ownership "check" only counts if it leads to a REJECTION
    (res.status(401/403), throw, return next(error)).  Code that merely
    observes the mismatch (logging, analytics, CTF scoring) without blocking
    the response is NOT a real authorization check.
    """
    findings: list[dict[str, Any]] = []
    exts = {".js", ".ts", ".tsx", ".jsx", ".py", ".rb", ".go", ".java", ".php"}

    param_id_pattern = re.compile(r'req\.params\.(\w+)')
    db_query_pattern = re.compile(r'(?:findOne|findByPk|findById|findByID|findAll|findOrCreate)\s*\(')

    # A real ownership enforcement must have a DENIAL response
    denial_pattern = re.compile(
        r'(?:res\.status\s*\(\s*(?:401|403|404)\s*\)'
        r'|throw\s+new\s+(?:Error|Unauthorized|Forbidden|HttpException)'
        r'|return\s+next\s*\(\s*(?:new\s+Error|err)'
        r'|raise\s+(?:Unauthorized|Forbidden|PermissionDenied|Http403|Http401)'
        r'|res\.sendStatus\s*\(\s*(?:401|403)\s*\))',
    )

    file_iter = file_index.files_with_suffixes(exts) if file_index else root.rglob("*")
    for f in file_iter:
        if file_index is None and (not f.is_file() or f.suffix not in exts or _is_excluded(f)):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue

        rel = str(f.relative_to(root))
        if any(d in rel for d in ("test", "spec", "mock", "__tests__")):
            continue

        lines = text.splitlines()
        for i, line in enumerate(lines):
            param_match = param_id_pattern.search(line)
            if not param_match:
                continue

            param_name = param_match.group(1)

            # Look for database query using this param within next 5 lines
            window_end = min(len(lines), i + 6)
            query_window = "\n".join(lines[i:window_end])
            if not db_query_pattern.search(query_window):
                continue

            # Check for ENFORCED ownership validation: the key is that
            # a real check must lead to a DENIAL (403, throw, etc).
            # If ownership keywords appear but with no denial, it's just
            # observation (logging, CTF scoring, analytics) not enforcement.
            check_end = min(len(lines), i + 25)
            check_window = "\n".join(lines[i:check_end])

            if denial_pattern.search(check_window):
                continue  # Real authorization enforcement exists

            findings.append(_make_finding(
                "idor",
                f"IDOR: req.params.{param_name} used in DB query without authorization enforcement",
                rel, i + 1, line.strip()[:200],
                f"Resource accessed by req.params.{param_name} without verifying ownership -- "
                f"no 401/403 response or access denial found in handler (CWE-639)",
                "high",
            ))

    return findings


# ---------------------------------------------------------------------------
# Frontend XSS (unsafe DOM bindings)
# ---------------------------------------------------------------------------

def detect_frontend_xss(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect unsafe DOM bindings in frontend templates.

    Scans Angular, React, and Vue templates for patterns that bypass
    framework auto-escaping and render raw HTML from potentially
    user-controlled sources.
    """
    findings: list[dict[str, Any]] = []

    # Angular: [innerHTML]="..." in .html templates
    angular_pattern = re.compile(r'\[innerHTML\]\s*=\s*["\']')
    # Angular: bypassSecurityTrust* in .ts files
    bypass_pattern = re.compile(r'bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)')
    # Vue: v-html directive
    vue_pattern = re.compile(r'\bv-html\s*=\s*["\']')

    # Scan HTML templates
    html_iter = file_index.files_with_suffixes({".html"}) if file_index else root.rglob("*.html")
    for f in html_iter:
        if file_index is None and _is_excluded(f):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(root))
        for i, line in enumerate(text.splitlines(), 1):
            if angular_pattern.search(line):
                findings.append(_make_finding(
                    "xss", "DOM XSS: Angular [innerHTML] binding",
                    rel, i, line.strip()[:200],
                    "Angular [innerHTML] bypasses auto-escaping, may render attacker-controlled HTML (CWE-79)",
                    "medium",
                ))
            if vue_pattern.search(line):
                findings.append(_make_finding(
                    "xss", "DOM XSS: Vue v-html directive",
                    rel, i, line.strip()[:200],
                    "Vue v-html renders raw HTML, may allow XSS if source is user-controlled (CWE-79)",
                    "medium",
                ))

    # Scan TypeScript for Angular bypass
    ts_iter = file_index.files_with_suffixes({".ts"}) if file_index else root.rglob("*.ts")
    for f in ts_iter:
        if file_index is None and _is_excluded(f):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(root))
        for i, line in enumerate(text.splitlines(), 1):
            if bypass_pattern.search(line):
                findings.append(_make_finding(
                    "xss", "DOM XSS: Angular security bypass",
                    rel, i, line.strip()[:200],
                    "bypassSecurityTrust* disables Angular sanitization, may allow XSS (CWE-79)",
                    "high",
                ))

    return findings


# ---------------------------------------------------------------------------
# Stored XSS (user data → DB → unsafe render)
# ---------------------------------------------------------------------------

def detect_stored_xss_risk(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect stored XSS risk: user data saved to DB without sanitization.

    Catches two patterns:
    1. Auto-CRUD frameworks (finale, epilogue, sequelize-restful) that expose
       models with string fields to POST -- req.body goes straight to DB.
    2. Explicit Model.create(req.body) or record.field = req.body.x → save()
       without HTML sanitization.

    These are flagged as stored-xss-risk because the data MAY be rendered
    unsafely in a frontend. Claude analysis determines if it actually is.
    """
    findings: list[dict[str, Any]] = []
    exts = {".js", ".ts", ".tsx", ".jsx", ".py", ".rb", ".php"}

    # Pattern 1: Auto-CRUD frameworks
    auto_crud_pattern = re.compile(
        r'(?:finale|epilogue|sequelize-restful|restful)'
        r'\.(?:resource|initialize|serve)\s*\(',
    )
    # Pattern 2: Model.create with req.body (mass assignment → stored data)
    mass_create_pattern = re.compile(
        r'\.create\s*\(\s*(?:req\.body|request\.body|params|data)\b',
    )
    # Pattern 3: field assignment from req then save
    field_assign_pattern = re.compile(
        r'\.\w+\s*=\s*(?:req\.body|request\.body|req\.file|request\.files)',
    )
    # Pattern 4: File originalname stored without sanitization
    filename_store_pattern = re.compile(
        r'(?:originalname|filename|file\.name)\b',
    )

    file_iter = file_index.files_with_suffixes(exts) if file_index else root.rglob("*")
    for f in file_iter:
        if file_index is None and (not f.is_file() or f.suffix not in exts or _is_excluded(f)):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue

        rel = str(f.relative_to(root))
        lines = text.splitlines()

        # Check for auto-CRUD (affects entire app, flag once per file)
        for i, line in enumerate(lines):
            if auto_crud_pattern.search(line):
                findings.append(_make_finding(
                    "stored-xss-risk",
                    "Auto-CRUD framework stores user input directly to DB",
                    rel, i + 1, line.strip()[:200],
                    "Auto-CRUD (finale/epilogue/restful) writes req.body to DB models without sanitization. "
                    "String fields may contain XSS payloads rendered in admin/UI views (CWE-79)",
                    "medium",
                ))
                break  # One per file

        # Check for mass create with req.body
        for i, line in enumerate(lines):
            if mass_create_pattern.search(line):
                # Check if sanitization exists nearby
                window = "\n".join(lines[max(0, i - 5):i + 1])
                if not re.search(r'(?i)sanitize|escape|encode|purify|clean|xss', window):
                    findings.append(_make_finding(
                        "stored-xss-risk",
                        "Model.create() with unsanitized user input",
                        rel, i + 1, line.strip()[:200],
                        "User input (req.body) stored via Model.create() without HTML sanitization. "
                        "Data may be rendered unsafely in frontend views (CWE-79)",
                        "medium",
                    ))

        # Check for file originalname storage
        for i, line in enumerate(lines):
            if filename_store_pattern.search(line):
                # Check if it's being stored (near a write/create/save/pipe)
                window = "\n".join(lines[max(0, i - 3):min(len(lines), i + 4)])
                if re.search(r'(?:save|create|write|pipe|insert|update|store)', window, re.IGNORECASE):
                    if not re.search(r'(?i)sanitize|escape|basename|secure_filename', window):
                        findings.append(_make_finding(
                            "stored-xss-risk",
                            "User-controlled filename stored without sanitization",
                            rel, i + 1, line.strip()[:200],
                            "File originalname stored to DB/filesystem without sanitization. "
                            "If rendered in UI, enables stored XSS via crafted filename (CWE-79)",
                            "medium",
                        ))

    return findings


# ---------------------------------------------------------------------------
# Mobile payment code contracts
# ---------------------------------------------------------------------------

def _line_for(lines: list[str], pattern: str) -> tuple[int, str]:
    regex = re.compile(pattern)
    for index, line in enumerate(lines, 1):
        if regex.search(line):
            return index, line.strip()[:200]
    return 1, lines[0].strip()[:200] if lines else ""


_PAYMENT_CONTEXT = re.compile(
    r"(?i)(payment|checkout|billing|card|tokeni[sz]e|braintree|stripe|paypal|chase|firstdata|googlepay)"
)
_TOKEN_CONSTRUCTOR = re.compile(
    r"(?i)new\s+(?:[A-Za-z_$][\w$]*Token[A-Za-z_$\w]*|[A-Za-z_$][\w$]*Payment[A-Za-z_$\w]*|mw3)\s*\("
)
# NOTE: `_PAYMENT_ERROR_TYPES` removed — the payment-exception detector
# uses `_EXCEPTION_TO_PAYMENT_ERROR` for the same purpose. The error
# class names this regex would have matched are already implicit in
# the contextual checks.
_SCOPE_CONSTANT = re.compile(r"((?:ExternalPaymentProcessor|PaymentMethodType)\.[A-Z0-9_]+)")
_EXCEPTION_TO_PAYMENT_ERROR = re.compile(
    r"(?is)new\s+[A-Za-z_$][\w$]*(?:TokenizerError|PaymentError|CheckoutError|CardError|BillingError)"
    r"\s*\([^;]*getMessage\s*\("
)


def detect_mobile_payment_code_contracts(root: Path, file_index: FileIndex | None = None) -> list[dict[str, Any]]:
    """Detect high-signal Android/mobile payment trust-boundary code contracts."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java"}) if file_index else root.rglob("*.java")
    for path in files:
        if _is_excluded(path):
            continue
        rel = str(path.relative_to(root))
        path_signal = f"{rel} {path}"
        if not _PAYMENT_CONTEXT.search(path_signal):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()

        if "@JavascriptInterface" in text and _TOKEN_CONSTRUCTOR.search(text):
            line, excerpt = _line_for(lines, r"@JavascriptInterface|new\s+[A-Za-z_$][\w$]*\s*\(")
            findings.append(_make_code_contract_finding(
                "mobile-js-bridge-payment-token",
                "Payment WebView JavaScript bridge constructs native token object from JS-controlled values",
                rel, line, excerpt,
                "A JavaScriptInterface method receives values from WebView JavaScript and constructs a native "
                "payment/token object without visible validation. Trigger condition: JavaScript running in the "
                "payment WebView calls the bridge callback with attacker-chosen token fields.",
                "medium",
                trigger_conditions=[
                    "Reach the payment WebView flow that registers the JavaScriptInterface.",
                    "Execute or influence JavaScript in that WebView context before token construction.",
                ],
                impact=(
                    "Arbitrary bridge values can flow into payment-token construction if WebView script integrity "
                    "or origin isolation fails."
                ),
                validation_steps=[
                    "Confirm whether only app-bundled JS can execute in the WebView.",
                    "Trace bridge arguments into token submission and server-side validation.",
                    "Check WebView settings, loaded URL/data origin, and any addJavascriptInterface exposure.",
                ],
            ))

        if (
            "ExternalPaymentProcessor." in text
            and "PaymentMethodType." in text
            and len({constant.split(".", 1)[0] for constant in _SCOPE_CONSTANT.findall(text)}) >= 2
        ):
            line, excerpt = _line_for(lines, r"PaymentMethodType\.[A-Z0-9_]+|ExternalPaymentProcessor\.[A-Z0-9_]+")
            findings.append(_make_code_contract_finding(
                "payment-client-token-scope-mismatch",
                "Payment client-token request hardcodes processor and payment-method scope",
                rel, line, excerpt,
                "Payment API key/token request code hardcodes both a processor enum and payment-method enum. "
                "Trigger condition: another payment path reuses this client token outside that exact method scope. "
                "The code-level risk is a token-scope mismatch for card, wallet, or device-data flows.",
                "medium",
                trigger_conditions=[
                    "Call a payment flow that obtains its token through this service.",
                    "Compare the requested processor/method scope against downstream card, wallet, or device-data operations.",
                ],
                impact=(
                    "Payment-token or fraud-signal flows may run with the wrong method scope, depending on "
                    "server-side token validation and SDK behavior."
                ),
                validation_steps=[
                    "Trace call sites of the token service into card, wallet, and data collection classes.",
                    "Confirm server response token scope and downstream SDK behavior.",
                    "Verify whether downstream payment operations reject or accept a mismatched-scope token.",
                ],
            ))

        if _EXCEPTION_TO_PAYMENT_ERROR.search(text) and "Exception" in text:
            line, excerpt = _line_for(lines, r"getMessage\(\)|new\s+TokenizerError")
            findings.append(_make_code_contract_finding(
                "payment-exception-message-propagation",
                "Payment exception message is copied into payment error object",
                rel, line, excerpt,
                "Payment error handling copies raw exception messages into payment error objects. Trigger "
                "condition: the payment provider or network stack returns an exception containing sensitive or "
                "internal response details.",
                "low",
                trigger_conditions=[
                    "Force a payment-provider network error whose exception message contains backend detail.",
                    "Trace whether TokenizerError is logged, displayed, or sent to telemetry.",
                ],
                impact="Internal payment/provider details may leak through logs, telemetry, or user-visible errors.",
                validation_steps=[
                    "Inspect downstream TokenizerError consumers.",
                    "Confirm redaction before analytics/logging/UI display.",
                ],
            ))

    return findings


# ---------------------------------------------------------------------------
# Mobile / Android WebView and SDK security
# ---------------------------------------------------------------------------

# Recognise a WebView interpolation context: a StringBuilder/concat that ends
# inside an ``evaluateJavascript`` or ``loadUrl("javascript:")`` call. We look
# for the call signal first, then check the same file for unescaped variable
# splice patterns.
_JS_EVAL_CALL = re.compile(
    r"(?:evaluateJavascript|loadData|loadDataWithBaseURL|loadUrl)\s*\(\s*[\"']?javascript:"
    r"|\.evaluateJavascript\s*\("
)
# NOTE: a broader `_JS_PAYLOAD_LITERAL` regex was deleted —
# detect_webview_js_injection uses three more targeted regexes
# (_JS_SCRIPT_TAG_LITERAL + _JS_VAR_DECLARATION + _JS_INTERPOLATION_SPLIT)
# that produce fewer false positives than this all-in-one pattern.
# NOTE: A `_REMOTE_CONFIG_URL_SETTER` regex was deleted as redundant —
# the `_REMOTE_CONFIG_URL_GET`-based detector below already catches the
# same shape from the source side (key/value pulled from config that
# later flows to an HTTP request). Keeping both would double-report
# every remote-config endpoint pattern.
_REMOTE_CONFIG_URL_GET = re.compile(
    r"""\.(?:getString|optString)\s*\(\s*["'](?:[A-Z_]+URL|[A-Z_]+ENDPOINT|[A-Z_]+HOST|[a-z_]+_url|[a-z_]+_endpoint)["']"""
)
_HTTP_NEW_REQUEST = re.compile(
    r"(?:Request\.Builder|HttpURLConnection|OkHttpClient|Retrofit|new\s+URL|URI\.create"
    r"|HttpGet|HttpPost|CoroutineCallFactory|Call\.Factory|RestClient|ApolloClient"
    r"|RetrofitClient|HttpClient|RestTemplate|Volley|WebSocketFactory)"
)
_NETWORK_SECURITY_CONFIG_PIN = re.compile(r"<pin\s+digest=")
_NETWORK_SECURITY_CONFIG_DOMAIN = re.compile(r"<domain[^>]*>([^<]+)</domain>")
_EXPORTED_COMPONENT = re.compile(
    r"<(activity|service|receiver|provider)\b[^>]*android:exported\s*=\s*[\"']true[\"']",
    re.IGNORECASE,
)
_HAS_PERMISSION = re.compile(
    r"android:(?:permission|readPermission|writePermission)\s*=\s*[\"']", re.IGNORECASE
)
# NOTE: `_INTENT_FILTER` and `_SCHEME_DEEPLINK` regexes were deleted —
# the current intent-filter / deeplink detection walks XML structurally
# via `_read_exported_component_declaration` rather than scanning by
# regex line-by-line. Those helpers were leftovers from an earlier
# line-scanning design.
_WEBVIEW_JS_ENABLED = re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)")
_WEBVIEW_FILE_ACCESS = re.compile(
    r"(?:setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)"
    r"\s*\(\s*true\s*\)"
)
_WEBVIEW_JS_INTERFACE = re.compile(r"addJavascriptInterface\s*\(")
_HARDCODED_SECRET = re.compile(
    # AKIA / ASIA AWS Access Key IDs (20 chars total)
    r"(?:AKIA|ASIA)[A-Z0-9]{16}"
    # Stripe live + test + restricted keys (16+ char body)
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"
    # GitHub Personal/OAuth/User/Server/Refresh tokens (36 char body)
    r"|gh[pousr]_[A-Za-z0-9]{36}"
    # GitHub fine-grained PATs (variable length, includes underscores)
    r"|github_pat_[A-Za-z0-9_]{22,255}"
    # Slack legacy tokens (xoxb / xoxp / xoxa / xoxr / xoxs)
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
)
_RSA_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
_INTENT_REDIRECT = re.compile(
    r"startActivity\s*\(\s*(?:[a-zA-Z_$][\w$]*\.)?getParcelableExtra\s*\("
    r"|Intent\s*\.\s*parseUri\s*\("
)
_PENDING_INTENT_MUTABLE = re.compile(
    r"PendingIntent\.(?:getActivity|getService|getBroadcast)\s*\([^)]*FLAG_MUTABLE"
)
# NOTE: a `_DEBUG_FLAG` regex matching BuildConfig.DEBUG references was
# deleted as misconceived — code that's gated by `if (BuildConfig.DEBUG)`
# is the SAFE pattern (insecure stuff only runs in debug builds). The
# manifest `android:debuggable="true"` half is already detected by
# detect_android_manifest_issues — that path is the actual vuln signal.
_HTTP_SCHEME = re.compile(r"(?<![A-Za-z])http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.)")
_TRUST_ALL = re.compile(
    # Empty body: `{ }`, `{\n}`, or `{ // comment(s) only }` — i.e. no
    # statement before the closing brace. `[^}]*?` is non-greedy so we
    # only match if the next non-comment content IS the close.
    r"checkServerTrusted\s*\([^)]*\)\s*\{(?:\s*|/\*[^*]*\*/|//[^\n]*\n)*\}"
    r"|X509TrustManager\s*\([^)]*\)\s*\{[^}]*return\s+new\s+X509Certificate\s*\[\s*0\s*\]"
    r"|setHostnameVerifier\s*\(\s*(?:ALLOW_ALL_HOSTNAME_VERIFIER|new\s+HostnameVerifier\s*\(\s*\)\s*\{[^}]*return\s+true)"
)


_JS_SCRIPT_TAG_LITERAL = re.compile(r"""["']<\s*script\b""", re.IGNORECASE)
_JS_VAR_DECLARATION = re.compile(r"""["']\s*var\s+[A-Za-z_$][\w$]*\s*=""")
_JS_INTERPOLATION_SPLIT = re.compile(
    # "...":var x = " followed by a Java/Kotlin identifier and then more JS literal,
    # signalling "build a JS string by concatenating native values into JS code".
    r"""["'][^"']{0,40}["']\s*,\s*[A-Za-z_$][\w$]*\s*,\s*["']"""
)
_WEBVIEW_CONTEXT = re.compile(
    r"\bWebView\b|@JavascriptInterface|evaluateJavascript|loadUrl|loadData|setJavaScriptEnabled"
)


def detect_webview_js_injection(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect Android WebView JS injection: native values spliced into a JS literal.

    Many mobile tokenization flows (iframe-shim card encryption SDKs, custom
    card tokenizers, PIE-style flows) build a ``<script>`` block in Java/Kotlin
    via StringBuilder and dispatch it to a WebView elsewhere (often through a
    coroutine helper in a sibling file). Anchoring on the JS literal
    construction is more robust than requiring ``evaluateJavascript`` in the
    same compilation unit because jadx output frequently splits coroutine
    launchers into anonymous inner-class files.
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        has_script = bool(_JS_SCRIPT_TAG_LITERAL.search(text))
        has_var_decl = bool(_JS_VAR_DECLARATION.search(text))
        has_split = bool(_JS_INTERPOLATION_SPLIT.search(text))
        has_eval = bool(_JS_EVAL_CALL.search(text))
        has_wv_context = bool(_WEBVIEW_CONTEXT.search(text))
        # We need the file to be assembling a JS payload (script tag or var decl)
        # AND splicing native variables into it (the comma-split pattern), OR an
        # eval call sitting right next to the literal in the same file.
        if not (has_script or has_var_decl):
            continue
        if not (has_split or has_eval):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"\"\s*<\s*script|\"var\s+\w+\s*=|evaluateJavascript|loadUrl")
        rel = str(path.relative_to(root))
        severity = "high" if has_split else "medium"
        # Confidence signal: a file that assembles a JS literal AND references
        # a WebView (or contains an explicit evaluateJavascript / loadUrl
        # call) is high-confidence dispatch. Without either, we're seeing a
        # JS-construction helper whose dispatch site lives elsewhere — still
        # worth surfacing but at lower severity and as a hotspot, not a
        # finding. Confidence is reported via the `confidence` metadata
        # field rather than baked into the human title (the title was
        # carrying an awkward parenthetical that made downstream tooling
        # hard to dedupe).
        confidence = "high"
        if not has_wv_context and not has_eval:
            confidence = "low"
            severity = "medium"
        findings.append(_make_code_contract_finding(
            "mobile-webview-js-injection",
            "JS payload assembled from native values (likely WebView dispatch)",
            rel, line, excerpt,
            "Java/Kotlin code constructs a JavaScript payload — a <script> tag or `var X = …` "
            "declaration — by interleaving native values between JS string literals. If any "
            "spliced value reaches this point unescaped from a network or intent source, the "
            "attacker breaks out of the JS literal and executes arbitrary JS in the eventual "
            "WebView context (CWE-94 / CWE-79). Most mobile card-tokenization SDKs "
            "(iframe shims, custom in-WebView encryptors) follow this exact shape — confirm "
            "the dispatch site and verify each spliced field is escaped or originates from "
            "app-bundled data.",
            severity,
            trigger_conditions=[
                "Attacker can influence one of the native values that are spliced into the JS literal.",
                "The JS payload is eventually passed to evaluateJavascript, loadUrl(\"javascript:\"), or loadData.",
                "The WebView used to dispatch has setJavaScriptEnabled(true) or a JavascriptInterface bridge.",
            ],
            impact=(
                "Arbitrary JavaScript executes inside the WebView with access to any "
                "@JavascriptInterface methods and to PII (PAN/CVV/JWT/etc.) that the same payload "
                "happens to be interpolating."
            ),
            validation_steps=[
                "Identify which class hands this payload to a WebView (often in the same package, "
                "frequently a `*$executeJavascriptCoroutine*` inner class in jadx output).",
                "Trace each spliced native value to its origin (network response, intent extra, config).",
                "Check cert pinning for any remote source of those values (network_security_config.xml).",
                "Audit @JavascriptInterface surface that the WebView exposes.",
            ],
            confidence=confidence,
        ))
    return findings


def detect_webview_unsafe_config(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect WebViews configured with file-access or JS-interface footguns."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _WEBVIEW_JS_ENABLED.search(text):
            continue
        lines = text.splitlines()
        rel = str(path.relative_to(root))
        if _WEBVIEW_FILE_ACCESS.search(text):
            line, excerpt = _line_for(lines, r"setAllow(?:File|Universal)")
            findings.append(_make_finding(
                "mobile-webview-file-access",
                "WebView grants file/universal access while JavaScript is enabled",
                rel, line, excerpt,
                "WebView enables JavaScript and also setAllowFileAccess(true) or "
                "setAllowUniversalAccessFromFileURLs(true). A loaded file:// or attacker-"
                "controlled HTML can read arbitrary app files / cross-origin resources. (CWE-200)",
                "high", "finding",
            ))
        if _WEBVIEW_JS_INTERFACE.search(text):
            line, excerpt = _line_for(lines, r"addJavascriptInterface")
            findings.append(_make_finding(
                "mobile-webview-js-interface",
                "WebView exposes a @JavascriptInterface bridge with JavaScript enabled",
                rel, line, excerpt,
                "addJavascriptInterface combined with setJavaScriptEnabled(true) creates a "
                "native bridge any in-WebView JS can call. Combined with any JS injection or "
                "compromised remote content, this allows native API access. (CWE-749)",
                "medium", "hotspot",
            ))
        if re.search(r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)", text):
            lines2 = text.splitlines()
            line2, excerpt2 = _line_for(lines2, r"setWebContentsDebuggingEnabled")
            findings.append(_make_finding(
                "mobile-webview-debug-enabled",
                "WebView debugging enabled (chrome://inspect attaches)",
                rel, line2, excerpt2,
                "setWebContentsDebuggingEnabled(true) lets any debuggable companion process "
                "attach to the WebView via chrome://inspect and read/inject scripts. Must not "
                "ship in release builds — gate behind BuildConfig.DEBUG. (CWE-489)",
                "medium", "finding",
            ))
    return findings


_SERVICE_PACKAGE_HINT = re.compile(
    r"/services?/|/api/|/network/|/http/|/rest/|/client/|/repository/|/tokeni[sz]"
)


def detect_remote_controlled_url(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect endpoints whose URL is read from remote config and then used in HTTP.

    Mirrors the remote-controlled-URL pattern common to payment tokenization
    flows: the endpoint URL is fetched from a remote config / strategy
    response (``getString("FOO_URL", ...)``) and handed off to a network
    call. Combined with weak transport pinning this is a redirection-and-
    exfiltration primitive.

    The HTTP-context signal is broad (OkHttp/Retrofit/Apollo/Volley/custom
    `CoroutineCallFactory` wrappers) and we still fall back to a path-based
    hint when the file lives in a `services/` or `api/` package — those almost
    always dispatch over the network somewhere in the call graph.
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _REMOTE_CONFIG_URL_GET.search(text):
            continue
        rel = str(path.relative_to(root))
        has_http = bool(_HTTP_NEW_REQUEST.search(text))
        has_service_pkg = bool(_SERVICE_PACKAGE_HINT.search("/" + rel))
        if not (has_http or has_service_pkg):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"\.(?:getString|optString)\s*\([^)]*URL")
        severity = "high" if has_http else "medium"
        findings.append(_make_code_contract_finding(
            "mobile-remote-controlled-endpoint",
            "Network endpoint URL is sourced from remote config and then dispatched",
            rel, line, excerpt,
            "The same Java/Kotlin file pulls a URL/endpoint string from a config store "
            "(getString/optString of a *_URL key) and constructs an HTTP request. If the "
            "config feed is server-controlled and the connection is not pinned, an attacker "
            "who tampers with or impersonates the config service can redirect requests "
            "(including payment, tokenization, or auth flows) to an attacker-owned host. "
            "(CWE-610, CWE-441)",
            severity,
            trigger_conditions=[
                "Config feed delivering the URL is reachable by an attacker (MITM or server compromise).",
                "No certificate pinning / response signing on the URL once dispatched.",
            ],
            impact=(
                "Sensitive data (cards, tokens, tracking IDs) can be redirected to an attacker "
                "endpoint that mimics the legitimate API."
            ),
            validation_steps=[
                "Trace the config key to determine which backend supplies the value.",
                "Check network_security_config.xml for pin entries covering the dispatched host.",
                "Confirm whether response integrity (signatures/JWS) is verified before use.",
            ],
        ))
    return findings


def _collect_app_hosts(root: Path, file_index: FileIndex | None) -> list[str]:
    """Scan Java/Kotlin sources for hosts the app actually reaches.

    Returns a deduplicated list of `host` strings parsed from `https://host`
    or `http://host` literals so the NSC report can cite which API hosts
    the app uses *but doesn't pin*.
    """
    hosts: set[str] = set()
    url_re = re.compile(r"""["']https?://([a-zA-Z0-9.\-]+)""")
    if file_index:
        java_files = list(file_index.files_with_suffixes({".java", ".kt"}))
    else:
        java_files = [p for p in root.rglob("*") if p.suffix in {".java", ".kt"}]
    for p in java_files[:5000]:  # bound search; ~5k decompiled .java is plenty
        if _is_excluded(p):
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for h in url_re.findall(text):
            if "." in h and "%" not in h:
                hosts.add(h)
    return sorted(hosts)


def detect_network_security_config_gaps(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Inspect AndroidManifest + network_security_config for pinning gaps.

    When narrow pinning is detected, this also enumerates hosts that the
    Java/Kotlin code actually contacts but that aren't covered by the
    pin-set — turning "pins only X" into an actionable "pins only X, but
    code talks to Y, Z, W" finding.
    """
    findings: list[dict[str, Any]] = []
    cfg_paths: list[Path] = []
    if file_index:
        cfg_paths = list(file_index.files_with_suffixes({".xml"}))
    else:
        cfg_paths = list(root.rglob("*.xml"))
    nsc_found = False
    for path in cfg_paths:
        if _is_excluded(path):
            continue
        name = path.name.lower()
        if "network_security_config" not in name and name != "network_security_config.xml":
            continue
        nsc_found = True
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        pinned_domains = _NETWORK_SECURITY_CONFIG_DOMAIN.findall(text) if _NETWORK_SECURITY_CONFIG_PIN.search(text) else []
        rel = str(path.relative_to(root))
        if not _NETWORK_SECURITY_CONFIG_PIN.search(text):
            findings.append(_make_finding(
                "mobile-nsc-no-pinning",
                "network_security_config.xml has no <pin> entries",
                rel, 1, text.splitlines()[0][:200] if text else "",
                "Android network_security_config has no <pin-set> declarations. All HTTPS "
                "traffic relies on system CA trust, so any compromised intermediate CA or "
                "user-installed root can MITM API responses (config feeds, payment, auth). "
                "(CWE-295)",
                "medium", "finding",
            ))
        elif pinned_domains:
            # Enumerate hosts the app code actually talks to that aren't covered.
            app_hosts = _collect_app_hosts(root, file_index)
            unpinned = [
                h for h in app_hosts
                if not any(pd == h or h.endswith("." + pd) for pd in pinned_domains)
            ]
            unpinned_summary = ""
            if unpinned:
                unpinned_summary = (
                    f" App code references {len(unpinned)} other host(s) "
                    f"(sample: {', '.join(unpinned[:5])}) that fall back to system CA trust."
                )
            findings.append(_make_finding(
                "mobile-nsc-narrow-pinning",
                f"network_security_config pins only: {', '.join(pinned_domains[:5])}",
                rel, 1, ", ".join(pinned_domains[:5])[:200],
                "Pinning is configured but only covers the listed domains. Other API hosts "
                "(payment processors, identity, config) still rely on system CA trust. Audit "
                f"whether tokenization and auth flows are inside the pinned set. (CWE-295){unpinned_summary}",
                "low", "hotspot",
            ))
        if 'cleartextTrafficPermitted="true"' in text:
            findings.append(_make_finding(
                "mobile-nsc-cleartext",
                "network_security_config permits cleartext traffic",
                rel, 1, "cleartextTrafficPermitted=true",
                "cleartextTrafficPermitted=true allows plaintext HTTP traffic, exposing any "
                "URL fetched without https to passive interception. (CWE-319)",
                "high", "finding",
            ))
    return findings


_COMPONENT_NAME = re.compile(r"""android:name\s*=\s*["']([^"']+)["']""")
_INTENT_SCHEME = re.compile(r"""android:scheme\s*=\s*["']([^"']+)["']""")
_INTENT_HOST = re.compile(r"""android:host\s*=\s*["']([^"']+)["']""")
_INTENT_PATH_PREFIX = re.compile(r"""android:pathPrefix\s*=\s*["']([^"']+)["']""")
_INTENT_PATH_PATTERN = re.compile(r"""android:pathPattern\s*=\s*["']([^"']+)["']""")


def _read_exported_component_declaration(
    lines: list[str], start_idx: int
) -> tuple[str, dict[str, Any]]:
    """Return (declaration_text, metadata) for an exported component declaration.

    ``start_idx`` is 0-based and points at the line containing the opening tag
    (e.g. ``<activity ... android:exported="true">``).

    The declaration ends when we see the wrapper element's matching close tag
    (``</activity>``, ``</service>``, etc.) — or, if the opening tag itself
    ends with ``/>``, immediately. Nested self-closes (``<data .../>``,
    ``<action .../>``) are intentionally *not* treated as terminators.
    """
    if start_idx >= len(lines):
        return "", {}
    first = lines[start_idx]
    wrapper_match = re.search(
        r"<(activity|service|receiver|provider)\b", first, re.IGNORECASE
    )
    wrapper = wrapper_match.group(1).lower() if wrapper_match else None
    close_tag = f"</{wrapper}>" if wrapper else None
    declaration = [first]
    closed = False
    # Self-closed wrapper: `<activity ... />` on a single line, no children.
    # We have to be careful not to mis-detect `<data .../>` inside the same
    # line — but a self-closed <activity ...> tag ends with `/>` AFTER all of
    # its attributes and AT END OF LINE (modulo trailing whitespace).
    if re.search(r"/>\s*$", first):
        return "\n".join(declaration), _extract_component_meta("\n".join(declaration), True)
    j = start_idx + 1
    while j < len(lines) and j < start_idx + 200:
        declaration.append(lines[j])
        if close_tag and close_tag in lines[j].lower():
            closed = True
            break
        j += 1
    body = "\n".join(declaration)
    return body, _extract_component_meta(body, closed)


def _extract_component_meta(body: str, closed: bool) -> dict[str, Any]:
    meta: dict[str, Any] = {"body_closed": closed}
    name_m = _COMPONENT_NAME.search(body)
    if name_m:
        meta["component_name"] = name_m.group(1)
    schemes = _INTENT_SCHEME.findall(body)
    if schemes:
        meta["intent_schemes"] = sorted(set(schemes))
    hosts = _INTENT_HOST.findall(body)
    if hosts:
        meta["intent_hosts"] = sorted(set(hosts))
    paths = _INTENT_PATH_PREFIX.findall(body) + _INTENT_PATH_PATTERN.findall(body)
    if paths:
        meta["intent_paths"] = sorted(set(paths))
    return meta


def detect_android_manifest_issues(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Surface exported components without permissions and debuggable builds."""
    findings: list[dict[str, Any]] = []
    cfg_paths = list(file_index.files_with_suffixes({".xml"})) if file_index else list(root.rglob("*.xml"))
    for path in cfg_paths:
        if _is_excluded(path):
            continue
        if path.name != "AndroidManifest.xml":
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        lines = text.splitlines()
        # Exported components with no permission attribute
        for i, line in enumerate(lines, 1):
            m = _EXPORTED_COMPONENT.search(line)
            if not m:
                continue
            body, meta = _read_exported_component_declaration(lines, i - 1)
            if _HAS_PERMISSION.search(body):
                continue
            kind = m.group(1).lower()
            name = meta.get("component_name") or "(unnamed)"
            # Skip framework-provided debug tooling that gets shipped when the
            # dev forgot to strip compose-tooling from the release variant.
            # The developer can't fix this from app code, only by removing
            # the dependency from the release build.
            if name in _FRAMEWORK_DEBUG_EXPORTED:
                continue
            schemes = meta.get("intent_schemes") or []
            hosts = meta.get("intent_hosts") or []
            paths = meta.get("intent_paths") or []
            # Compose a much more actionable title than the previous "Exported activity ..."
            # Cap the snippet to the first few entries to keep titles readable;
            # full lists live in `metadata` for downstream tooling.
            def _trim(items: list[str], n: int = 3) -> str:
                if not items:
                    return ""
                head = ",".join(items[:n])
                tail = "" if len(items) <= n else f" (+{len(items) - n} more)"
                return head + tail
            title_extra = ""
            if schemes:
                title_extra = f" handling deeplink scheme(s) {_trim(schemes)}"
                if hosts:
                    title_extra += f" on host(s) {_trim(hosts)}"
            elif hosts:
                title_extra = f" on host(s) {_trim(hosts)}"
            msg_extra = ""
            if schemes:
                msg_extra = (
                    f" Component handles deeplink scheme(s) {','.join(schemes)}"
                    + (f" on host(s) {','.join(hosts)}" if hosts else "")
                    + (f" with path(s) {','.join(paths)}" if paths else "")
                    + ". Any installed app (or any web page if scheme is http/https) can dispatch intents into it."
                )
            # Severity reflects realistic exploit reachability:
            #  - Exported activity with a custom-scheme deeplink → high
            #    (web pages can dispatch via Browser/Intent.parseUri).
            #  - Exported activity with an http/https-only filter → medium
            #    (gated by Android App Links / digital asset verification).
            #  - Exported service/receiver/provider without filter → medium
            #    (still reachable via explicit Intent from any installed app).
            #  - Exported activity with NO intent-filter at all → low
            #    (reachable only via explicit Intent, often by accident).
            has_custom_scheme = any(
                s.lower() not in {"http", "https"} for s in schemes
            )
            if has_custom_scheme:
                ec_severity = "high"
            elif schemes:
                ec_severity = "medium"
            elif kind == "activity":
                ec_severity = "low"
            else:
                ec_severity = "medium"
            findings.append(_make_finding(
                "mobile-exported-component-no-permission",
                f"Exported {kind} `{name}` without a permission guard{title_extra}",
                rel, i, line.strip()[:200],
                f"AndroidManifest declares an exported <{kind}> with no android:permission. "
                "Any installed app can interact with it. Re-check what intents/data this "
                f"component accepts.{msg_extra} (CWE-926)",
                ec_severity, "hotspot",
                metadata={
                    "component_name": meta.get("component_name"),
                    "component_kind": kind,
                    "intent_schemes": schemes,
                    "intent_hosts": hosts,
                    "intent_paths": paths,
                },
            ))
            # If the component handles custom-scheme deeplinks AND has no host
            # restrictions, surface a separate higher-signal finding: any web
            # page can launch the deeplink and the activity has to defensively
            # reject untrusted data on every code path.
            if schemes and not hosts and not paths and any(
                s.lower() not in {"http", "https"} for s in schemes
            ):
                findings.append(_make_finding(
                    "mobile-deeplink-unrestricted",
                    f"Custom-scheme deeplink {','.join(schemes)} on `{name}` has no host or path restriction",
                    rel, i, line.strip()[:200],
                    "An exported activity handles a custom-scheme deeplink with no "
                    f"`android:host` or `android:pathPrefix/pathPattern` filter. Any other "
                    "app — and, with browser intent dispatch, any web page — can launch "
                    "this activity with attacker-controlled URI data. Confirm the activity "
                    "treats deeplink parameters as untrusted input on every code path "
                    "(no implicit redirect, no eval, no automatic auth). (CWE-939)",
                    "medium", "finding",
                    metadata={
                        "component_name": meta.get("component_name"),
                        "intent_schemes": schemes,
                    },
                ))
        # Debuggable production build
        for i, line in enumerate(lines, 1):
            if 'android:debuggable="true"' in line:
                findings.append(_make_finding(
                    "mobile-debuggable-build",
                    "AndroidManifest sets android:debuggable=true",
                    rel, i, line.strip()[:200],
                    "android:debuggable=true exposes JDWP attach surface and full app process "
                    "inspection to anyone with adb access. Should never appear in a release. (CWE-489)",
                    "high", "finding",
                ))
    return findings


def detect_insecure_tls(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect trust-all TLS managers / blanket hostname verifiers."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _TRUST_ALL.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"checkServerTrusted|setHostnameVerifier|X509Certificate\s*\[\s*0\s*\]")
        rel = str(path.relative_to(root))
        findings.append(_make_finding(
            "mobile-insecure-tls",
            "Insecure TLS: empty checkServerTrusted / always-true hostname verifier",
            rel, line, excerpt,
            "X509TrustManager.checkServerTrusted is empty or the hostname verifier always "
            "returns true. Any HTTPS endpoint reached through this trust manager accepts "
            "arbitrary certificates, defeating transport security. (CWE-295)",
            "critical", "finding",
        ))
    return findings


def detect_hardcoded_secrets_simple(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Surface high-confidence credential patterns embedded in source.

    Intentionally narrow — only AWS keys, Stripe live keys, GitHub PATs,
    Slack tokens, and PEM private keys. Pair with the broader secret-scanner
    pipeline for full coverage.
    """
    findings: list[dict[str, Any]] = []
    exts = {".java", ".kt", ".py", ".js", ".ts", ".tsx", ".jsx", ".go",
            ".rb", ".php", ".cs", ".rs", ".properties", ".env", ".yaml", ".yml"}
    files = file_index.files_with_suffixes(exts) if file_index else (
        p for p in root.rglob("*") if p.suffix in exts
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for i, line in enumerate(text.splitlines(), 1):
            if _HARDCODED_SECRET.search(line):
                findings.append(_make_finding(
                    "secret-hardcoded",
                    "Hardcoded credential pattern detected",
                    rel, i, line.strip()[:200],
                    "A high-confidence secret pattern (cloud key / payment provider live key / "
                    "git or chat platform token) is hardcoded in source. Rotate and migrate to "
                    "a secrets manager. (CWE-798)",
                    "critical", "finding",
                ))
            elif _RSA_PRIVATE_KEY.search(line):
                findings.append(_make_finding(
                    "secret-private-key",
                    "Embedded private key material",
                    rel, i, line.strip()[:200],
                    "A PEM private key block is embedded in source. Anything signed or decrypted "
                    "with this material can be impersonated by anyone with access to the APK or "
                    "repo. (CWE-321)",
                    "critical", "finding",
                ))
    return findings


def detect_mobile_intent_redirection(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect Intent.parseUri / startActivity with externally-supplied Intent.

    Classic Android Intent Redirection: an Activity reads an Intent from an
    extra it does not own and re-launches it, gaining access to its caller's
    permissions (StrandHogg / Pulse-style).
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _INTENT_REDIRECT.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"startActivity\s*\(|Intent\.parseUri")
        rel = str(path.relative_to(root))
        findings.append(_make_finding(
            "mobile-intent-redirection",
            "Activity re-launches an externally provided Intent",
            rel, line, excerpt,
            "The Activity unpacks an Intent from a Parcelable extra (or Intent.parseUri) and "
            "calls startActivity on it. Combined with an exported component, this becomes a "
            "permission-relay primitive — a malicious caller can trampoline through the app "
            "to reach permissions/components it could not otherwise. (CWE-940)",
            "high", "finding",
        ))
    return findings


def detect_hardcoded_http_url(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect hardcoded `http://` URLs in app code.

    Distinct from `mobile-cleartext-traffic-allowed` (manifest flag):
    this hotspots specific code locations that bypass HTTPS even when
    the manifest enforces cleartext traffic disabled. localhost /
    private-network addresses are intentionally allowed (developer
    debug servers, lan-only IoT endpoints).
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes(
        {".java", ".kt", ".swift", ".m", ".mm"}
    ) if file_index else (
        p for p in root.rglob("*")
        if p.suffix in {".java", ".kt", ".swift", ".m", ".mm"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _HTTP_SCHEME.search(line):
                rel = str(path.relative_to(root))
                findings.append(_make_finding(
                    "mobile-hardcoded-http-url",
                    "Hardcoded http:// URL in app code",
                    rel, i, line.strip()[:200],
                    "Hardcoded plain-HTTP URL in app code routes the request through "
                    "cleartext regardless of the network_security_config / "
                    "usesCleartextTraffic settings. localhost / 127.0.0.1 / private "
                    "RFC1918 ranges are exempt — those are debug or LAN-only paths. "
                    "Replace with https:// or wire the URL through the pinned client. "
                    "(CWE-319)",
                    "medium", "hotspot",
                ))
    return findings


def detect_task_affinity_abuse(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect StrandHogg-style task-affinity hijacking surface.

    An activity declared with `launchMode="singleTask"` AND a custom
    `taskAffinity` lets a malicious app place itself into the same
    task stack and intercept Intent dispatches (the StrandHogg / 2017
    "task hijacking" class). Either attribute alone is sometimes
    legitimate; the combination is rarely required and is the
    fingerprint of the vulnerable pattern.
    """
    findings: list[dict[str, Any]] = []
    cfg_paths = list(file_index.files_with_suffixes({".xml"})) if file_index else list(root.rglob("*.xml"))
    for path in cfg_paths:
        if _is_excluded(path):
            continue
        if path.name != "AndroidManifest.xml":
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for i, line in enumerate(text.splitlines(), 1):
            if _TASK_AFFINITY_ABUSE.search(line):
                findings.append(_make_finding(
                    "mobile-task-affinity-hijack",
                    "Activity uses launchMode=singleTask with a custom taskAffinity",
                    rel, i, line.strip()[:200],
                    "The combination of `launchMode=\"singleTask\"` and a non-default "
                    "`taskAffinity` is the StrandHogg task-hijacking fingerprint. A "
                    "malicious app declaring the same taskAffinity can plant itself "
                    "in the host task stack and either capture intents or display a "
                    "spoofed UI on top of the host's task switcher entry. (CWE-926)",
                    "medium", "hotspot",
                ))
    return findings


def detect_dynamic_receiver_no_perm(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect runtime `registerReceiver(receiver, filter)` without a permission arg.

    The 2-arg form of `registerReceiver` registers a broadcast receiver
    exported to every installed app — Android 13+ requires either
    `RECEIVER_NOT_EXPORTED` or a permission arg. Pre-Android-13 the 2-arg
    form is the default and is a common ipc leak.
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        # Skip files that explicitly pass RECEIVER_NOT_EXPORTED or a
        # permission — those are the safe forms.
        if "RECEIVER_NOT_EXPORTED" in text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _DYNAMIC_REGISTRATION_NO_PERM.search(line):
                rel = str(path.relative_to(root))
                findings.append(_make_finding(
                    "mobile-dynamic-receiver-unprotected",
                    "registerReceiver(receiver, filter) without permission / RECEIVER_NOT_EXPORTED",
                    rel, i, line.strip()[:200],
                    "Two-arg `registerReceiver(receiver, filter)` registers the receiver "
                    "as exported on Android <=12 (default behaviour) and Android 13+ "
                    "without explicit RECEIVER_NOT_EXPORTED. Any installed app can send "
                    "broadcasts matching the filter — a classic IPC information-leak / "
                    "command-injection vector. Pass `Context.RECEIVER_NOT_EXPORTED` (API "
                    "33+) or a `signature`-level permission. (CWE-925)",
                    "medium", "hotspot",
                ))
    return findings


def detect_tapjacking_disabled(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect `setFilterTouchesWhenObscured(false)`.

    setFilterTouchesWhenObscured(true) is Android's defense against
    tapjacking — an attacker overlays a transparent UI over the
    victim app to capture taps and route them as if the user
    consented. Explicitly setting it to `false` (the default for
    pre-1.5 apps) opens the activity to overlay attacks.
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _TAPJACKING_FLAG.search(line):
                rel = str(path.relative_to(root))
                findings.append(_make_finding(
                    "mobile-tapjacking-disabled",
                    "View opts out of tapjacking protection (setFilterTouchesWhenObscured(false))",
                    rel, i, line.strip()[:200],
                    "Explicitly disabling filterTouchesWhenObscured leaves the view "
                    "vulnerable to overlay-based tap injection. An attacker app drawing "
                    "a transparent overlay can capture taps and route them as if the "
                    "user consented to the underlying action (consent dialog, payment "
                    "confirm, biometric prompt). (CWE-1021)",
                    "medium", "hotspot",
                ))
    return findings


def detect_pendingintent_mutable(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect FLAG_MUTABLE PendingIntents (Android 12+ guidance violation)."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _PENDING_INTENT_MUTABLE.search(line):
                rel = str(path.relative_to(root))
                findings.append(_make_finding(
                    "mobile-pendingintent-mutable",
                    "PendingIntent created with FLAG_MUTABLE",
                    rel, i, line.strip()[:200],
                    "FLAG_MUTABLE allows the receiving component to fill in unset fields and "
                    "redirect the embedded Intent. Use FLAG_IMMUTABLE unless mutation is "
                    "intentional. (CWE-925)",
                    "medium", "hotspot",
                ))
    return findings


# ---------------------------------------------------------------------------
# Mobile crypto / storage / deeplink
# ---------------------------------------------------------------------------

_CIPHER_INSECURE = re.compile(
    # Cipher.getInstance("AES") -> defaults to ECB, with no padding spec.
    # Also flag explicit ECB, DES, RC4, MD5, SHA1 (legacy/broken).
    r"""Cipher\.getInstance\s*\(\s*["'](?:AES|DES|3DES|RC4)["']"""
    r"""|Cipher\.getInstance\s*\(\s*["'][^"']*ECB[^"']*["']"""
    r"""|MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']"""
    r"""|Mac\.getInstance\s*\(\s*["'](?:HmacMD5|HmacSHA1)["']"""
)
_INSECURE_RANDOM = re.compile(
    # Math.random() / new Random() used in a security-looking context
    r"""(?:new\s+Random\s*\(\s*\)|Math\.random\s*\(\s*\))"""
)
_SECURITY_CONTEXT_HINT = re.compile(
    r"(?i)(token|nonce|salt|iv|key|secret|password|otp|seed)"
)
_SHARED_PREFS_SENSITIVE = re.compile(
    # SharedPreferences put-with-sensitive-keyname (plain SharedPreferences is plaintext)
    r"""(?:edit\(\)|getSharedPreferences[^)]*\))[\s\S]{0,200}?\.put(?:String|StringSet)\s*\("""
    r"""\s*["'](?i:[a-z_.\-]*(?:token|password|secret|jwt|api_?key|auth|credential|pin|cvv|pan)[a-z_.\-]*)["']"""
)
# Captures the key name from `.putString("<key>", ...)`. We re-run this on the
# matching line so we can surface the key in the finding title — instantly
# actionable for reviewers ("which token is stored unencrypted?").
_SHARED_PREFS_KEY = re.compile(
    r"""\.put(?:String|StringSet)\s*\(\s*["']([a-zA-Z0-9_.\-]+)["']"""
)
_ENCRYPTED_PREFS_CTX = re.compile(r"EncryptedSharedPreferences\b")
_PROVIDER_EXPORTED = re.compile(
    r"<provider\b[^>]*android:exported\s*=\s*[\"']true[\"']", re.IGNORECASE
)
_PROVIDER_GRANT_URI = re.compile(
    r"<provider\b[^>]*android:grantUriPermissions\s*=\s*[\"']true[\"']", re.IGNORECASE
)
_DEEPLINK_HOST_WILDCARD = re.compile(
    r"<data\b[^>]*android:host\s*=\s*[\"'](?:\*|.*\.\*)[\"']", re.IGNORECASE
)
# NOTE: `_DEEPLINK_AUTO_VERIFY` removed — `android:autoVerify="true"` is
# the SAFE form (turns a deeplink into a verified App Link gated by
# Digital Asset Links). Flagging its presence would be backwards.
_BACKUP_FLAG = re.compile(r"android:allowBackup\s*=\s*[\"']true[\"']")
_CLEARTEXT_TRAFFIC_FLAG = re.compile(
    r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']"
)
_TASK_AFFINITY_ABUSE = re.compile(r"android:launchMode\s*=\s*[\"']singleTask[\"'][^>]*android:taskAffinity\s*=\s*[\"'][\w.\-]+[\"']")
_TAPJACKING_FLAG = re.compile(r"setFilterTouchesWhenObscured\s*\(\s*false\s*\)")
# Identifier names that look like they hold sensitive values
_SENSITIVE_IDENT = re.compile(
    r"(?i)(?:token|password|jwt|api_?key|secret|cvv|pan|ssn|seed|access_?token|refresh_?token|auth)"
)
_DYNAMIC_REGISTRATION_NO_PERM = re.compile(
    # registerReceiver(receiver, filter) without a permission arg or RECEIVER_NOT_EXPORTED
    r"registerReceiver\s*\([^,]+,[^,)]+\)\s*;"
)


def detect_insecure_crypto(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect insecure default cipher/digest/random choices.

    On Android the JCA default for ``Cipher.getInstance("AES")`` is
    ``AES/ECB/PKCS5Padding`` — almost never what you want for confidential
    data. MD5/SHA-1 in signing contexts and plain ``Random`` for secrets are
    also flagged.
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, 1):
            if _CIPHER_INSECURE.search(line):
                findings.append(_make_finding(
                    "mobile-insecure-crypto",
                    "Insecure cipher/digest primitive",
                    rel, i, line.strip()[:200],
                    "Insecure JCA primitive in use: AES/DES/3DES/RC4 with default (ECB) mode, "
                    "or MD5/SHA-1/HmacMD5/HmacSHA1. These are broken for confidentiality or "
                    "integrity. Switch to AES/GCM/NoPadding (or ChaCha20-Poly1305) and SHA-256+ "
                    "/ HmacSHA256+. (CWE-327)",
                    "high", "finding",
                ))
            if _INSECURE_RANDOM.search(line) and _SECURITY_CONTEXT_HINT.search(line):
                findings.append(_make_finding(
                    "mobile-insecure-random",
                    "Insecure RNG used in security context",
                    rel, i, line.strip()[:200],
                    "java.util.Random / Math.random() is predictable and not cryptographically "
                    "secure. Use SecureRandom for tokens, nonces, salts, IVs, OTPs. (CWE-338)",
                    "medium", "finding",
                ))
    return findings


def detect_sensitive_sharedprefs(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect sensitive values written to non-encrypted SharedPreferences."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if _ENCRYPTED_PREFS_CTX.search(text):
            # Class already uses EncryptedSharedPreferences -- assume the same
            # bag is in use throughout the file.
            continue
        if not _SHARED_PREFS_SENSITIVE.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"\.put(?:String|StringSet)\s*\(")
        rel = str(path.relative_to(root))
        # Extract every sensitive key name in the file (a single class often
        # stores multiple fields). Reviewers need to see "which token" was
        # stored, not just "a token was stored somewhere".
        key_names: list[str] = []
        for km in _SHARED_PREFS_KEY.finditer(text):
            kname = km.group(1)
            if _SECURITY_CONTEXT_HINT.search(kname) or re.search(
                r"(?i)cvv|pan|jwt|credential|auth|pin", kname
            ):
                if kname not in key_names:
                    key_names.append(kname)
        title_extra = ""
        if key_names:
            head = ",".join(key_names[:3])
            tail = "" if len(key_names) <= 3 else f" (+{len(key_names) - 3} more)"
            title_extra = f" (key(s): {head}{tail})"
        findings.append(_make_finding(
            "mobile-shared-prefs-sensitive",
            f"Sensitive value stored in plain SharedPreferences{title_extra}",
            rel, line, excerpt,
            "A field whose name suggests a token/password/JWT/PIN/PAN is written to plain "
            "SharedPreferences (which is stored unencrypted on disk and is readable by any "
            "rooted device / backup). Use EncryptedSharedPreferences with the Android Keystore. "
            "(CWE-312)",
            "high", "finding",
            metadata={"pref_keys": key_names},
        ))
    return findings


def detect_android_storage_backup_issues(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Surface allowBackup=true, exported ContentProviders, deeplink wildcards."""
    findings: list[dict[str, Any]] = []
    cfg_paths = list(file_index.files_with_suffixes({".xml"})) if file_index else list(root.rglob("*.xml"))
    for path in cfg_paths:
        if _is_excluded(path):
            continue
        if path.name != "AndroidManifest.xml":
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if _BACKUP_FLAG.search(line):
                findings.append(_make_finding(
                    "mobile-allow-backup-true",
                    "AndroidManifest sets allowBackup=true",
                    rel, i, line.strip()[:200],
                    "allowBackup=true allows adb backup / Google Auto Backup to exfiltrate the "
                    "app's data dir (including non-encrypted SharedPreferences, tokens, SQL DBs). "
                    "Set to false or define a precise data_extraction_rules to opt out tokens, "
                    "session data, and PII. (CWE-200)",
                    "medium", "hotspot",
                ))
            if _CLEARTEXT_TRAFFIC_FLAG.search(line):
                findings.append(_make_finding(
                    "mobile-cleartext-traffic-allowed",
                    "AndroidManifest sets usesCleartextTraffic=true",
                    rel, i, line.strip()[:200],
                    "android:usesCleartextTraffic=true (or its default on minSdk<28) lets the "
                    "app talk to plain HTTP endpoints anywhere on the internet — analytics "
                    "beacons, dev test hosts, or any URL the attacker can land via remote "
                    "config. Any in-path attacker can read/modify those requests. Set to "
                    "false and use a network_security_config to whitelist any genuinely "
                    "required cleartext domain. (CWE-319)",
                    "medium", "hotspot",
                ))
            if _PROVIDER_EXPORTED.search(line):
                # Look ahead 10 lines for a permission attribute
                window = "\n".join(lines[i - 1 : i + 10])
                if not _HAS_PERMISSION.search(window):
                    findings.append(_make_finding(
                        "mobile-exported-provider",
                        "Exported ContentProvider with no permission",
                        rel, i, line.strip()[:200],
                        "Exported <provider> with no android:readPermission/writePermission means "
                        "any installed app can query/mutate its URIs. Provider URIs are an extremely "
                        "common Android attack surface (file disclosure, IDOR, SQL injection). (CWE-926)",
                        "high", "finding",
                    ))
            if _PROVIDER_GRANT_URI.search(line):
                findings.append(_make_finding(
                    "mobile-provider-grant-uri-permissions",
                    "ContentProvider has android:grantUriPermissions=true",
                    rel, i, line.strip()[:200],
                    "`grantUriPermissions=true` lets any client temporarily receive read/write "
                    "access to the provider's URIs via `FLAG_GRANT_READ_URI_PERMISSION` / "
                    "`FLAG_GRANT_WRITE_URI_PERMISSION` flags on an Intent — bypassing the "
                    "provider's static permission guard. Combined with an exported activity "
                    "that doesn't sanitize forwarded Intents, this becomes a URI-traversal "
                    "+ file-disclosure primitive. Set `grantUriPermissions=false` unless "
                    "intentional + verify every grant site explicitly. (CWE-275 + CWE-926)",
                    "medium", "hotspot",
                ))
            if _DEEPLINK_HOST_WILDCARD.search(line):
                findings.append(_make_finding(
                    "mobile-deeplink-host-wildcard",
                    "Deep link declares a wildcard host",
                    rel, i, line.strip()[:200],
                    "<data android:host=\"*\"> opens the activity to any host. Validate host/path "
                    "in code before consuming any extras to avoid intent injection / open redirect. "
                    "(CWE-441)",
                    "medium", "hotspot",
                ))
    return findings


def detect_log_sensitive_data(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect log statements that interpolate sensitive **identifiers**.

    The check is intentionally pedantic: it strips string literals out of the
    Log call before looking for sensitive keywords, so messages whose only
    sensitive token sits inside a hardcoded string (``"Failed to get FIS auth
    token"`` etc.) are not flagged. Only variables / field accesses whose
    *name* matches the sensitive identifier list count.
    """
    findings: list[dict[str, Any]] = []
    log_call = re.compile(r"""(?:Log|Slf4j|Logger)\.(?:d|v|i|w|e)\s*\(([^)]*)\)""")
    # Common exception / generic names we should NEVER flag.
    benign_idents = frozenset({
        "e", "ex", "exception", "th", "throwable", "t", "tr", "tag",
        "TAG", "msg", "message", "name", "value", "obj", "result",
        "view", "v", "context", "ctx",
    })
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, 1):
            m = log_call.search(line)
            if not m:
                continue
            args = m.group(1)
            # Strip string literals so we can inspect identifiers only.
            no_strings = re.sub(r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""", "", args)
            idents = re.findall(r"[A-Za-z_$][\w$]*", no_strings)
            non_benign = [ident for ident in idents if ident not in benign_idents]
            if not non_benign:
                continue
            sensitive_idents = [ident for ident in non_benign if _SENSITIVE_IDENT.search(ident)]
            if not sensitive_idents:
                continue
            findings.append(_make_finding(
                "mobile-log-sensitive",
                f"Log statement interpolates sensitive value(s): {', '.join(sensitive_idents[:3])}",
                rel, i, line.strip()[:200],
                "A logger call interpolates a variable/field whose name suggests it holds a "
                "token, password, JWT, API key, CVV, or PAN. Logcat is collected by many "
                "device-management agents and was world-readable on pre-Android 4.1. Redact "
                "or remove. (CWE-532)",
                "medium", "hotspot",
                metadata={"sensitive_idents": sensitive_idents},
            ))
    return findings


# ---------------------------------------------------------------------------
# Mobile additional: deserialization, exec, WebView mixed content, JWT
# ---------------------------------------------------------------------------

_OBJECT_INPUT_STREAM = re.compile(
    r"new\s+ObjectInputStream\s*\(|readObject\s*\(\s*\)"
)
_RUNTIME_EXEC = re.compile(
    r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\("
)
# Class/file names whose Runtime.exec / ProcessBuilder usage is intentional
# root-detection probing ("which su", "/system/xbin/su") rather than a tainted
# code-exec surface. Skipping these drops a recurring class of false positives.
_ROOT_DETECTION_HINTS = re.compile(
    r"RootDetect|rootDetect|checkSu|SuExecutable|SuChecker|RootBeer|RootCheck",
    re.IGNORECASE,
)
_ROOT_DETECTION_LITERALS = re.compile(
    r"""['"](?:which\s+su|/system/(?:bin|xbin)/su|/sbin/su|su\s*-?c)['"]""",
    re.IGNORECASE,
)

# Framework-provided exported components that ship with debug tooling. These
# appear in release manifests when developers forget to strip compose-tooling
# from the release variant, but they expose no app-side behavior worth flagging
# — the developer can't patch them short of removing the dependency.
_FRAMEWORK_DEBUG_EXPORTED = {
    "androidx.compose.ui.tooling.PreviewActivity",
    "androidx.compose.ui.tooling.preview.PreviewActivity",
}
_WEBVIEW_MIXED_CONTENT = re.compile(
    r"setMixedContentMode\s*\(\s*(?:0|WebSettings\.MIXED_CONTENT_ALWAYS_ALLOW)"
)
_HARDCODED_JWT = re.compile(
    # JWT shape: three base64url segments separated by dots.
    r"['\"]eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}['\"]"
)
# NOTE: a regex for root-detection presence was deleted as misconceived —
# "file mentions su/magisk/frida" is not a vulnerability on its own,
# and flagging every root-detection-using file as a finding is pure
# noise. The N+5 ROOT_DETECTION_HINTS regex (above) is the inverse —
# it SUPPRESSES runtime-exec findings inside those files. That's the
# direction with real audit value.


def detect_insecure_deserialization(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect Java ObjectInputStream usage on app boundaries."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _OBJECT_INPUT_STREAM.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"new\s+ObjectInputStream|readObject")
        rel = str(path.relative_to(root))
        findings.append(_make_finding(
            "mobile-insecure-deserialization",
            "Java native serialization in use",
            rel, line, excerpt,
            "ObjectInputStream / readObject is a textbook gadget-chain vector. If any input "
            "reaches it from a Parcel extra, file, network, or SharedPreferences, an attacker "
            "with controlled bytes can construct a payload that invokes arbitrary callbacks "
            "during deserialization. Replace with a structured codec (Protobuf, JSON+schema, "
            "Moshi). (CWE-502)",
            "high", "finding",
        ))
    return findings


def detect_runtime_exec(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect Runtime.exec / ProcessBuilder — often a code-exec vector on root."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _RUNTIME_EXEC.search(text):
            continue
        rel = str(path.relative_to(root))
        # Skip intentional root-detection probes: the SUT runs a hardcoded
        # `which su` / `/system/xbin/su` check that isn't tainted by any
        # caller-controlled string.
        if _ROOT_DETECTION_HINTS.search(rel) or _ROOT_DETECTION_LITERALS.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"Runtime\.getRuntime|ProcessBuilder")
        # Only flag when the file looks app-side (not stdlib helpers we missed).
        findings.append(_make_finding(
            "mobile-runtime-exec",
            "Runtime.exec / ProcessBuilder in app code",
            rel, line, excerpt,
            "Runtime.getRuntime().exec() / ProcessBuilder is an unusual surface for Android "
            "apps. If any spliced argument originates from intent extras, deeplinks, or remote "
            "config, an attacker may inject command tokens. On rooted devices these run with "
            "broader privileges. (CWE-78)",
            "high", "hotspot",
        ))
    return findings


def detect_webview_mixed_content(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect WebView setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".java", ".kt"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".java", ".kt"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _WEBVIEW_MIXED_CONTENT.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"setMixedContentMode")
        rel = str(path.relative_to(root))
        findings.append(_make_finding(
            "mobile-webview-mixed-content",
            "WebView allows mixed-content loads",
            rel, line, excerpt,
            "MIXED_CONTENT_ALWAYS_ALLOW lets HTTP subresources load inside HTTPS pages. Active "
            "content injected over HTTP can run with the page's privileges. Use "
            "MIXED_CONTENT_NEVER_ALLOW (or COMPATIBILITY_MODE only with the strictest URL "
            "allowlist). (CWE-319)",
            "high", "finding",
        ))
    return findings


def detect_hardcoded_jwt(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect a literal JWT (three base64url segments) embedded in source."""
    findings: list[dict[str, Any]] = []
    exts = {".java", ".kt", ".py", ".js", ".ts", ".tsx", ".jsx", ".go",
            ".rb", ".php", ".cs", ".rs", ".properties", ".env", ".yaml", ".yml"}
    files = file_index.files_with_suffixes(exts) if file_index else (
        p for p in root.rglob("*") if p.suffix in exts
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, 1):
            if _HARDCODED_JWT.search(line):
                findings.append(_make_finding(
                    "secret-hardcoded-jwt",
                    "Hardcoded JWT in source",
                    rel, i, line.strip()[:200],
                    "A literal JWT is embedded in source. Even if expired, it leaks the "
                    "issuer's claims model, the audience, and (with HS256) potentially enough "
                    "structure to attempt cracking the signing secret. (CWE-798)",
                    "high", "finding",
                ))
    return findings


# ---------------------------------------------------------------------------
# iOS / Swift / Objective-C detectors
# ---------------------------------------------------------------------------

_IOS_ATS_ARBITRARY = re.compile(
    # Info.plist NSAppTransportSecurity.NSAllowsArbitraryLoads=true
    r"<key>\s*NSAllowsArbitraryLoads\s*</key>\s*<true\s*/>"
)
_IOS_ATS_HTTP_LOADS_OK = re.compile(
    r"<key>\s*NSAllowsArbitraryLoadsForMedia\s*</key>\s*<true\s*/>"
    r"|<key>\s*NSAllowsLocalNetworking\s*</key>\s*<true\s*/>"
)
_IOS_KEYCHAIN_ALWAYS = re.compile(
    # kSecAttrAccessibleAlways / AlwaysThisDeviceOnly -- pre-iOS 10 only,
    # readable when device is locked.
    r"kSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b"
)
_IOS_TRUST_ALL_SSL = re.compile(
    # NSURLConnection delegate accepts any server trust without evaluating it.
    r"didReceiveChallenge[\s\S]{0,300}?NSURLAuthenticationMethodServerTrust"
    r"[\s\S]{0,200}?\.useCredential\s*,\s*URLCredential\s*\(\s*trust\s*:"
    r"|@objc\s+func\s+urlSession[^{]*didReceive\s+challenge[\s\S]{0,300}?"
    r"completionHandler\s*\(\s*\.useCredential\s*,\s*URLCredential\s*\(\s*trust\s*:"
)
_IOS_WK_WEBVIEW_JS = re.compile(
    r"WKWebView|UIWebView|loadHTMLString\s*\(|evaluateJavaScript\s*\("
)
_IOS_OPEN_URL_WITH_INPUT = re.compile(
    # canOpenURL / open with user input -- intent-redirect equivalent for iOS
    r"UIApplication\.shared\.(?:canOpenURL|open)\s*\(\s*URL\s*\(\s*string:\s*[a-zA-Z_][\w]*"
)


def detect_ios_ats_disabled(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Inspect Info.plist for App Transport Security exemptions."""
    findings: list[dict[str, Any]] = []
    cfg_paths = list(file_index.files_with_suffixes({".plist"})) if file_index else list(root.rglob("*.plist"))
    # Also scan generic XML/Info.plist file path
    if file_index:
        cfg_paths.extend(file_index.files_with_suffixes({".xml"}))
    else:
        cfg_paths.extend(root.rglob("Info.plist"))
    seen: set[Path] = set()
    for path in cfg_paths:
        if path in seen or _is_excluded(path):
            continue
        seen.add(path)
        if path.name.lower() != "info.plist":
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        lines = text.splitlines()
        if _IOS_ATS_ARBITRARY.search(text):
            line, excerpt = _line_for(lines, r"NSAllowsArbitraryLoads")
            findings.append(_make_finding(
                "ios-ats-arbitrary-loads",
                "Info.plist sets NSAllowsArbitraryLoads=true",
                rel, line, excerpt,
                "NSAllowsArbitraryLoads disables App Transport Security globally — all HTTP "
                "(and weak TLS) loads bypass enforcement. Replace with NSExceptionDomains "
                "targeted at the specific legacy hosts you actually need. (CWE-319)",
                "high", "finding",
            ))
        if _IOS_ATS_HTTP_LOADS_OK.search(text):
            line, excerpt = _line_for(lines, r"NSAllowsArbitraryLoadsForMedia|NSAllowsLocalNetworking")
            findings.append(_make_finding(
                "ios-ats-partial-exemption",
                "Info.plist relaxes ATS for media or local networking",
                rel, line, excerpt,
                "ATS exemption widens the unauthenticated transport surface. Verify the "
                "exemption is necessary and scoped to specific hosts. (CWE-319)",
                "medium", "hotspot",
            ))
    return findings


def detect_ios_keychain_misuse(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect kSecAttrAccessibleAlways — readable when device is locked."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".swift", ".m", ".mm", ".h"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".swift", ".m", ".mm", ".h"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _IOS_KEYCHAIN_ALWAYS.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"kSecAttrAccessibleAlways")
        rel = str(path.relative_to(root))
        findings.append(_make_finding(
            "ios-keychain-accessible-always",
            "Keychain item readable when device is locked",
            rel, line, excerpt,
            "kSecAttrAccessibleAlways / kSecAttrAccessibleAlwaysThisDeviceOnly allows the "
            "stored item to be read while the device is locked, including by attackers with "
            "brief physical access. Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or "
            "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly. (CWE-922)",
            "high", "finding",
        ))
    return findings


def detect_ios_trust_all(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect NSURLSession trust-all delegate handler."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".swift", ".m", ".mm"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".swift", ".m", ".mm"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _IOS_TRUST_ALL_SSL.search(text):
            continue
        lines = text.splitlines()
        line, excerpt = _line_for(lines, r"NSURLAuthenticationMethodServerTrust|didReceive\s+challenge")
        rel = str(path.relative_to(root))
        findings.append(_make_finding(
            "ios-trust-all-ssl",
            "NSURLSession delegate accepts any server trust",
            rel, line, excerpt,
            "The URLSession authentication challenge handler returns a credential built from "
            "the server trust without evaluating it (no SecTrustEvaluate, no pin compare). Any "
            "HTTPS endpoint reached through this session accepts arbitrary certificates, "
            "defeating transport security. (CWE-295)",
            "critical", "finding",
        ))
    return findings


def detect_ios_open_url_with_input(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect `UIApplication.shared.open(URL(string: var))` patterns.

    iOS analog of Android intent-redirection: calling
    `UIApplication.shared.open` (or `canOpenURL`) with a URL built
    from a variable lets a caller dispatch arbitrary URL schemes
    through the host app — opening other apps, dialing numbers,
    triggering custom-scheme deeplinks. If `var` is reachable from
    URL-context input (push payload, deeplink param, fetched config),
    it's a classic open-URL-injection.
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".swift", ".m", ".mm"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".swift", ".m", ".mm"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if _IOS_OPEN_URL_WITH_INPUT.search(line):
                rel = str(path.relative_to(root))
                findings.append(_make_finding(
                    "ios-open-url-redirection",
                    "UIApplication.shared.open() / canOpenURL() called with variable URL",
                    rel, i, line.strip()[:200],
                    "The variable form of `UIApplication.shared.open(URL(string: someVar))` "
                    "lets a caller-supplied string dispatch arbitrary URL schemes. If "
                    "`someVar` traces back to a push notification payload, deeplink "
                    "parameter, fetched JSON, or pasteboard, an attacker can launch "
                    "tel://, sms://, custom-scheme deeplinks, or even file:// URLs "
                    "through the host app's privilege. Validate the scheme + host "
                    "against an allowlist before dispatching. (CWE-940)",
                    "high", "finding",
                ))
    return findings


def detect_ios_log_sensitive(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect NSLog/os_log/print calls that include a sensitive identifier.

    iOS analog of `detect_log_sensitive_data`. Pure-literal log lines
    aren't flagged — only calls where a variable/field whose name
    suggests a token / password / JWT / etc. is interpolated.
    """
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".swift", ".m", ".mm"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".swift", ".m", ".mm"}
    )
    log_call = re.compile(r"""(?:NSLog|os_log|print)\s*\(([^)]*)\)""")
    benign_idents = frozenset({
        "e", "ex", "exception", "th", "tr", "tag", "TAG", "msg",
        "message", "name", "value", "obj", "result",
    })
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines, 1):
            m = log_call.search(line)
            if not m:
                continue
            args = m.group(1)
            no_strings = re.sub(r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""", "", args)
            idents = re.findall(r"[A-Za-z_$][\w$]*", no_strings)
            non_benign = [ident for ident in idents if ident not in benign_idents]
            if not non_benign:
                continue
            sensitive_idents = [
                ident for ident in non_benign if _SENSITIVE_IDENT.search(ident)
            ]
            if not sensitive_idents:
                continue
            findings.append(_make_finding(
                "ios-log-sensitive",
                f"Log statement interpolates sensitive value(s): {', '.join(sensitive_idents[:3])}",
                rel, i, line.strip()[:200],
                "An iOS logger call (NSLog / os_log / print) interpolates a "
                "variable/field whose name suggests it holds a token, password, "
                "JWT, API key, CVV, or PAN. Use os_log with `%{private}@` and "
                "appropriate `os_log_type_t` to redact, or drop the log entirely. "
                "(CWE-532)",
                "medium", "hotspot",
                metadata={"sensitive_idents": sensitive_idents},
            ))
    return findings


def detect_ios_webview_unsafe(
    root: Path, file_index: FileIndex | None = None
) -> list[dict[str, Any]]:
    """Detect UIWebView (deprecated) and WKWebView with risky JS surfaces."""
    findings: list[dict[str, Any]] = []
    files = file_index.files_with_suffixes({".swift", ".m", ".mm"}) if file_index else (
        p for p in root.rglob("*") if p.suffix in {".swift", ".m", ".mm"}
    )
    for path in files:
        if _is_excluded(path):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if not _IOS_WK_WEBVIEW_JS.search(text):
            continue
        lines = text.splitlines()
        rel = str(path.relative_to(root))
        # UIWebView is deprecated and accepts arbitrary URLs
        if "UIWebView" in text:
            line, excerpt = _line_for(lines, r"UIWebView")
            findings.append(_make_finding(
                "ios-uiwebview-deprecated",
                "Deprecated UIWebView in use",
                rel, line, excerpt,
                "UIWebView is deprecated since iOS 12 and has known process-isolation issues. "
                "Migrate to WKWebView with explicit JS evaluation policy. (CWE-1104)",
                "medium", "hotspot",
            ))
        # loadHTMLString with concatenated input
        if re.search(r"loadHTMLString\s*\([^)]*\\\(", text) or re.search(
            r"loadHTMLString\s*\(\s*[\"'][^\"']*[\"']\s*\+\s*\w+", text
        ):
            line, excerpt = _line_for(lines, r"loadHTMLString")
            findings.append(_make_finding(
                "ios-webview-html-concat",
                "WKWebView/UIWebView loads HTML built by string interpolation",
                rel, line, excerpt,
                "loadHTMLString receives a string assembled via Swift interpolation or concat. "
                "If any spliced value comes from network/intent, the WebView renders attacker "
                "HTML/JS in the app origin. (CWE-79)",
                "high", "finding",
            ))
        # evaluateJavaScript with concatenated input
        if re.search(r"evaluateJavaScript\s*\([^)]*\\\(", text):
            line, excerpt = _line_for(lines, r"evaluateJavaScript")
            findings.append(_make_finding(
                "ios-webview-evaljs-concat",
                "WKWebView evaluateJavaScript with interpolated value",
                rel, line, excerpt,
                "evaluateJavaScript builds the JS payload via Swift string interpolation. Any "
                "spliced variable that escapes its string literal executes attacker JS in the "
                "WebView. (CWE-94)",
                "high", "finding",
            ))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_all_detectors(target_path: str) -> list[dict[str, Any]]:
    """Run all extended vulnerability class detectors.

    Returns a list of findings to be merged into the main findings list.

    Per-detector failures are caught and logged at WARNING level, and
    recorded on the module-level `LAST_DETECTOR_FAILURES` list so the
    caller (typically scan_orchestrator) can surface them in the output
    artifact's `scan_metadata`. A single buggy detector should not lose
    every other detector's findings.
    """
    # Reset in place (.clear) rather than rebind (`= []`) so callers
    # that did `from vuln_class_detectors import LAST_DETECTOR_FAILURES`
    # still see the reset through their reference. Same fix as bug 34
    # in chain_detector. Drop `global` since we don't rebind anymore.
    LAST_DETECTOR_FAILURES.clear()

    root = Path(target_path).resolve()
    if not root.is_dir():
        return []

    # One directory traversal shared by all detectors
    file_index = FileIndex.build(root)

    all_findings: list[dict[str, Any]] = []

    detectors = [
        ("SQL injection", detect_sql_injection),
        ("PHP injection", detect_php_injection),
        ("SSRF (two-pass)", detect_ssrf_two_pass),
        ("race conditions", detect_race_conditions),
        ("prototype pollution", detect_prototype_pollution),
        ("file upload", detect_file_upload_vulns),
        ("OAuth/OIDC", detect_oauth_flaws),
        ("request smuggling", detect_request_smuggling),
        ("WebSocket", detect_websocket_vulns),
        ("mass assignment", detect_mass_assignment),
        ("CORS", detect_cors_misconfig),
        ("CI/CD", detect_cicd_vulns),
        ("IDOR", detect_missing_ownership_check),
        ("frontend XSS", detect_frontend_xss),
        ("stored XSS risk", detect_stored_xss_risk),
        ("mobile payment code contracts", detect_mobile_payment_code_contracts),
        ("mobile WebView JS injection", detect_webview_js_injection),
        ("mobile WebView unsafe config", detect_webview_unsafe_config),
        ("mobile remote-controlled endpoint", detect_remote_controlled_url),
        ("mobile network security config", detect_network_security_config_gaps),
        ("mobile AndroidManifest", detect_android_manifest_issues),
        ("mobile insecure TLS", detect_insecure_tls),
        ("mobile intent redirection", detect_mobile_intent_redirection),
        ("mobile PendingIntent mutable", detect_pendingintent_mutable),
        ("mobile tapjacking disabled", detect_tapjacking_disabled),
        ("mobile task affinity hijack", detect_task_affinity_abuse),
        ("mobile dynamic receiver unprotected", detect_dynamic_receiver_no_perm),
        ("mobile hardcoded http URL", detect_hardcoded_http_url),
        ("hardcoded secrets (narrow)", detect_hardcoded_secrets_simple),
        ("mobile insecure crypto/RNG", detect_insecure_crypto),
        ("mobile sensitive SharedPreferences", detect_sensitive_sharedprefs),
        ("mobile storage/backup/provider", detect_android_storage_backup_issues),
        ("mobile log sensitive data", detect_log_sensitive_data),
        ("mobile insecure deserialization", detect_insecure_deserialization),
        ("mobile Runtime.exec", detect_runtime_exec),
        ("mobile WebView mixed content", detect_webview_mixed_content),
        ("hardcoded JWT", detect_hardcoded_jwt),
        ("iOS ATS arbitrary loads", detect_ios_ats_disabled),
        ("iOS keychain misuse", detect_ios_keychain_misuse),
        ("iOS trust-all SSL", detect_ios_trust_all),
        ("iOS WebView unsafe", detect_ios_webview_unsafe),
        ("iOS log sensitive", detect_ios_log_sensitive),
        ("iOS open-URL redirection", detect_ios_open_url_with_input),
    ]

    for name, detector in detectors:
        try:
            # CI/CD detector scans a subdirectory, doesn't use file_index
            if detector is detect_cicd_vulns:
                findings = detector(root)
            else:
                findings = detector(root, file_index=file_index)
            if findings:
                log.info("Extended detector [%s]: %d findings", name, len(findings))
                all_findings.extend(findings)
        except Exception as e:
            # Stable marker `[detector-failure]` for greppable log analysis.
            log.warning(
                "[detector-failure] detector=%s error=%s: %s",
                name, type(e).__name__, e,
            )
            LAST_DETECTOR_FAILURES.append({
                "detector": name,
                "error": f"{type(e).__name__}: {e}",
            })

    if LAST_DETECTOR_FAILURES:
        log.warning(
            "Extended detector failures: %d (see scan_metadata.detector_failures in output)",
            len(LAST_DETECTOR_FAILURES),
        )
    log.info("Extended detectors total: %d findings", len(all_findings))
    return all_findings
