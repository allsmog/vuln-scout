---
name: Mobile Android Whitebox Audit
description: Use this skill when the user is auditing a decompiled Android application — directory structure includes `jadx_out/` / `apktool_out/`, files end in `.smali` / are jadx-renamed to `defpackage/*.java`, or the conversation mentions an APK / xAPK / `com.example.*` package. Covers the high-signal vulnerability classes vuln-scout detects in decompiled APKs and the conventions for running the unified mobile-audit workflow.
version: 1.0.0
---

# Mobile Android Whitebox Audit

## When this skill applies

The user is reviewing a decompiled Android target. Signals to look for:

- The working directory or referenced target contains `jadx_out/`, `jadx_out2/`,
  `apktool_out/`, `AndroidManifest.xml`, `*.smali`, or jadx's signature
  `defpackage/*.java` files (obfuscated default-package classes).
- The user mentions an APK, xAPK, or an Android package name
  (`com.example.*`, `com.acme.app`, etc.).
- A previous run produced findings under `<target>/.claude/findings.json` whose
  `type` starts with `mobile-*`.

## Workflow: prefer `/vuln-scout:mobile-audit`

For Android targets, the regular `/vuln-scout:scan` only sees one of the two
decompilation trees (code OR resources). Use the unified driver instead:

```
/vuln-scout:mobile-audit <target-root>
```

The driver auto-discovers `jadx_out/sources` (or `jadx/sources`,
`decompiled/sources`, `android-decompiled/sources`, `src/main/java`) for code
findings and `apktool_out` (or `apktool`, `res`) for manifest + NSC findings,
runs the orchestrator on each, and merges the artifacts into a single
`<target>/.claude/findings.json`. Use the `--profile deep` flag when CodeQL /
Joern are installed (run `python3 vuln-scout/scripts/doctor.py` to confirm).

## High-signal detector cheatsheet

VulnScout ships dedicated mobile detectors. Each produces normalized findings
with the standard schema (`stable_key`, `kind`, `severity`, `type`, etc.).

| Detector | Type slug | What it finds |
|---|---|---|
| `detect_webview_js_injection` | `mobile-webview-js-injection` | A `<script>` block or `var X =` JS literal assembled from native StringBuilder/helper calls — the in-WebView card-tokenization shape. Dispatched via `evaluateJavascript` somewhere in the call graph. |
| `detect_webview_unsafe_config` | `mobile-webview-file-access`, `mobile-webview-js-interface` | `setJavaScriptEnabled(true)` + `setAllowFileAccess(true)` / `addJavascriptInterface()`. |
| `detect_remote_controlled_url` | `mobile-remote-controlled-endpoint` | URL fetched from a config key (`getString("*_URL"...)`) and dispatched via OkHttp/Retrofit/`CoroutineCallFactory` — the remote-config URL-injection shape. |
| `detect_network_security_config_gaps` | `mobile-nsc-no-pinning`, `mobile-nsc-narrow-pinning`, `mobile-nsc-cleartext` | Missing or partial cert pinning, cleartext traffic permitted. |
| `detect_android_manifest_issues` | `mobile-exported-component-no-permission`, `mobile-debuggable-build` | Exported activity/service/receiver with no permission guard; debuggable production build. |
| `detect_android_storage_backup_issues` | `mobile-allow-backup-true`, `mobile-exported-provider`, `mobile-deeplink-host-wildcard` | allowBackup=true; exported ContentProviders without permission; wildcard deeplink hosts. |
| `detect_insecure_crypto` | `mobile-insecure-crypto`, `mobile-insecure-random` | AES default mode (ECB) / DES / 3DES / RC4 / MD5 / SHA-1 / HmacMD5; `Math.random()` / `new Random()` used for tokens/IVs/keys. |
| `detect_sensitive_sharedprefs` | `mobile-shared-prefs-sensitive` | Tokens / passwords / JWTs / PANs written to non-Encrypted SharedPreferences. |
| `detect_log_sensitive_data` | `mobile-log-sensitive` | `Log.X` call interpolating a variable whose name maps to a sensitive identifier. |
| `detect_insecure_tls` | `mobile-insecure-tls` | Empty `checkServerTrusted` / always-true `HostnameVerifier`. |
| `detect_mobile_intent_redirection` | `mobile-intent-redirection` | Activity re-launches an externally provided Intent (StrandHogg shape). |
| `detect_pendingintent_mutable` | `mobile-pendingintent-mutable` | `PendingIntent.get*` with `FLAG_MUTABLE`. |
| `detect_hardcoded_secrets_simple` | `secret-hardcoded`, `secret-private-key` | AKIA / sk_live_ / ghp_ / xoxb / `-----BEGIN PRIVATE KEY-----` blocks. |

## Triage shortcuts

When `findings.json` is heavy, sort by these priorities first:

1. `mobile-webview-js-injection` + `mobile-remote-controlled-endpoint` in the
   same package — that's a complete chain (server-influenced data flows into
   JS that runs in a privileged WebView).
2. `mobile-insecure-tls` + `mobile-nsc-no-pinning` — MITM precondition holds
   for the entire app.
3. `mobile-shared-prefs-sensitive` in an auth/identity package.
4. `mobile-exported-component-no-permission` on receivers/services that pass
   intents into payment, auth, or deeplink handlers.

## Calibration anchors

If a code change to detectors needs validation, run against a decompiled
target with both `jadx_out/sources/` and `apktool_out/` present. A healthy
mobile target with a payment-tokenization flow should produce roughly:

- Total findings: 7–30 (mix of high/medium, plus a handful of hotspots)
  depending on profile and how much obfuscated SDK code lives under
  `defpackage/`
- Must include at least:
  - `mobile-remote-controlled-endpoint` on a `*TokenizeCardApi`-style class
    where a `*_URL` key is read from config and dispatched
  - `mobile-webview-js-injection` on a payment package class that splices
    native values into a `<script>` literal
  - `mobile-nsc-narrow-pinning` at
    `apktool_out/res/xml/network_security_config.xml` whenever pinning is
    declared but the pin-set is narrower than the app's API surface

## Path-exclusion conventions

`vuln_class_detectors.py` strips findings inside well-known third-party paths
to keep noise out of decompiled APKs:

- Single-segment, root-only: `kotlin`, `kotlinx`, `java`, `javax`, `androidx`,
  `okhttp3`, `retrofit2`, `okio`, `dagger`, `tslib`, `j$` …
- Multi-segment, anywhere: `com/google/android/*`, `com/google/firebase/*`,
  `com/squareup/*`, `com/bumptech/glide/*`, `com/lexisnexisrisk/*`,
  `io/reactivex/*`, `io/sentry/*`, `org/maplibre/*` …

Default-package classes (`defpackage/jh5.java` style) cannot be excluded by
path — review their content if a finding lands there.
