---
name: Mobile Payment Tokenization Patterns
description: Use this skill when reviewing mobile code that handles card data, payment tokenization, or third-party payment SDK integrations (Braintree, Stripe, Adyen, Google Pay, Apple Pay, FirstData-style iframe encryptors). The skill catalogues the high-signal attack patterns vuln-scout detects in mobile payment flows — server-controlled tokenization URLs, JavaScript-injection-into-WebView card-data exfiltration, JS-bridge token construction, and payment scope mismatches — and maps each to the detector that fires.
version: 1.0.0
---

# Mobile Payment Tokenization Patterns

## When this skill applies

The user is reviewing mobile (Android/iOS) code that handles:

- Card tokenization (PAN/CVV/expiry → opaque token)
- Payment processor SDK integration (Braintree, Stripe, Adyen, FirstData-
  style iframe encryptors)
- Wallets (Google Pay, Apple Pay, Cash App, Venmo)
- Encrypted PAN encryption in WebViews
- Issuer / PIE (Public Initialization Encryption) key management

Signals: files under `**/payment/**`, `**/checkout/**`, `**/tokenize*/**`, `**/services/**/api/`, mentions of "PIE key", "iframe shim", "EncryptionListener", "PaymentMethodType".

## The PIE / iframe-shim / Braintree tokenization shape

Most modern card tokenization on Android follows this template:

1. The app fetches an **encryption key** (RSA pubkey or symmetric salt) from a backend.
2. The app fetches the **tokenization endpoint URL** from a backend.
3. The app builds a **JavaScript payload** that contains:
   - The key material
   - The card data (PAN/CVV/expiry) interpolated into JS literals
   - A `<script>` block that calls into an exposed `@JavascriptInterface`
4. The app dispatches the JS into a **WebView** with `setJavaScriptEnabled(true)`.
5. The WebView's encryption JS produces an opaque token, which the bridge returns to native code.
6. The native code submits the token to the processor over HTTPS.

Each step has a corresponding VulnScout detector:

| Step | Detector | What goes wrong |
|---|---|---|
| 2 (URL fetched) | `mobile-remote-controlled-endpoint` | Backend supplies an attacker-controlled URL; client follows it. |
| 1 (key fetched) | `mobile-webview-js-injection` | Key material is spliced into a JS literal unescaped — break out, run JS. |
| 3-4 (JS dispatch) | `mobile-webview-js-injection`, `mobile-webview-file-access`, `mobile-webview-js-interface` | WebView config or @JavascriptInterface exposes native callbacks. |
| 5 (bridge) | `mobile-js-bridge-payment-token` | Native token object is constructed from JS-controlled values. |
| 6 (submit) | `mobile-nsc-narrow-pinning`, `mobile-nsc-no-pinning`, `mobile-insecure-tls` | Cert pinning gap on the processor host allows MITM of the token. |

## What a real hit looks like

When the detectors fire on a payment flow you should expect to see a cluster
along these lines (file names will differ; the *shape* is what matters):

| Detector type | File shape | Notes |
|---|---|---|
| `mobile-remote-controlled-endpoint` | a `*TokenizeCardApi` / `*PaymentApi` class | a `*_URL` key is pulled from remote config and dispatched via OkHttp / Retrofit / a custom `CoroutineCallFactory`. |
| `mobile-webview-js-injection` | a tokenization helper under `**/payment/**/js/` | PIE/RSA key material + PAN/CVV spliced into a `<script>` literal via StringBuilder. |
| `mobile-js-bridge-payment-token` | a sibling `EncryptionListener` / `*Bridge` class | `@JavascriptInterface onEncryptionComplete` builds the native token object. |
| `mobile-nsc-narrow-pinning` | `apktool_out/res/xml/network_security_config.xml` | pin-set covers a single advertising/SDK domain while every payment / identity / config host still relies on system CA. |
| `mobile-shared-prefs-sensitive` | an auth/identity package | access token / refresh token written to plain SharedPreferences. |
| `payment-client-token-scope-mismatch` | a Braintree wrapper | hardcoded `ExternalPaymentProcessor.X` + `PaymentMethodType.Y` may reuse the token outside its intended scope. |

## Chain to look for

Two detectors in the same payment package + a manifest-side pinning gap = a complete card-data exfiltration primitive. VulnScout's `chain_detector.py` auto-builds this as `Mobile WebView dispatch chain`.

## Cross-platform notes

- iOS equivalents: `ios-webview-evaljs-concat` (= `mobile-webview-js-injection`), `ios-ats-arbitrary-loads` (= `mobile-nsc-cleartext`), `ios-trust-all-ssl` (= `mobile-insecure-tls`).
- Cash App SDK / Square SDK use similar PIE-style flows — apply the same template.
- Google Pay tokens are wrapped server-side and don't follow this template; client-side findings on a Google Pay flow are usually informational.

See also: [[mobile-android]], [[mobile-ios]].
