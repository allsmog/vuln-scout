---
name: Mobile iOS Whitebox Audit
description: Use this skill when the user is auditing an iOS application — directory contains `.ipa`, `Info.plist`, `*.swift`, `*.m`, `*.mm`, or an `xcodeproj`. Also activates when the conversation mentions WKWebView, NSURLSession, Keychain, App Transport Security, or any `com.apple.*` / `bundleidentifier`-style iOS package name.
version: 1.0.0
---

# Mobile iOS Whitebox Audit

## When this skill applies

The user is reviewing an iOS target. Signals to look for:

- The target directory has an `Info.plist`, `*.swift`, `*.m`, `*.mm`, or `*.xcodeproj`.
- The conversation mentions WKWebView, NSURLSession, Keychain, ATS, KeychainAccess, ObjC runtime.
- A previous run produced `.claude/findings.json` entries whose `type` starts with `ios-*`.

## Triage anchors

| Type | What to verify |
|---|---|
| `ios-ats-arbitrary-loads` | The Info.plist has `NSAllowsArbitraryLoads=true`. Confirm whether any specific exempt domain is actually needed; otherwise this disables ATS for the entire app. |
| `ios-ats-partial-exemption` | `NSAllowsLocalNetworking` / `NSAllowsArbitraryLoadsForMedia` widens trust. Inventory which hosts the app actually needs over HTTP. |
| `ios-keychain-accessible-always` | `kSecAttrAccessibleAlways` / `kSecAttrAccessibleAlwaysThisDeviceOnly` lets locked-device attackers read the item. Switch to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. |
| `ios-trust-all-ssl` | `URLSessionDelegate.urlSession(_:didReceive:completionHandler:)` returns `.useCredential, URLCredential(trust: serverTrust)` without `SecTrustEvaluate`. Catastrophic — replace with explicit pinning. |
| `ios-uiwebview-deprecated` | UIWebView is deprecated since iOS 12 and has known issues. Migrate to WKWebView. |
| `ios-webview-html-concat` | `loadHTMLString` receives an interpolated/concatenated string. If any value originates from a network response or pasteboard, it renders attacker HTML/JS in the app origin. |
| `ios-webview-evaljs-concat` | `evaluateJavaScript` builds the JS payload via Swift interpolation. Any escape from a string literal executes attacker JS in the WebView. |

## Workflow: prefer `/vuln-scout:mobile-audit`

For iOS targets that include both source and bundle resources, point
`/vuln-scout:mobile-audit` at the project root. The driver discovers
`*/Info.plist` and Swift/ObjC sources under `src/`, `Sources/`, or
`Application/`.

If you have an extracted IPA, point the driver at the unzipped Payload
folder. The Info.plist will be at `Payload/AppName.app/Info.plist`.

## Cross-platform parallels

Many of the high-signal Android detectors have an iOS analog. When you see a
chain on Android, consider whether the iOS app has the same one:

| Android | iOS analog |
|---|---|
| `mobile-webview-js-injection` | `ios-webview-evaljs-concat` |
| `mobile-nsc-narrow-pinning` | `ios-ats-partial-exemption`, `ios-trust-all-ssl` |
| `mobile-shared-prefs-sensitive` | `ios-keychain-accessible-always`, NSUserDefaults misuse |
| `mobile-insecure-tls` | `ios-trust-all-ssl` |

See also [[mobile-android]] for the Android counterpart.
