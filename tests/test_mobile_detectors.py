"""Tests for mobile / decompiled-APK detectors and third-party path filtering.

These tests pin the high-signal patterns we rely on for Android whitebox
review (Chase-PIE / FirstData remote-URL pattern, JS literal assembly,
network_security_config gaps, exported component without permission,
trust-all TLS managers) and the noise reductions we made to the legacy
detectors (skipping kotlin/, androidx/, com/google/android/ etc.).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "vuln-scout" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


vcd = _load("vuln_class_detectors", SCRIPTS_DIR / "vuln_class_detectors.py")


class ThirdPartyPathFilterTests(unittest.TestCase):
    """Lock the path-exclusion heuristics so refactors can't accidentally
    re-introduce the noise that decompiled-APK scans surface."""

    def test_excluded_dirs_only_checked_relative_to_scan_root(self):
        # Bug 23: when the user's scan target sits under a directory
        # named like an excluded one (e.g., /Users/me/build/myapp),
        # the OLD _is_excluded check against absolute path.parts would
        # exclude every file in the target. After the fix, only parts
        # AFTER the root count.
        # path = /scan/root/build/app/src/main/X.java (where 'build' is
        # in EXCLUDED_DIRS) — but the scan root is /scan/root/build/app,
        # so 'build' is in the root, not the relative path.
        root = Path("/scan/root/build/app")
        good_file = Path("/scan/root/build/app/src/main/X.java")
        self.assertFalse(
            vcd._is_excluded(good_file, root=root),
            "_is_excluded should only check parts AFTER root — ancestor"
            " 'build' must not exclude files under the scan target",
        )
        # And without root, the old behavior is preserved
        self.assertTrue(vcd._is_excluded(good_file),
                        "back-compat: no-root call still uses absolute parts")
        # And a file actually inside an excluded dir within the target
        # still excludes correctly
        bad_file = Path("/scan/root/build/app/build/cached/Y.java")
        self.assertTrue(vcd._is_excluded(bad_file, root=root))

    def test_ios_pods_is_excluded(self):
        # CocoaPods dependencies must be skipped — third-party code
        # the operator can't fix from their app source tree.
        self.assertTrue(vcd._is_excluded(Path("Pods/AFNetworking/AFHTTPSessionManager.m")))

    def test_carthage_is_excluded(self):
        self.assertTrue(vcd._is_excluded(Path("Carthage/Build/iOS/Foo.swift")))

    def test_swiftpm_is_excluded(self):
        self.assertTrue(vcd._is_excluded(Path(".swiftpm/checkouts/foo/Sources/X.swift")))

    def test_derived_data_is_excluded(self):
        self.assertTrue(vcd._is_excluded(Path("DerivedData/Build/intermediates/Foo.swift")))

    def test_kotlin_root_is_third_party(self):
        self.assertTrue(vcd._is_third_party_path(Path("kotlin/SynchronizedLazyImpl.java")))

    def test_kotlinx_coroutines_is_third_party(self):
        self.assertTrue(vcd._is_third_party_path(Path("kotlinx/coroutines/JobSupport.java")))

    def test_androidx_is_third_party(self):
        self.assertTrue(vcd._is_third_party_path(Path("androidx/work/impl/Foo.java")))

    def test_user_app_with_android_segment_not_third_party(self):
        # User app packages like com.example.app.* should NOT be filtered
        # even though "android" appears as a path segment.
        self.assertFalse(vcd._is_third_party_path(
            Path("com/example/app/payment/processors/services/chase/api/a.java")
        ))

    def test_com_google_android_is_third_party(self):
        self.assertTrue(vcd._is_third_party_path(Path("com/google/android/gms/X.java")))

    def test_threatmetrix_is_third_party(self):
        self.assertTrue(vcd._is_third_party_path(Path("com/lexisnexisrisk/threatmetrix/Y.java")))

    def test_absolute_path_under_source_root_is_filtered(self):
        # Absolute paths via FileIndex should still work because
        # _effective_parts strips up to the source root marker.
        self.assertTrue(vcd._is_third_party_path(
            Path("/Users/me/bug-bounty/example/target/jadx_out/sources/kotlin/X.java")
        ))

    def test_absolute_user_app_path_not_filtered(self):
        self.assertFalse(vcd._is_third_party_path(
            Path("/Users/me/bug-bounty/example/target/jadx_out/sources/com/example/app/payment/X.java")
        ))

    def test_defpackage_is_third_party(self):
        # jadx parks proguard-stripped classes in `defpackage/`. These are
        # always third-party SDK code (Nimbus JOSE, Braintree internals,
        # etc.) whose package got minified away; never user-actionable.
        self.assertTrue(vcd._is_third_party_path(Path("defpackage/r2d.java")))
        self.assertTrue(vcd._is_third_party_path(Path("defpackage/gsh.java")))
        self.assertTrue(vcd._is_third_party_path(
            Path("/Users/me/bug-bounty/example/target/jadx_out/sources/defpackage/r2d.java")
        ))


class WebViewJsInjectionTests(unittest.TestCase):
    def test_detects_chase_pie_pattern(self):
        # Mimics jadx-decompiled com/example/.../payment/js/a.java including the
        # "literal, identifier, literal" multi-arg call shape that real
        # decompiled tokenization helpers produce.
        sample = r"""
package com.example.app.payment.processors.services.chase.js;
public final class a {
    public final String b(ap1 ap1Var, cja cjaVar) {
        int i = cjaVar.a;
        int i2 = cjaVar.b;
        String str = cjaVar.c;
        String str2 = cjaVar.d;
        StringBuilder sbC = no.c(i, i2, "var PIE = {L:", ",E:", ",K:\"");
        qn0.e(sbC, str, "\",key_id:\"", str2, "\",phase:");
        StringBuilder sbG = ue0.g("<script>", "x", "</script>");
        return apf.p(sbG.toString());
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.java").write_text(sample)
            findings = vcd.detect_webview_js_injection(root)
            self.assertTrue(
                any(f["type"] == "mobile-webview-js-injection" for f in findings),
                f"expected JS injection finding, got: {findings}",
            )

    def test_skips_files_without_js_payload(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "plain.java").write_text(
                'class Plain { void f() { System.out.println("hello"); } }'
            )
            findings = vcd.detect_webview_js_injection(root)
            self.assertEqual(findings, [])

    def test_title_does_not_carry_confidence_parenthetical(self):
        # A file that builds a JS literal but has no WebView reference is
        # lower-confidence — that signal must live in `confidence` metadata,
        # NOT in the title (which downstream tooling uses for dedup).
        sample = r"""
package com.example.app.helper;
public final class JsHelper {
    public String build(String token, String userId) {
        StringBuilder sbC = no.c(1, 2, "var X = ", token, ", Y = ");
        StringBuilder sbS = ue0.g("<script>", "x", "</script>");
        return sbS.toString();
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "JsHelper.java").write_text(sample)
            findings = vcd.detect_webview_js_injection(root)
            self.assertTrue(findings, "expected at least one finding")
            f = findings[0]
            # Title MUST NOT include the parenthetical confidence note.
            self.assertNotIn("no WebView reference", f["title"])
            self.assertNotIn("verify dispatch path", f["title"])
            # Confidence MUST be structured.
            self.assertEqual(f.get("confidence"), "low")


class RemoteControlledUrlTests(unittest.TestCase):
    def test_detects_first_data_url_pattern(self):
        sample = """
package com.example.app.payment.processors.services.firstdata.api;
import com.example.app.networking.CoroutineCallFactory;
public final class FirstDataTokenizeCardApi {
    public final String invoke() {
        return this.a.getString("FIRST_DATA_URL", "https://api.paysecure.acculynk.net").concat("/X");
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "services").mkdir()
            (root / "services" / "firstdata.java").write_text(sample)
            findings = vcd.detect_remote_controlled_url(root)
            self.assertTrue(
                any(f["type"] == "mobile-remote-controlled-endpoint" for f in findings),
                f"expected remote-controlled-endpoint finding, got: {findings}",
            )


class NetworkSecurityConfigTests(unittest.TestCase):
    def test_detects_narrow_pinning(self):
        sample = """<?xml version="1.0"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">usebutton.com</domain>
        <pin-set>
            <pin digest="SHA-256">aaaa</pin>
        </pin-set>
    </domain-config>
</network-security-config>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "network_security_config.xml").write_text(sample)
            findings = vcd.detect_network_security_config_gaps(root)
            self.assertTrue(
                any(f["type"] == "mobile-nsc-narrow-pinning" for f in findings),
                f"expected narrow-pinning finding, got: {findings}",
            )

    def test_detects_no_pinning(self):
        sample = """<?xml version="1.0"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false"/>
</network-security-config>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "network_security_config.xml").write_text(sample)
            findings = vcd.detect_network_security_config_gaps(root)
            self.assertTrue(
                any(f["type"] == "mobile-nsc-no-pinning" for f in findings)
            )

    def test_detects_cleartext_traffic(self):
        sample = """<?xml version="1.0"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true"/>
</network-security-config>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "network_security_config.xml").write_text(sample)
            findings = vcd.detect_network_security_config_gaps(root)
            self.assertTrue(any(f["type"] == "mobile-nsc-cleartext" for f in findings))


class AndroidManifestTests(unittest.TestCase):
    def test_exported_activity_without_permission(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".FooActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            self.assertTrue(
                any(f["type"] == "mobile-exported-component-no-permission" for f in findings),
            )

    def test_exported_with_permission_skipped(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".FooActivity" android:exported="true"
                  android:permission="com.example.FOO_PERMISSION"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            self.assertFalse(
                any(f["type"] == "mobile-exported-component-no-permission" for f in findings),
                "permission-guarded exported component should not be flagged",
            )

    def test_exported_component_finding_names_the_component(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name="com.example.app.DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="example"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            exported = [f for f in findings if f["type"] == "mobile-exported-component-no-permission"]
            self.assertEqual(len(exported), 1)
            fnd = exported[0]
            self.assertIn("DeepLinkActivity", fnd["title"])
            meta = fnd.get("metadata", {})
            self.assertEqual(meta.get("component_name"), "com.example.app.DeepLinkActivity")
            self.assertEqual(meta.get("component_kind"), "activity")
            self.assertIn("example", meta.get("intent_schemes", []))

    def test_unrestricted_custom_scheme_deeplink_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="myapp"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            self.assertTrue(
                any(f["type"] == "mobile-deeplink-unrestricted" for f in findings),
                f"expected unrestricted-deeplink finding, got types: {[f['type'] for f in findings]}",
            )

    def test_deeplink_with_host_restriction_skipped(self):
        # Same activity but with android:host — much narrower attack surface,
        # so we don't fire the extra mobile-deeplink-unrestricted finding.
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="myapp" android:host="open.example.com"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            self.assertFalse(
                any(f["type"] == "mobile-deeplink-unrestricted" for f in findings),
                "deeplink with host restriction should not produce unrestricted-deeplink finding",
            )

    def test_https_deeplink_not_flagged_unrestricted(self):
        # https:// app-link is gated by digital asset links, not by adb side-load.
        # We deliberately don't fire the unrestricted-deeplink finding for it.
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".AppLinkActivity" android:exported="true">
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="https"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            self.assertFalse(
                any(f["type"] == "mobile-deeplink-unrestricted" for f in findings),
                "https scheme deeplink should not trigger mobile-deeplink-unrestricted",
            )

    def test_exported_custom_scheme_activity_marked_high(self):
        # Custom-scheme deeplink → high severity. Any web page can dispatch
        # via Intent.parseUri; the activity must defensively reject untrusted
        # URI data on every code path.
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".PaymentDeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="myappscheme"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            exported = [f for f in findings if f["type"] == "mobile-exported-component-no-permission"]
            self.assertTrue(exported)
            self.assertEqual(exported[0]["severity"], "high")

    def test_exported_https_only_activity_stays_medium(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".AppLinkActivity" android:exported="true">
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="https" android:host="example.com"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            exported = [f for f in findings if f["type"] == "mobile-exported-component-no-permission"]
            self.assertTrue(exported)
            self.assertEqual(exported[0]["severity"], "medium")

    def test_exported_activity_no_filter_marked_low(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".OrphanActivity" android:exported="true"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            exported = [f for f in findings if f["type"] == "mobile-exported-component-no-permission"]
            self.assertTrue(exported)
            self.assertEqual(exported[0]["severity"], "low")

    def test_compose_preview_activity_not_flagged_as_exported(self):
        # androidx.compose.ui.tooling.PreviewActivity is debug tooling that
        # ships with compose. It's exported by design but exposes no app
        # behavior — flagging it would be unfixable noise.
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name="androidx.compose.ui.tooling.PreviewActivity"
                  android:exported="true"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            self.assertFalse(
                any(f["type"] == "mobile-exported-component-no-permission" for f in findings),
                "compose PreviewActivity should be filtered as framework debug tooling",
            )

    def test_debuggable_build_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:debuggable="true"/>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_manifest_issues(root)
            self.assertTrue(any(f["type"] == "mobile-debuggable-build" for f in findings))


class InsecureTLSTests(unittest.TestCase):
    def test_empty_check_server_trusted_with_comment_flagged(self):
        # Bug 25: pre-fix, an empty body containing a // comment failed
        # the `\s*` check, missing this common shape.
        sample = """
class Trust implements X509TrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // intentionally empty — accepts all certs
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Trust.java").write_text(sample)
            findings = vcd.detect_insecure_tls(root)
            self.assertTrue(
                any(f["type"] == "mobile-insecure-tls" for f in findings),
                f"expected insecure-tls for commented empty body, got: {findings}",
            )

    def test_empty_check_server_trusted_flagged(self):
        sample = """
package com.example.net;
import javax.net.ssl.X509TrustManager;
class Trust implements X509TrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String authType) { }
    public void checkClientTrusted(X509Certificate[] chain, String authType) { }
    public X509Certificate[] getAcceptedIssuers() { return null; }
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Trust.java").write_text(sample)
            findings = vcd.detect_insecure_tls(root)
            self.assertTrue(any(f["type"] == "mobile-insecure-tls" for f in findings))


class HardcodedSecretsTests(unittest.TestCase):
    def test_github_oauth_token_variants_flagged(self):
        # Bug 26: pre-fix, regex only matched ghp_ prefix. GitHub also
        # uses gho_ (OAuth), ghu_ (user), ghs_ (server), ghr_ (refresh) —
        # all 36-char body. Plus github_pat_ (fine-grained PATs) with
        # underscores allowed.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "T.java").write_text(
                'String oa = "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";\n'
                'String us = "ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";\n'
                'String sv = "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";\n'
                'String rf = "ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";\n'
                'String fg = "github_pat_11ABCDE0123456789_aBcDeFg012345678901234567890";\n'
            )
            findings = vcd.detect_hardcoded_secrets_simple(root)
            self.assertGreaterEqual(
                len(findings), 5,
                f"expected 5+ GitHub token variants, got: {[f['type'] for f in findings]}",
            )

    def test_aws_key_flagged(self):
        # Use AKIA prefix + 16 alphanumerics
        sample = 'String key = "AKIAIOSFODNN7EXAMPLE";'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Conf.java").write_text(sample)
            findings = vcd.detect_hardcoded_secrets_simple(root)
            self.assertTrue(any(f["type"] == "secret-hardcoded" for f in findings))

    def test_private_key_block_flagged(self):
        sample = """
String pem = "-----BEGIN RSA PRIVATE KEY-----\\n" +
             "MIIBOgIBAAJBAL...\\n" +
             "-----END RSA PRIVATE KEY-----";
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Crypto.java").write_text(sample)
            findings = vcd.detect_hardcoded_secrets_simple(root)
            self.assertTrue(any(f["type"] == "secret-private-key" for f in findings))


class RaceConditionNoiseReductionTests(unittest.TestCase):
    """The Kotlin/Java `static volatile Lazy` pattern was previously generating
    ~900 findings per APK. Pin the new behavior so a refactor can't bring it back.
    """

    def test_static_volatile_not_flagged_in_java(self):
        sample = """
package com.example;
class Cache {
    static volatile int counter = 0;
    static long timestamp;
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Cache.java").write_text(sample)
            findings = vcd.detect_race_conditions(root)
            # Java is no longer included in the file-system TOCTOU detector at all.
            self.assertFalse(
                any(f["type"] == "race-condition" for f in findings),
                f"Java static/volatile should not trigger race-condition findings, got {findings}",
            )

    def test_parameterized_room_query_not_flagged(self):
        sample = """
def fetch(work_id):
    return db.execute('SELECT * FROM SystemIdInfo WHERE work_spec_id=? AND generation=?', (work_id, 1))
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "fetch.py").write_text(sample)
            findings = vcd.detect_race_conditions(root)
            # Parameterized SELECT with no concat should not trigger the new TOCTOU pattern.
            self.assertFalse(
                any(f["type"] == "race-condition" for f in findings),
            )

    def test_concatenated_sql_still_flagged(self):
        sample = """
def fetch(uid):
    return db.execute("SELECT * FROM users WHERE id='" + uid + "'")
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "fetch.py").write_text(sample)
            findings = vcd.detect_race_conditions(root)
            self.assertTrue(any(f["type"] == "race-condition" for f in findings))


class CorsNoiseReductionTests(unittest.TestCase):
    def test_origin_substring_in_toString_not_flagged(self):
        # Mirrors decompiled toString() builders that previously matched the
        # naive ``(?:allow_origin|allowed_origins|origin).*null`` regex.
        sample = """
class Route {
    public String toString() {
        return "Route(origin=" + origin + ", destination=" + dest + ", value=null)";
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Route.java").write_text(sample)
            findings = vcd.detect_cors_misconfig(root)
            self.assertEqual(findings, [], "decompiled Java toString should not match CORS")

    def test_real_cors_null_allowed_flagged(self):
        sample = """
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'null');
    next();
});
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "server.js").write_text(sample)
            findings = vcd.detect_cors_misconfig(root)
            self.assertTrue(any(f["type"] == "cors-misconfig" for f in findings))


class InsecureCryptoTests(unittest.TestCase):
    def test_md5_flagged(self):
        sample = 'MessageDigest.getInstance("MD5");'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Hash.java").write_text(sample)
            findings = vcd.detect_insecure_crypto(root)
            self.assertTrue(any(f["type"] == "mobile-insecure-crypto" for f in findings))

    def test_aes_default_mode_flagged(self):
        sample = 'Cipher.getInstance("AES");'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Aes.java").write_text(sample)
            findings = vcd.detect_insecure_crypto(root)
            self.assertTrue(any(f["type"] == "mobile-insecure-crypto" for f in findings))

    def test_sha256_not_flagged(self):
        sample = 'MessageDigest.getInstance("SHA-256");'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Hash.java").write_text(sample)
            findings = vcd.detect_insecure_crypto(root)
            self.assertEqual(findings, [])

    def test_random_in_token_context_flagged(self):
        sample = 'long tokenSeed = new Random().nextLong();'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "T.java").write_text(sample)
            findings = vcd.detect_insecure_crypto(root)
            self.assertTrue(any(f["type"] == "mobile-insecure-random" for f in findings))


class SensitiveSharedPrefsTests(unittest.TestCase):
    def test_access_token_flagged(self):
        sample = 'editorEdit.putString("access_token", token).apply();'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.java").write_text(sample)
            findings = vcd.detect_sensitive_sharedprefs(root)
            # Need a getSharedPreferences/edit() context for the detector
            (root / "Auth.java").write_text(
                "void store() { editorEdit.edit().putString(\"access_token\", token).apply(); }"
            )
            findings = vcd.detect_sensitive_sharedprefs(root)
            self.assertTrue(any(f["type"] == "mobile-shared-prefs-sensitive" for f in findings))

    def test_encrypted_prefs_skipped(self):
        # Files that use EncryptedSharedPreferences should not be flagged
        sample = """
EncryptedSharedPreferences prefs = ...;
prefs.edit().putString("access_token", token).apply();
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.java").write_text(sample)
            findings = vcd.detect_sensitive_sharedprefs(root)
            self.assertEqual(findings, [])

    def test_finding_names_the_pref_keys(self):
        # The title and metadata should surface the actual key name(s) being
        # stored, so reviewers can see exactly which token is at risk.
        sample = (
            'void store() {\n'
            '  prefs.edit()\n'
            '    .putString("access_token", t)\n'
            '    .putString("refresh_token", r)\n'
            '    .putString("user_pin", p)\n'
            '    .apply();\n'
            '}\n'
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.java").write_text(sample)
            findings = vcd.detect_sensitive_sharedprefs(root)
            self.assertTrue(findings)
            f = findings[0]
            keys = (f.get("metadata") or {}).get("pref_keys") or []
            self.assertIn("access_token", keys)
            self.assertIn("refresh_token", keys)
            self.assertIn("user_pin", keys)
            self.assertIn("access_token", f["title"])


class LogSensitiveTests(unittest.TestCase):
    def test_status_message_not_flagged(self):
        # Pure literal status message — must NOT trigger
        sample = 'Log.w("FirebaseMessaging", "FIS auth token is empty");'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "L.java").write_text(sample)
            findings = vcd.detect_log_sensitive_data(root)
            self.assertEqual(findings, [], "literal-only log message should not trigger")

    def test_token_var_interpolated_flagged(self):
        sample = 'Log.d("X", "got token=" + accessToken);'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "L.java").write_text(sample)
            findings = vcd.detect_log_sensitive_data(root)
            self.assertTrue(
                any(f["type"] == "mobile-log-sensitive" for f in findings),
                f"interpolated access token should be flagged: {findings}",
            )

    def test_exception_log_not_flagged(self):
        # Throwable arg only
        sample = 'Log.e("X", "auth failed", e);'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "L.java").write_text(sample)
            findings = vcd.detect_log_sensitive_data(root)
            self.assertEqual(findings, [])


class StorageBackupTests(unittest.TestCase):
    def test_allow_backup_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:allowBackup="true"/>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_storage_backup_issues(root)
            self.assertTrue(any(f["type"] == "mobile-allow-backup-true" for f in findings))

    def test_cleartext_traffic_allowed_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="true"/>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_storage_backup_issues(root)
            self.assertTrue(
                any(f["type"] == "mobile-cleartext-traffic-allowed" for f in findings),
                f"expected cleartext-traffic finding, got: {[f['type'] for f in findings]}",
            )

    def test_cleartext_traffic_false_not_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="false"/>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_storage_backup_issues(root)
            self.assertFalse(
                any(f["type"] == "mobile-cleartext-traffic-allowed" for f in findings),
                "cleartext=false must not trigger the cleartext-traffic finding",
            )

    def test_exported_provider_no_permission_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <provider android:name=".X" android:exported="true" android:authorities="com.example.x"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_storage_backup_issues(root)
            self.assertTrue(any(f["type"] == "mobile-exported-provider" for f in findings))


class SqlInjectionProseRejectionTests(unittest.TestCase):
    """Regression: ``"...update repo: " + var + "..."`` log lines were
    previously flagged as SQL injection because the regex matched a bare
    SQL keyword followed by a quoted+concat pattern. The tightened regex
    now requires SQL syntax (FROM/INTO/SET/WHERE/VALUES) between the
    keyword and the concat point.
    """

    def test_prose_in_log_not_flagged(self):
        sample = 'l.v("[Active Trips] Should update repo: " + z + ". Current: " + v + ".");'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "L.java").write_text(sample)
            findings = vcd.detect_sql_injection(root)
            self.assertEqual(findings, [], "log prose should not match SQL detector")

    def test_real_select_concat_still_flagged(self):
        sample = "db.execute(\"SELECT * FROM users WHERE id='\" + uid + \"'\");"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "fetch.js").write_text(sample)
            findings = vcd.detect_sql_injection(root)
            self.assertTrue(any(f["type"] == "sql-injection" for f in findings))


class InsecureDeserializationTests(unittest.TestCase):
    def test_object_input_stream_flagged(self):
        sample = """
import java.io.ObjectInputStream;
class A {
    void f(byte[] data) {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        ois.readObject();
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "A.java").write_text(sample)
            findings = vcd.detect_insecure_deserialization(root)
            self.assertTrue(any(f["type"] == "mobile-insecure-deserialization" for f in findings))


class IosOpenUrlRedirectionTests(unittest.TestCase):
    def test_open_url_with_variable_flagged(self):
        sample = (
            'let target = pushPayload["url"]\n'
            'UIApplication.shared.open(URL(string: target)!)\n'
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Router.swift").write_text(sample)
            findings = vcd.detect_ios_open_url_with_input(root)
            self.assertTrue(
                any(f["type"] == "ios-open-url-redirection" for f in findings),
            )

    def test_open_url_with_literal_not_flagged(self):
        # Constant URL literal is fine.
        sample = (
            'UIApplication.shared.open(URL(string: "https://example.com")!)\n'
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Router.swift").write_text(sample)
            findings = vcd.detect_ios_open_url_with_input(root)
            self.assertEqual(findings, [])


class IosLogSensitiveTests(unittest.TestCase):
    def test_swift_print_with_token_flagged(self):
        sample = (
            'let accessToken = fetchToken()\n'
            'print("auth: \\(accessToken)")\n'
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.swift").write_text(sample)
            findings = vcd.detect_ios_log_sensitive(root)
            self.assertTrue(
                any(f["type"] == "ios-log-sensitive" for f in findings),
                f"expected ios-log-sensitive, got: {[f['type'] for f in findings]}",
            )

    def test_nslog_pure_literal_not_flagged(self):
        sample = 'NSLog("user logged in successfully");\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.m").write_text(sample)
            findings = vcd.detect_ios_log_sensitive(root)
            self.assertEqual(findings, [])


class ProviderGrantUriTests(unittest.TestCase):
    def test_grant_uri_permissions_true_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <provider android:name=".P" android:exported="false" android:grantUriPermissions="true" android:authorities="com.example.p"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_storage_backup_issues(root)
            self.assertTrue(
                any(f["type"] == "mobile-provider-grant-uri-permissions" for f in findings),
                f"expected provider-grant-uri finding, got: {[f['type'] for f in findings]}",
            )

    def test_grant_uri_permissions_false_not_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <provider android:name=".P" android:exported="false" android:grantUriPermissions="false" android:authorities="com.example.p"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_android_storage_backup_issues(root)
            self.assertFalse(
                any(f["type"] == "mobile-provider-grant-uri-permissions" for f in findings),
            )


class TaskAffinityTests(unittest.TestCase):
    def test_singletask_with_taskaffinity_flagged(self):
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".X" android:launchMode="singleTask" android:taskAffinity="com.attacker.shared"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_task_affinity_abuse(root)
            self.assertTrue(
                any(f["type"] == "mobile-task-affinity-hijack" for f in findings),
            )

    def test_singletask_alone_not_flagged(self):
        # `singleTask` alone is a legitimate launch mode — flag only with
        # the taskAffinity combo.
        sample = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".X" android:launchMode="singleTask"/>
    </application>
</manifest>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AndroidManifest.xml").write_text(sample)
            findings = vcd.detect_task_affinity_abuse(root)
            self.assertEqual(findings, [])


class DynamicReceiverTests(unittest.TestCase):
    def test_two_arg_registerReceiver_flagged(self):
        sample = "ctx.registerReceiver(receiver, filter);\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "X.java").write_text(sample)
            findings = vcd.detect_dynamic_receiver_no_perm(root)
            self.assertTrue(
                any(f["type"] == "mobile-dynamic-receiver-unprotected" for f in findings),
            )

    def test_receiver_not_exported_skipped(self):
        # File mentioning RECEIVER_NOT_EXPORTED is the safe form.
        sample = (
            "import static android.content.Context.RECEIVER_NOT_EXPORTED;\n"
            "ctx.registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED);\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "X.java").write_text(sample)
            findings = vcd.detect_dynamic_receiver_no_perm(root)
            self.assertEqual(findings, [])


class HardcodedHttpUrlTests(unittest.TestCase):
    def test_http_url_flagged(self):
        sample = 'String API = "http://api.example.com/v1/data";\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Api.java").write_text(sample)
            findings = vcd.detect_hardcoded_http_url(root)
            self.assertTrue(
                any(f["type"] == "mobile-hardcoded-http-url" for f in findings),
            )

    def test_localhost_not_flagged(self):
        sample = (
            'String DEV = "http://localhost:8080/api";\n'
            'String LAN = "http://192.168.1.5/cmd";\n'
            'String P = "http://127.0.0.1/loop";\n'
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Api.java").write_text(sample)
            findings = vcd.detect_hardcoded_http_url(root)
            self.assertEqual(findings, [])

    def test_https_not_flagged(self):
        sample = 'String API = "https://api.example.com/v1/data";\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Api.java").write_text(sample)
            findings = vcd.detect_hardcoded_http_url(root)
            self.assertEqual(findings, [])


class TapjackingTests(unittest.TestCase):
    def test_filter_touches_false_flagged(self):
        sample = (
            "class V { void setup() {\n"
            "  payButton.setFilterTouchesWhenObscured(false);\n"
            "}}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "V.java").write_text(sample)
            findings = vcd.detect_tapjacking_disabled(root)
            self.assertTrue(
                any(f["type"] == "mobile-tapjacking-disabled" for f in findings),
                f"expected tapjacking finding, got: {findings}",
            )

    def test_filter_touches_true_not_flagged(self):
        sample = "payButton.setFilterTouchesWhenObscured(true);\n"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "V.java").write_text(sample)
            findings = vcd.detect_tapjacking_disabled(root)
            self.assertEqual(findings, [])


class RuntimeExecTests(unittest.TestCase):
    def test_runtime_exec_flagged(self):
        sample = 'Runtime.getRuntime().exec(cmd);'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "R.java").write_text(sample)
            findings = vcd.detect_runtime_exec(root)
            self.assertTrue(any(f["type"] == "mobile-runtime-exec" for f in findings))

    def test_root_detection_class_name_suppresses_runtime_exec(self):
        # Apps that probe `Runtime.exec` from a class named RootDetection*
        # are doing intentional su-binary probing, not tainted exec.
        sample = (
            'package com.example.security;\n'
            'class RootDetectionService {\n'
            '    void check() { new ProcessBuilder("/system/xbin/su").start(); }\n'
            '}\n'
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "RootDetectionService.java").write_text(sample)
            findings = vcd.detect_runtime_exec(root)
            self.assertEqual(
                findings, [],
                "root-detection probe should not produce mobile-runtime-exec",
            )

    def test_su_path_literal_suppresses_runtime_exec(self):
        # Even if the class name doesn't hint at root detection, a hardcoded
        # SU binary path literal in the same file is strong evidence this
        # is root probing rather than a tainted exec sink.
        sample = 'Process p = Runtime.getRuntime().exec("/system/xbin/su");\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Probe.java").write_text(sample)
            findings = vcd.detect_runtime_exec(root)
            self.assertEqual(findings, [])


class WebViewMixedContentTests(unittest.TestCase):
    def test_mixed_content_always_allow_flagged(self):
        sample = 'webView.getSettings().setMixedContentMode(0);'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "W.java").write_text(sample)
            findings = vcd.detect_webview_mixed_content(root)
            self.assertTrue(any(f["type"] == "mobile-webview-mixed-content" for f in findings))

    def test_compatibility_mode_not_flagged(self):
        sample = 'webView.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "W.java").write_text(sample)
            findings = vcd.detect_webview_mixed_content(root)
            self.assertEqual(findings, [])


class HardcodedJwtTests(unittest.TestCase):
    def test_jwt_literal_flagged(self):
        # Three base64url segments
        sample = 'String t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF_xyz";'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "T.java").write_text(sample)
            findings = vcd.detect_hardcoded_jwt(root)
            self.assertTrue(any(f["type"] == "secret-hardcoded-jwt" for f in findings))


class IOSAtsTests(unittest.TestCase):
    def test_arbitrary_loads_flagged(self):
        sample = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
</dict></plist>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Info.plist").write_text(sample)
            findings = vcd.detect_ios_ats_disabled(root)
            self.assertTrue(any(f["type"] == "ios-ats-arbitrary-loads" for f in findings))

    def test_strict_ats_not_flagged(self):
        sample = """<?xml version="1.0"?>
<plist><dict><key>NSAppTransportSecurity</key><dict>
<key>NSExceptionDomains</key><dict>
<key>legacy.example.com</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>
</dict></dict></dict></plist>"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Info.plist").write_text(sample)
            findings = vcd.detect_ios_ats_disabled(root)
            # Should not match arbitrary-loads; partial exemption could still be 0 here
            arb = [f for f in findings if f["type"] == "ios-ats-arbitrary-loads"]
            self.assertEqual(arb, [])


class IOSKeychainTests(unittest.TestCase):
    def test_accessible_always_flagged(self):
        sample = """
import Security
let attrs = [kSecAttrAccessible as String: kSecAttrAccessibleAlways]
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.swift").write_text(sample)
            findings = vcd.detect_ios_keychain_misuse(root)
            self.assertTrue(any(f["type"] == "ios-keychain-accessible-always" for f in findings))

    def test_accessible_when_unlocked_not_flagged(self):
        sample = 'let attrs = [kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.swift").write_text(sample)
            findings = vcd.detect_ios_keychain_misuse(root)
            self.assertEqual(findings, [])


class IOSWebViewTests(unittest.TestCase):
    def test_eval_js_interpolation_flagged(self):
        sample = """
import WebKit
func run(_ token: String) {
    webView.evaluateJavaScript("window.app.setToken(\\(token))", completionHandler: nil)
}
"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "W.swift").write_text(sample)
            findings = vcd.detect_ios_webview_unsafe(root)
            self.assertTrue(
                any(f["type"] == "ios-webview-evaljs-concat" for f in findings),
                f"got: {findings}",
            )

    def test_uiwebview_flagged(self):
        sample = "let view = UIWebView(frame: .zero)"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "W.swift").write_text(sample)
            findings = vcd.detect_ios_webview_unsafe(root)
            self.assertTrue(any(f["type"] == "ios-uiwebview-deprecated" for f in findings))


class MobileChainTests(unittest.TestCase):
    """Verify the new mobile chain detectors fire on Chase-PIE-shape inputs."""

    @staticmethod
    def _load_chain():
        # service_graph is a transitive import of chain_detector
        return (
            _load("service_graph", SCRIPTS_DIR / "service_graph.py"),
            _load("chain_detector", SCRIPTS_DIR / "chain_detector.py"),
        )

    def test_webview_chain_links_url_and_js_in_same_package(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "F1",
                "type": "mobile-remote-controlled-endpoint",
                "file": "com/example/app/payment/processors/services/chase/api/X.java",
                "line": 10,
                "kind": "finding",
                "severity": "high",
            },
            {
                "id": "F2",
                "type": "mobile-webview-js-injection",
                "file": "com/example/app/payment/processors/services/chase/js/a.java",
                "line": 119,
                "kind": "finding",
                "severity": "medium",
            },
            {
                "id": "F3",
                "type": "mobile-webview-js-interface",
                "file": "com/example/app/payment/processors/services/chase/js/EncryptionListener.java",
                "line": 32,
                "kind": "hotspot",
                "severity": "medium",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        webview = [c for c in chains if "WebView dispatch" in c.get("name", "")]
        self.assertTrue(webview, f"expected mobile WebView dispatch chain, got: {chains}")

    def test_mitm_chain_links_pinning_gap_and_remote_url(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "N1",
                "type": "mobile-nsc-narrow-pinning",
                "file": "res/xml/network_security_config.xml",
                "line": 1,
                "kind": "hotspot",
                "severity": "low",
            },
            {
                "id": "U1",
                "type": "mobile-remote-controlled-endpoint",
                "file": "com/example/api/X.java",
                "line": 22,
                "kind": "finding",
                "severity": "high",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        mitm = [c for c in chains if "MITM" in c.get("name", "")]
        self.assertTrue(mitm, f"expected MITM precondition chain, got: {chains}")

    def test_backup_exfil_chain_links_allow_backup_and_plain_prefs(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "B1",
                "type": "mobile-allow-backup-true",
                "file": "AndroidManifest.xml",
                "line": 125,
                "kind": "hotspot",
                "severity": "medium",
            },
            {
                "id": "P1",
                "type": "mobile-shared-prefs-sensitive",
                "file": "com/example/auth/a.java",
                "line": 96,
                "kind": "finding",
                "severity": "high",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        backup = [c for c in chains if "backup-extractable" in c.get("name", "")]
        self.assertTrue(
            backup,
            f"expected backup-extractable token chain, got: {chains}",
        )
        # Both findings should be tagged with the chain id
        self.assertEqual(findings[0]["chain_role"], "entry")
        self.assertEqual(findings[1]["chain_role"], "sink")

    def test_backup_exfil_chain_names_the_exposed_keys(self):
        # When the prefs finding carries metadata.pref_keys, the chain's
        # impact statement should name them so the chain is reportable
        # without opening the underlying findings.
        _, cd = self._load_chain()
        findings = [
            {
                "id": "B1",
                "type": "mobile-allow-backup-true",
                "file": "AndroidManifest.xml",
                "line": 125,
                "kind": "hotspot",
                "severity": "medium",
            },
            {
                "id": "P1",
                "type": "mobile-shared-prefs-sensitive",
                "file": "com/example/auth/a.java",
                "line": 96,
                "kind": "finding",
                "severity": "high",
                "metadata": {"pref_keys": ["access_token", "refresh_token", "user_pin"]},
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        backup = [c for c in chains if "backup-extractable" in c.get("name", "")]
        self.assertTrue(backup)
        impact = backup[0].get("impact", "")
        self.assertIn("access_token", impact)
        self.assertIn("refresh_token", impact)
        self.assertIn("user_pin", impact)

    def test_deeplink_webview_chain_links_exported_intent_and_js_injection(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "E1",
                "type": "mobile-exported-component-no-permission",
                "file": "AndroidManifest.xml",
                "line": 100,
                "kind": "hotspot",
                "severity": "medium",
                "metadata": {
                    "component_name": "com.example.app.DeepLinkActivity",
                    "intent_schemes": ["myapp", "https"],
                },
            },
            {
                "id": "W1",
                "type": "mobile-webview-js-injection",
                "file": "com/example/app/web/WebViewHelper.java",
                "line": 42,
                "kind": "finding",
                "severity": "high",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        deeplink_chain = [c for c in chains if "deeplink" in c.get("name", "").lower()]
        self.assertTrue(
            deeplink_chain,
            f"expected deeplink→WebView chain, got: {chains}",
        )
        self.assertEqual(findings[0]["chain_role"], "entry")
        self.assertEqual(findings[1]["chain_role"], "sink")

    def test_deeplink_webview_chain_fires_for_host_wildcard(self):
        # Wildcard-host deeplink should also chain with a WebView finding.
        _, cd = self._load_chain()
        findings = [
            {
                "id": "H1",
                "type": "mobile-deeplink-host-wildcard",
                "file": "AndroidManifest.xml",
                "line": 88,
                "kind": "hotspot",
                "severity": "medium",
            },
            {
                "id": "W1",
                "type": "mobile-webview-js-interface",
                "file": "com/example/app/WebViewHelper.java",
                "line": 42,
                "kind": "finding",
                "severity": "high",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertTrue(
            any("deeplink" in c.get("name", "").lower() for c in chains),
            f"expected deeplink→WebView chain triggered by host-wildcard, got: {chains}",
        )

    def test_deeplink_webview_chain_silent_without_webview(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "E1",
                "type": "mobile-deeplink-unrestricted",
                "file": "AndroidManifest.xml",
                "line": 100,
                "kind": "finding",
                "severity": "medium",
                "metadata": {"intent_schemes": ["myapp"]},
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("deeplink" in c.get("name", "").lower() for c in chains),
            "must not synthesize deeplink chain without a WebView finding",
        )

    def test_backup_exfil_chain_silent_without_allow_backup(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "P1",
                "type": "mobile-shared-prefs-sensitive",
                "file": "com/example/auth/a.java",
                "line": 96,
                "kind": "finding",
                "severity": "high",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("backup-extractable" in c.get("name", "") for c in chains),
            "must not synthesize backup chain when allowBackup finding is absent",
        )

    def test_permission_relay_chain_links_exported_and_intent_redirection(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "E1",
                "type": "mobile-exported-component-no-permission",
                "file": "AndroidManifest.xml",
                "line": 50,
                "kind": "hotspot",
                "severity": "medium",
                "metadata": {
                    "component_name": "com.example.app.Trampoline",
                    "component_kind": "activity",
                },
            },
            {
                "id": "R1",
                "type": "mobile-intent-redirection",
                "file": "com/example/app/Trampoline.java",
                "line": 78,
                "kind": "finding",
                "severity": "high",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        relay_chain = [c for c in chains if "permission-relay" in c.get("name", "").lower()]
        self.assertTrue(
            relay_chain,
            f"expected permission-relay chain, got: {chains}",
        )
        self.assertEqual(findings[0]["chain_role"], "entry")
        self.assertEqual(findings[1]["chain_role"], "sink")
        chain = relay_chain[0]
        self.assertIn("Trampoline", chain.get("flow_description", ""))
        self.assertIn("E1", chain.get("finding_ids", []))
        self.assertIn("R1", chain.get("finding_ids", []))

    def test_low_confidence_chain_member_gets_boosted_to_medium(self):
        # A finding that's low-confidence in isolation but lands in a chain
        # should be promoted to medium with an audit trail. (Chain context
        # corroborates the dispatch path the in-file check couldn't see.)
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "confidence": "low"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertTrue(chains)
        p1 = next(f for f in findings if f["id"] == "P1")
        self.assertEqual(p1["confidence"], "medium")
        self.assertEqual(
            (p1.get("metadata") or {}).get("confidence_boosted_by_chain"),
            p1.get("chain_id"),
        )

    def test_chain_membership_does_not_boost_already_high_confidence(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium",
             "confidence": "high"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "confidence": "high"},
        ]
        _, _ = cd.detect_chains(findings, service_graph=None)
        # confidence must remain `high`, not get clobbered
        self.assertEqual(findings[1]["confidence"], "high")
        # No boost annotation
        self.assertNotIn(
            "confidence_boosted_by_chain",
            findings[1].get("metadata", {}),
        )

    def test_chain_confidence_is_weakest_link_post_boost(self):
        # Chain confidence is the weakest link across participants
        # AFTER the chain-corroborated confidence boost runs. So a low
        # participant that got boosted to medium puts the chain at
        # medium (not at the original low).
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium",
             "confidence": "high"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "confidence": "low"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        backup = next(c for c in chains if "backup-extractable" in c.get("name", ""))
        # P1 was low → boosted to medium by chain context → chain is medium
        self.assertEqual(backup.get("confidence"), "medium")

    def test_chain_carries_cvss_estimate_from_severity(self):
        # Each chain should get a numeric cvss_estimate derived from
        # severity (CVSS-3.1 band midpoint).
        _, cd = self._load_chain()
        findings = [
            {"id": "N1", "type": "mobile-nsc-narrow-pinning",
             "file": "apktool_out/res/xml/network_security_config.xml", "line": 1,
             "kind": "hotspot", "severity": "low", "confidence": "high"},
            {"id": "R1", "type": "mobile-remote-controlled-endpoint",
             "file": "com/example/api/Client.java", "line": 30,
             "kind": "finding", "severity": "critical", "confidence": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        # MITM chain inherits critical severity from the participants.
        mitm = next(c for c in chains if "MITM" in c.get("name", ""))
        self.assertEqual(mitm.get("severity"), "critical")
        self.assertEqual(mitm.get("cvss_estimate"), 9.5)

    def test_chain_confidence_high_when_all_participants_high(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium",
             "confidence": "high"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "confidence": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        backup = next(c for c in chains if "backup-extractable" in c.get("name", ""))
        self.assertEqual(backup.get("confidence"), "high")

    def test_chains_aggregate_cwes_from_impact_and_participants(self):
        # CWE IDs from the chain's own impact prose plus each
        # participant finding's message should land sorted, deduplicated,
        # under chain.cwes.
        _, cd = self._load_chain()
        findings = [
            {"id": "D1", "type": "mobile-debuggable-build",
             "file": "AndroidManifest.xml", "line": 7,
             "kind": "finding", "severity": "high",
             "message": "android:debuggable=true exposes JDWP. (CWE-489)"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["access_token"]},
             "message": "Plain SharedPreferences. (CWE-312)"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        debuggable = next(c for c in chains if "debuggable" in c.get("name", "").lower())
        cwes = debuggable.get("cwes") or []
        # Chain impact for debuggable+secret cites CWE-489 + CWE-200; the
        # prefs participant adds CWE-312; sorted = 200, 312, 489.
        self.assertIn("CWE-200", cwes)
        self.assertIn("CWE-312", cwes)
        self.assertIn("CWE-489", cwes)
        # Sorted numerically: CWE-200, CWE-312, CWE-489
        self.assertEqual(cwes, sorted(cwes, key=lambda s: int(s.split("-")[1])))

    def test_mobile_scan_literal_severity_copies_match_artifact_utils(self):
        # mobile_scan keeps literal copies of SEVERITY_RANK / SEVERITY_ORDER
        # due to lazy-import ordering. This test asserts those literals
        # stay in sync with the canonical constants. A contributor who
        # edits artifact_utils but forgets mobile_scan breaks this test
        # before the drift ships.
        import re as _re
        au = _load("artifact_utils", SCRIPTS_DIR / "artifact_utils.py")
        scan_src = (SCRIPTS_DIR / "mobile_scan.py").read_text()
        # Find both `_SEV_RANK = {...}` and `_SEV_ORDER = [...]` literal copies.
        rank_lit = _re.search(r"_SEV_RANK\s*=\s*(\{[^}]*\})", scan_src)
        order_lit = _re.search(r"_SEV_ORDER\s*=\s*(\[[^\]]*\])", scan_src)
        self.assertIsNotNone(rank_lit, "expected _SEV_RANK literal in mobile_scan")
        self.assertIsNotNone(order_lit, "expected _SEV_ORDER literal in mobile_scan")
        # eval the literal payloads (safe — they're whitespace + dict/list
        # punctuation + the known severity tokens).
        rank_value = eval(rank_lit.group(1))
        order_value = eval(order_lit.group(1))
        self.assertEqual(rank_value, au.SEVERITY_RANK)
        self.assertEqual(order_value, au.SEVERITY_ORDER)

    def test_every_static_mobile_chain_carries_at_least_one_cwe(self):
        # Every static mobile/iOS chain pattern (excluding dynamic
        # ssrf-to-* etc.) must cite at least one CWE in its impact
        # so chain.cwes is never empty. Regression test for N+152.
        _, cd = self._load_chain()
        findings = [
            # Cover every mobile/iOS chain
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "M.xml", "line": 1, "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "p.java", "line": 1, "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["t"]}},
            {"id": "J1", "type": "mobile-webview-js-injection",
             "file": "j.java", "line": 1, "kind": "finding", "severity": "high"},
            {"id": "U1", "type": "mobile-remote-controlled-endpoint",
             "file": "u.java", "line": 1, "kind": "finding", "severity": "high"},
            {"id": "I1", "type": "mobile-webview-js-interface",
             "file": "i.java", "line": 1, "kind": "finding", "severity": "medium"},
            {"id": "N1", "type": "mobile-nsc-narrow-pinning",
             "file": "n.xml", "line": 1, "kind": "hotspot", "severity": "low"},
            {"id": "D1", "type": "mobile-debuggable-build",
             "file": "M.xml", "line": 2, "kind": "finding", "severity": "high"},
            {"id": "L1", "type": "mobile-log-sensitive",
             "file": "l.java", "line": 1, "kind": "hotspot", "severity": "medium",
             "metadata": {"sensitive_idents": ["t"]}},
            {"id": "M1", "type": "graphql-sensitive-client-mutation",
             "file": "g.graphql", "line": 1, "kind": "finding", "severity": "medium",
             "title": "Sensitive GraphQL mutation shipped in client resources: X"},
            {"id": "E1", "type": "mobile-exported-component-no-permission",
             "file": "M.xml", "line": 3, "kind": "hotspot", "severity": "medium",
             "metadata": {"component_name": "X", "intent_schemes": ["s"]}},
            {"id": "R1", "type": "mobile-intent-redirection",
             "file": "r.java", "line": 1, "kind": "finding", "severity": "high"},
            {"id": "DS1", "type": "mobile-insecure-deserialization",
             "file": "d.java", "line": 1, "kind": "finding", "severity": "high"},
            {"id": "IW1", "type": "ios-webview-html-concat",
             "file": "w.swift", "line": 1, "kind": "finding", "severity": "medium"},
            {"id": "IA1", "type": "ios-ats-arbitrary-loads",
             "file": "I.plist", "line": 1, "kind": "finding", "severity": "high"},
            {"id": "IK1", "type": "ios-keychain-accessible-always",
             "file": "a.swift", "line": 1, "kind": "finding", "severity": "high"},
            {"id": "RNG1", "type": "mobile-insecure-random",
             "file": "t.java", "line": 1, "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        empty_cwe_chains = [c for c in chains if not (c.get("cwes") or [])]
        self.assertEqual(
            empty_cwe_chains, [],
            "every static mobile/iOS chain must cite at least one CWE in its impact",
        )

    def test_safe_wrapper_rejects_bool_return(self):
        # Bug 32: isinstance(True, int) is True in Python (bool is
        # subclass of int). A chain function returning True/False would
        # slip past the isinstance(int) check and reset chain_counter
        # to 1/0. Verify the bool guard is in place by reading the
        # source — runtime test would require injecting a buggy pattern.
        cd_src = (SCRIPTS_DIR / "chain_detector.py").read_text()
        self.assertIn("isinstance(result, int) and not isinstance(result, bool)", cd_src,
                      "bool guard missing in _safe() wrapper — chain_counter "
                      "would clobber on bool return")

    def test_chain_confidence_verified_treated_as_strongest(self):
        # Bug 28: _CONFIDENCE_RANK was missing "verified" so a finding
        # marked as confidence="verified" (the strongest level — has a
        # PoC) was incorrectly treated as the WEAKEST (rank 0 default)
        # and the chain got marked confidence="verified" via the
        # min-rank logic.
        _, cd = self._load_chain()
        self.assertIn("verified", cd._CONFIDENCE_RANK)
        self.assertEqual(
            cd._CONFIDENCE_RANK["verified"], 4,
            "verified must be the highest rank",
        )
        self.assertGreater(
            cd._CONFIDENCE_RANK["verified"],
            cd._CONFIDENCE_RANK["high"],
            "verified must outrank high",
        )

    def test_chain_detector_severity_rank_matches_artifact_utils(self):
        # chain_detector aliases artifact_utils.SEVERITY_RANK — if anyone
        # accidentally redefines the local copy as a divergent literal,
        # this test fails. Compare contents (not identity) because the
        # test loader uses spec_from_file_location which creates
        # independent module instances.
        _, cd = self._load_chain()
        au = _load("artifact_utils", SCRIPTS_DIR / "artifact_utils.py")
        self.assertEqual(cd._SEVERITY_RANK, au.SEVERITY_RANK)
        self.assertEqual(set(cd._SEVERITY_RANK), set(au.SEVERITY_RANK))

    def test_chain_detector_public_api_pinned(self):
        # Pin the public __all__ surface — a future contributor adding
        # an internal helper to __all__ (or removing a public name)
        # breaks this test first.
        _, cd = self._load_chain()
        expected = {"detect_chains", "list_chain_patterns", "LAST_PATTERN_FAILURES"}
        self.assertEqual(set(cd.__all__), expected)
        # Every name in __all__ must actually exist on the module.
        for name in cd.__all__:
            self.assertTrue(hasattr(cd, name), f"missing public name: {name}")

    def test_chains_carry_programmatic_pattern_slug(self):
        # Each chain must carry a `pattern` slug so downstream filters
        # can pivot on it programmatically (not substring-match the name).
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertTrue(chains)
        self.assertEqual(chains[0].get("pattern"), "mobile-backup-exfil")

    def test_chain_cwes_propagate_to_member_findings(self):
        # A finding inside a chain should carry chain_cwes aggregated
        # from every chain it participates in.
        _, cd = self._load_chain()
        findings = [
            {"id": "D1", "type": "mobile-debuggable-build",
             "file": "AndroidManifest.xml", "line": 7,
             "kind": "finding", "severity": "high",
             "message": "(CWE-489)"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["access_token"]},
             "message": "(CWE-312)"},
        ]
        _, _ = cd.detect_chains(findings, service_graph=None)
        p1 = next(f for f in findings if f["id"] == "P1")
        cwes = p1.get("chain_cwes") or []
        # P1 is in debuggable+secret chain (CWE-489 + CWE-200) AND
        # backup-extractable chain (CWE-200 + CWE-312). Aggregated set.
        self.assertIn("CWE-200", cwes)
        self.assertIn("CWE-312", cwes)
        self.assertIn("CWE-489", cwes)

    def test_multi_chain_participation_recorded(self):
        # A single finding can land in multiple chains (e.g. a sensitive
        # prefs write lands in both backup-exfil AND token-replay chains).
        # chain_id stays single-valued (back-compat), but
        # chain_participations[] captures every participation.
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["access_token"]}},
            {"id": "M1", "type": "graphql-sensitive-client-mutation",
             "file": "res/raw/x.graphql", "line": 1,
             "kind": "finding", "severity": "medium",
             "title": "Sensitive GraphQL mutation shipped in client resources: SomeMutation"},
        ]
        _, _ = cd.detect_chains(findings, service_graph=None)
        p1 = next(f for f in findings if f["id"] == "P1")
        parts = p1.get("chain_participations") or []
        patterns = {p.get("pattern") for p in parts}
        # P1 should be a participant in both backup-exfil AND token-replay.
        self.assertIn("mobile-backup-exfil", patterns)
        self.assertIn("mobile-token-replay", patterns)
        # chain_id stays single-valued for back-compat
        self.assertIn(p1.get("chain_id"), {part.get("chain_id") for part in parts})

    def test_chain_pattern_propagates_to_member_findings(self):
        # Each finding that lands in a chain should carry chain_pattern,
        # not just chain_id and chain_role.
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertEqual(findings[0]["chain_pattern"], "mobile-backup-exfil")
        self.assertEqual(findings[1]["chain_pattern"], "mobile-backup-exfil")

    def test_every_chain_name_is_registered_in_the_pattern_map(self):
        # Every chain name produced by the detector code MUST have an
        # entry in _CHAIN_NAME_TO_PATTERN (otherwise the slug falls back
        # to slugification, which is unstable and breaks ignore-file
        # rules). This catches "renamed a chain but forgot the map".
        _, cd = self._load_chain()
        # Build inputs that fire every chain we care about
        findings = [
            # Mobile WebView dispatch
            {"id": "J1", "type": "mobile-webview-js-injection",
             "file": "com/example/x/Webview.java", "line": 30,
             "kind": "finding", "severity": "high"},
            {"id": "U1", "type": "mobile-remote-controlled-endpoint",
             "file": "com/example/x/Api.java", "line": 30,
             "kind": "finding", "severity": "high"},
            {"id": "I1", "type": "mobile-webview-js-interface",
             "file": "com/example/x/Bridge.java", "line": 30,
             "kind": "finding", "severity": "medium"},
            # MITM precondition
            {"id": "N1", "type": "mobile-nsc-narrow-pinning",
             "file": "apktool/res/xml/nsc.xml", "line": 1,
             "kind": "hotspot", "severity": "low"},
            # Backup exfil + token replay + debuggable + double-exposure
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["access_token"]}},
            {"id": "L1", "type": "mobile-log-sensitive",
             "file": "com/example/log/Net.java", "line": 22,
             "kind": "hotspot", "severity": "medium",
             "metadata": {"sensitive_idents": ["accessToken"]}},
            {"id": "D1", "type": "mobile-debuggable-build",
             "file": "AndroidManifest.xml", "line": 7,
             "kind": "finding", "severity": "high"},
            {"id": "M1", "type": "graphql-sensitive-client-mutation",
             "file": "res/raw/x.graphql", "line": 1,
             "kind": "finding", "severity": "medium",
             "title": "Sensitive GraphQL mutation shipped in client resources: X"},
            # Deeplink → WebView + permission-relay + gadget-landing
            {"id": "E1", "type": "mobile-exported-component-no-permission",
             "file": "AndroidManifest.xml", "line": 100,
             "kind": "hotspot", "severity": "medium",
             "metadata": {"component_name": "X", "intent_schemes": ["myapp"]}},
            {"id": "R1", "type": "mobile-intent-redirection",
             "file": "com/example/x/Trampoline.java", "line": 78,
             "kind": "finding", "severity": "high"},
            {"id": "DS1", "type": "mobile-insecure-deserialization",
             "file": "com/example/x/Decoder.java", "line": 50,
             "kind": "finding", "severity": "high"},
            # iOS WebView injection + credential-at-rest
            {"id": "IW1", "type": "ios-webview-html-concat",
             "file": "Sources/W.swift", "line": 30,
             "kind": "finding", "severity": "medium"},
            {"id": "IA1", "type": "ios-ats-arbitrary-loads",
             "file": "Info.plist", "line": 14,
             "kind": "finding", "severity": "high"},
            {"id": "IK1", "type": "ios-keychain-accessible-always",
             "file": "Sources/A.swift", "line": 22,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        # Every chain produced must have a pattern slug from the static
        # map (not a slug derived from name slugification).
        # Use the public list_chain_patterns() rather than the
        # private _CHAIN_NAME_TO_PATTERN dict. Skip the wildcard
        # entries (ssrf-to-*, etc.) since they're discovery hints,
        # not real slugs a chain can carry.
        known_static_slugs = {
            e["pattern"] for e in cd.list_chain_patterns()
            if "*" not in e["pattern"]
        }
        for c in chains:
            name = c.get("name", "")
            # Skip dynamic chain names (web/service patterns produce
            # names like "SSRF → command-injection" which intentionally
            # slugify rather than map).
            if any(prefix in name for prefix in (
                "SSRF →", "Auth Bypass →", "Path Traversal →", "(same file)"
            )):
                continue
            self.assertIn(
                c.get("pattern"), known_static_slugs,
                f"Chain '{name}' pattern '{c.get('pattern')}' not in static map "
                f"— either add to _CHAIN_NAME_TO_PATTERN or rename to a dynamic-style name.",
            )

    def test_list_chain_patterns_orders_static_alphabetically_then_dynamic(self):
        # Static slugs sort alphabetically; dynamic wildcards (ssrf-to-*,
        # auth-bypass-to-*, path-traversal-to-*) come at the end.
        _, cd = self._load_chain()
        entries = cd.list_chain_patterns()
        static = [e["pattern"] for e in entries if "*" not in e["pattern"]]
        dynamic = [e["pattern"] for e in entries if "*" in e["pattern"]]
        # Static portion is sorted alphabetically
        self.assertEqual(static, sorted(static),
                         f"static slugs not sorted: {static}")
        # Dynamic portion appears AFTER the last static entry
        if static and dynamic:
            full = [e["pattern"] for e in entries]
            self.assertGreater(
                full.index(dynamic[0]), full.index(static[-1]),
                "dynamic wildcards must come after static slugs"
            )

    def test_list_chain_patterns_returns_every_mobile_and_ios_slug(self):
        # Operators rely on --list-chain-patterns for .vuln-scout-ignore
        # discoverability. A regression that drops a slug from the static
        # map silently would break that workflow.
        _, cd = self._load_chain()
        entries = cd.list_chain_patterns()
        slugs = {e["pattern"] for e in entries}
        required = {
            "mobile-webview-dispatch",
            "mobile-mitm-precondition",
            "mobile-backup-exfil",
            "mobile-deeplink-webview",
            "mobile-permission-relay",
            "mobile-token-replay",
            "mobile-gadget-landing",
            "mobile-debuggable-secret",
            "mobile-token-double-exposure",
            "mobile-predictable-token",
            "ios-webview-injection",
            "ios-credential-at-rest",
            # Dynamic wildcards too
            "ssrf-to-*",
            "auth-bypass-to-*",
            "path-traversal-to-*",
        }
        missing = required - slugs
        self.assertEqual(missing, set(), f"missing chain-pattern entries: {missing}")
        # Every entry has both pattern + name
        for e in entries:
            self.assertIn("pattern", e)
            self.assertIn("name", e)
            self.assertTrue(e["name"], f"missing name for slug {e['pattern']}")

    def test_unknown_chain_name_derives_pattern_slug(self):
        # If a future chain detector ships a name we don't have a mapping
        # for, the slug derivation should still produce a usable handle.
        _, cd = self._load_chain()
        chains = [{"name": "Some New Hypothetical Chain", "finding_ids": []}]
        cd._stamp_chain_pattern_slugs(chains)
        self.assertEqual(chains[0]["pattern"], "some-new-hypothetical-chain")

    def test_chains_carry_stable_key_consistent_across_runs(self):
        # The same chain re-detected on the next scan should hash to the
        # same stable_key, enabling diff-against workflows.
        _, cd = self._load_chain()
        findings_a = [
            {"id": "B1", "stable_key": "sk-backup",
             "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "stable_key": "sk-prefs",
             "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        # Same findings, different IDs (e.g. after a rescan that reassigns IDs).
        findings_b = [
            {"id": "X9", "stable_key": "sk-backup",
             "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "Y3", "stable_key": "sk-prefs",
             "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        _, chains_a = cd.detect_chains(findings_a, service_graph=None)
        _, chains_b = cd.detect_chains(findings_b, service_graph=None)
        self.assertTrue(chains_a and chains_b)
        self.assertEqual(chains_a[0]["stable_key"], chains_b[0]["stable_key"])
        # Stable key should be deterministic, not the volatile chain-NNN id
        self.assertNotEqual(chains_a[0]["stable_key"], chains_a[0]["id"])

    def test_chain_pattern_returning_none_does_not_crash_pipeline(self):
        # If a chain pattern function forgets to return the incremented
        # counter (returns None), the _safe wrapper should keep using
        # the previous counter rather than blowing up the next pattern's
        # `f"chain-{counter:03d}"` format with a None value.
        from unittest import mock
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        # Force WebView dispatch chain to return None (bad return)
        with mock.patch.object(
            cd, "_detect_mobile_webview_chains",
            return_value=None,
        ):
            _, chains = cd.detect_chains(findings, service_graph=None)
        # Backup-extractable chain still runs successfully
        self.assertTrue(
            any("backup-extractable" in c.get("name", "") for c in chains),
            f"backup-exfil chain should still fire when webview returns None, got: {chains}",
        )
        # The bad return is recorded
        failures = cd.LAST_PATTERN_FAILURES
        self.assertTrue(
            any("non-int counter" in f["error"] for f in failures),
            f"expected non-int counter failure, got: {failures}",
        )

    def test_last_pattern_failures_resets_between_calls(self):
        # If detect_chains fails on call N, the failure list must NOT
        # leak into call N+1. Each invocation gets a fresh slate.
        from unittest import mock
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
        ]
        # Call 1: force a failure
        with mock.patch.object(
            cd, "_detect_mobile_webview_chains",
            side_effect=RuntimeError("first run boom"),
        ):
            cd.detect_chains(findings, service_graph=None)
        self.assertTrue(cd.LAST_PATTERN_FAILURES,
                        "expected failure from first run")
        # Call 2: no failure should be recorded — must reset cleanly
        cd.detect_chains(findings, service_graph=None)
        self.assertEqual(cd.LAST_PATTERN_FAILURES, [],
                         "LAST_PATTERN_FAILURES leaked across calls")

    def test_chain_failure_log_uses_stable_grep_marker(self):
        # Future refactors must keep the `[chain-pattern-failure]`
        # marker stable — CI log analyzers depend on it.
        import logging
        from unittest import mock
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        records: list[logging.LogRecord] = []
        # Attach a handler that captures all WARNING records from the
        # chain detector's logger.
        handler = logging.Handler()
        handler.emit = records.append  # type: ignore[assignment]
        cd_logger = logging.getLogger("vuln-scout")
        cd_logger.addHandler(handler)
        try:
            with mock.patch.object(
                cd, "_detect_mobile_webview_chains",
                side_effect=RuntimeError("synthetic boom"),
            ):
                cd.detect_chains(findings, service_graph=None)
        finally:
            cd_logger.removeHandler(handler)
        # At least one record must carry the stable marker.
        markers = [r for r in records if "[chain-pattern-failure]" in r.getMessage()]
        self.assertTrue(
            markers,
            f"expected [chain-pattern-failure] marker in logs, got: {[r.getMessage() for r in records]}",
        )

    def test_chain_pattern_failure_does_not_kill_other_patterns(self):
        # Force one pattern detector to raise; confirm the rest still
        # produce chains. Defensive against regressions in any single
        # pattern.
        from unittest import mock
        _, cd = self._load_chain()
        findings = [
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["access_token"]}},
        ]
        # Force the WebView dispatch chain to raise; backup-exfil chain
        # should still fire from the unaffected pattern.
        with mock.patch.object(
            cd, "_detect_mobile_webview_chains",
            side_effect=RuntimeError("synthetic boom"),
        ):
            _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertTrue(
            any("backup-extractable" in c.get("name", "") for c in chains),
            f"backup-exfil chain should still fire when webview pattern crashes, got: {chains}",
        )
        # The failure should be recorded on LAST_PATTERN_FAILURES
        failures = cd.LAST_PATTERN_FAILURES
        self.assertTrue(failures, "expected pattern failure to be recorded")
        self.assertTrue(
            any("webview" in f["pattern"] for f in failures),
            f"expected webview pattern in failures, got: {failures}",
        )
        self.assertTrue(
            any("synthetic boom" in f["error"] for f in failures),
        )

    def test_chain_sort_is_deterministic_within_severity_tier(self):
        # Same chains, same severities → same order. Tie-broken by
        # stable_key ascending. Run twice and confirm chain id order matches.
        _, cd = self._load_chain()
        def _build():
            return [
                {"id": "P1", "type": "mobile-shared-prefs-sensitive",
                 "stable_key": "sk-prefs",
                 "file": "com/example/auth/a.java", "line": 96,
                 "kind": "finding", "severity": "high"},
                {"id": "B1", "type": "mobile-allow-backup-true",
                 "stable_key": "sk-backup",
                 "file": "AndroidManifest.xml", "line": 50,
                 "kind": "hotspot", "severity": "medium"},
                {"id": "M1", "type": "graphql-sensitive-client-mutation",
                 "stable_key": "sk-mutation",
                 "file": "res/raw/x.graphql", "line": 1,
                 "kind": "finding", "severity": "medium",
                 "title": "Sensitive GraphQL mutation shipped in client resources: X"},
            ]
        _, chains_a = cd.detect_chains(_build(), service_graph=None)
        _, chains_b = cd.detect_chains(_build(), service_graph=None)
        # Two runs must yield identical chain ordering (by stable_key).
        self.assertEqual(
            [c.get("stable_key") for c in chains_a],
            [c.get("stable_key") for c in chains_b],
        )

    def test_chains_carry_max_participant_severity_and_sort_worst_first(self):
        # Build two chains with different severities and confirm the worst
        # one sorts first and each chain carries its max participant severity.
        _, cd = self._load_chain()
        findings = [
            # Lower-severity chain pair: backup (medium) + prefs (high)
            {"id": "B1", "type": "mobile-allow-backup-true",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
            # Higher-severity chain pair: NSC (low) + remote-controlled (critical)
            {"id": "N1", "type": "mobile-nsc-narrow-pinning",
             "file": "apktool_out/res/xml/network_security_config.xml", "line": 1,
             "kind": "hotspot", "severity": "low"},
            {"id": "R1", "type": "mobile-remote-controlled-endpoint",
             "file": "com/example/api/Client.java", "line": 30,
             "kind": "finding", "severity": "critical"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertTrue(len(chains) >= 2)
        # Every chain must now have severity
        for c in chains:
            self.assertIn(c.get("severity"), {"critical", "high", "medium", "low", "info"})
        # Critical chain sorts first
        self.assertEqual(chains[0].get("severity"), "critical")

    def test_token_replay_chain_links_prefs_and_graphql_mutation(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "P1",
                "type": "mobile-shared-prefs-sensitive",
                "file": "com/example/auth/a.java",
                "line": 96,
                "kind": "finding",
                "severity": "high",
                "metadata": {"pref_keys": ["access_token", "refresh_token"]},
            },
            {
                "id": "M1",
                "type": "graphql-sensitive-client-mutation",
                "file": "res/raw/graphql/DeletePaymentMethod.graphql",
                "line": 1,
                "kind": "finding",
                "severity": "medium",
                "title": "Sensitive GraphQL mutation shipped in client resources: DeletePaymentMethodFromSingleUseToken",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        replay = [c for c in chains if "token-replay" in c.get("name", "").lower()]
        self.assertTrue(replay, f"expected token-replay chain, got: {chains}")
        impact = replay[0].get("impact", "")
        self.assertIn("access_token", impact)
        self.assertIn("DeletePaymentMethodFromSingleUseToken", impact)
        self.assertEqual(findings[0]["chain_role"], "source")
        self.assertEqual(findings[1]["chain_role"], "sink")

    def test_gadget_landing_chain_links_exported_entry_and_deserialization(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "E1",
                "type": "mobile-exported-component-no-permission",
                "file": "AndroidManifest.xml",
                "line": 50,
                "kind": "hotspot",
                "severity": "medium",
                "metadata": {
                    "component_name": "com.example.app.IntentReceiver",
                    "component_kind": "activity",
                },
            },
            {
                "id": "D1",
                "type": "mobile-insecure-deserialization",
                "file": "com/example/app/Decoder.java",
                "line": 120,
                "kind": "finding",
                "severity": "high",
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        gadget = [c for c in chains if "gadget-landing" in c.get("name", "").lower()]
        self.assertTrue(gadget, f"expected gadget-landing chain, got: {chains}")
        self.assertIn("IntentReceiver", gadget[0].get("flow_description", ""))
        self.assertEqual(findings[0]["chain_role"], "entry")
        self.assertEqual(findings[1]["chain_role"], "sink")

    def test_ios_webview_injection_chain_links_html_concat_and_ats_gap(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "A1", "type": "ios-ats-arbitrary-loads",
             "file": "Info.plist", "line": 14,
             "kind": "finding", "severity": "high"},
            {"id": "W1", "type": "ios-webview-html-concat",
             "file": "Sources/PaymentView.swift", "line": 88,
             "kind": "finding", "severity": "medium"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        ios_chain = [c for c in chains if "ios webview injection" in c.get("name", "").lower()]
        self.assertTrue(ios_chain, f"expected iOS WebView injection chain, got: {chains}")
        self.assertEqual(findings[0]["chain_role"], "precondition")
        self.assertEqual(findings[1]["chain_role"], "sink")

    def test_ios_webview_injection_chain_silent_without_transport_gap(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "W1", "type": "ios-webview-evaljs-concat",
             "file": "Sources/PaymentView.swift", "line": 88,
             "kind": "finding", "severity": "medium"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("ios webview injection" in c.get("name", "").lower() for c in chains),
        )

    def test_ios_credential_at_rest_chain_links_keychain_and_ats(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "K1", "type": "ios-keychain-accessible-always",
             "file": "Sources/AuthStore.swift", "line": 22,
             "kind": "finding", "severity": "high"},
            {"id": "A1", "type": "ios-ats-arbitrary-loads",
             "file": "Info.plist", "line": 14,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        credit = [c for c in chains if "credential-at-rest" in c.get("name", "").lower()]
        self.assertTrue(credit, f"expected iOS credential-at-rest chain, got: {chains}")
        self.assertEqual(findings[0]["chain_role"], "credential")
        self.assertEqual(findings[1]["chain_role"], "precondition")

    def test_mitm_chain_accepts_ios_preconditions(self):
        # The pre-existing MITM chain (Pattern 7) should now fire on iOS
        # transport gaps too — not just Android NSC.
        _, cd = self._load_chain()
        findings = [
            {"id": "A1", "type": "ios-trust-all-ssl",
             "file": "Sources/Net.swift", "line": 33,
             "kind": "finding", "severity": "high"},
            {"id": "R1", "type": "mobile-remote-controlled-endpoint",
             "file": "com/example/api/Client.java", "line": 30,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertTrue(
            any("MITM precondition" in c.get("name", "") for c in chains),
            f"expected MITM chain to accept iOS precondition, got: {chains}",
        )

    def test_predictable_token_chain_links_insecure_rng_and_prefs(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "R1", "type": "mobile-insecure-random",
             "file": "com/example/auth/TokenGen.java", "line": 10,
             "kind": "finding", "severity": "high"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/Store.java", "line": 22,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["session_token"]}},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        pt = [c for c in chains if "predictable-token" in c.get("name", "").lower()]
        self.assertTrue(pt, f"expected predictable-token chain, got: {chains}")
        self.assertEqual(pt[0].get("pattern"), "mobile-predictable-token")
        self.assertIn("session_token", pt[0].get("impact", ""))
        self.assertEqual(findings[0]["chain_role"], "source")
        self.assertEqual(findings[1]["chain_role"], "sink")

    def test_predictable_token_chain_silent_without_prefs(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "R1", "type": "mobile-insecure-random",
             "file": "com/example/x.java", "line": 1,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("predictable-token" in c.get("name", "").lower() for c in chains),
        )

    def test_token_double_exposure_chain_links_shared_identifier(self):
        # When the same token name appears in both prefs storage and
        # log interpolation, the double-exposure chain should fire.
        _, cd = self._load_chain()
        findings = [
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["access_token", "user_pin"]}},
            {"id": "L1", "type": "mobile-log-sensitive",
             "file": "com/example/log/Net.java", "line": 22,
             "kind": "hotspot", "severity": "medium",
             "metadata": {"sensitive_idents": ["accessToken"]}},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        de = [c for c in chains if "double-exposure" in c.get("name", "").lower()]
        self.assertTrue(de, f"expected double-exposure chain, got: {chains}")
        self.assertEqual(de[0].get("pattern"), "mobile-token-double-exposure")
        self.assertEqual(findings[0]["chain_role"], "storage")
        self.assertEqual(findings[1]["chain_role"], "log")

    def test_token_double_exposure_chain_silent_without_overlap(self):
        # Prefs writes `refresh_token` but logs only `userId` (no shared
        # identifier) → no double-exposure chain.
        _, cd = self._load_chain()
        findings = [
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["refresh_token"]}},
            {"id": "L1", "type": "mobile-log-sensitive",
             "file": "com/example/log/Net.java", "line": 22,
             "kind": "hotspot", "severity": "medium",
             "metadata": {"sensitive_idents": ["userId"]}},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("double-exposure" in c.get("name", "").lower() for c in chains),
        )

    def test_debuggable_secret_chain_links_debuggable_and_prefs(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "D1", "type": "mobile-debuggable-build",
             "file": "AndroidManifest.xml", "line": 7,
             "kind": "finding", "severity": "high"},
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high",
             "metadata": {"pref_keys": ["access_token", "user_pin"]}},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        ch = [c for c in chains if "debuggable" in c.get("name", "").lower()]
        self.assertTrue(ch, f"expected debuggable+secret chain, got: {chains}")
        impact = ch[0].get("impact", "")
        self.assertIn("access_token", impact)
        self.assertIn("user_pin", impact)
        self.assertEqual(findings[0]["chain_role"], "entry")
        self.assertEqual(findings[1]["chain_role"], "exposed")

    def test_debuggable_secret_chain_silent_without_debuggable(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("debuggable" in c.get("name", "").lower() for c in chains),
        )

    def test_gadget_landing_chain_silent_without_deserialization(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "E1", "type": "mobile-exported-component-no-permission",
             "file": "AndroidManifest.xml", "line": 50,
             "kind": "hotspot", "severity": "medium",
             "metadata": {"component_name": "com.example.app.SomeActivity"}},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("gadget-landing" in c.get("name", "").lower() for c in chains),
        )

    def test_last_detector_failures_resets_between_calls(self):
        # Symmetric to N+95's LAST_PATTERN_FAILURES reset test: each
        # run_all_detectors invocation must start with a fresh
        # LAST_DETECTOR_FAILURES list.
        from unittest import mock
        vcd_mod = _load("vuln_class_detectors", SCRIPTS_DIR / "vuln_class_detectors.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.java").write_text(
                'void store() { prefs.edit().putString("access_token", t).apply(); }'
            )
            # Call 1: force a failure
            with mock.patch.object(
                vcd_mod, "detect_runtime_exec",
                side_effect=RuntimeError("first run boom"),
            ):
                vcd_mod.run_all_detectors(str(root))
            self.assertTrue(vcd_mod.LAST_DETECTOR_FAILURES,
                            "expected failure from first run")
            # Call 2: clean run — list must reset
            vcd_mod.run_all_detectors(str(root))
            self.assertEqual(vcd_mod.LAST_DETECTOR_FAILURES, [],
                             "LAST_DETECTOR_FAILURES leaked across calls")

    def test_detector_failure_log_uses_stable_grep_marker(self):
        # Symmetric to the [chain-pattern-failure] marker pin: future
        # log-format edits must keep the [detector-failure] marker
        # stable. CI log aggregators depend on it.
        from unittest import mock
        import logging
        vcd_mod = _load("vuln_class_detectors", SCRIPTS_DIR / "vuln_class_detectors.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.java").write_text(
                'void store() { prefs.edit().putString("access_token", t).apply(); }'
            )
            records: list[logging.LogRecord] = []
            handler = logging.Handler()
            handler.emit = records.append  # type: ignore[assignment]
            log = logging.getLogger("vuln-scout")
            log.addHandler(handler)
            try:
                with mock.patch.object(
                    vcd_mod, "detect_runtime_exec",
                    side_effect=RuntimeError("synthetic boom"),
                ):
                    vcd_mod.run_all_detectors(str(root))
            finally:
                log.removeHandler(handler)
            markers = [r for r in records if "[detector-failure]" in r.getMessage()]
            self.assertTrue(
                markers,
                f"expected [detector-failure] marker in logs, got: {[r.getMessage() for r in records]}",
            )

    def test_detector_failures_recorded_on_module_state(self):
        # Force one detector to raise; confirm run_all_detectors swallows
        # the exception and the failure is recorded on the module state.
        from unittest import mock
        vcd_mod = _load("vuln_class_detectors", SCRIPTS_DIR / "vuln_class_detectors.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Auth.java").write_text(
                'void store() { prefs.edit().putString("access_token", t).apply(); }'
            )
            # Mock one detector to raise. The rest must still produce findings.
            with mock.patch.object(
                vcd_mod, "detect_runtime_exec",
                side_effect=RuntimeError("synthetic boom"),
            ):
                findings = vcd_mod.run_all_detectors(str(root))
            # Other detectors still produced findings
            self.assertTrue(any(f.get("type") == "mobile-shared-prefs-sensitive" for f in findings))
            # Failure is recorded
            failures = vcd_mod.LAST_DETECTOR_FAILURES
            self.assertTrue(failures, "expected at least one recorded detector failure")
            self.assertTrue(any("Runtime.exec" in f["detector"] for f in failures))
            self.assertTrue(any("synthetic boom" in f["error"] for f in failures))

    def test_token_replay_chain_silent_without_graphql_mutation(self):
        _, cd = self._load_chain()
        findings = [
            {"id": "P1", "type": "mobile-shared-prefs-sensitive",
             "file": "com/example/auth/a.java", "line": 96,
             "kind": "finding", "severity": "high"},
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("token-replay" in c.get("name", "").lower() for c in chains),
            "token-replay chain must not synthesize without a graphql mutation finding",
        )

    def test_permission_relay_chain_silent_without_intent_redirection(self):
        _, cd = self._load_chain()
        findings = [
            {
                "id": "E1",
                "type": "mobile-exported-component-no-permission",
                "file": "AndroidManifest.xml",
                "line": 50,
                "kind": "hotspot",
                "severity": "medium",
                "metadata": {"component_name": "com.example.app.SomeActivity"},
            },
        ]
        _, chains = cd.detect_chains(findings, service_graph=None)
        self.assertFalse(
            any("permission-relay" in c.get("name", "").lower() for c in chains),
            "must not synthesize permission-relay chain without an intent-redirection finding",
        )


class MobileScanMergerTests(unittest.TestCase):
    """Lock the merge semantics of mobile_scan so we don't lose findings
    or double-count summary buckets after a refactor."""

    @staticmethod
    def _load_merger():
        return _load("mobile_scan", SCRIPTS_DIR / "mobile_scan.py")

    def test_chain_rollups_have_deterministic_key_order(self):
        # Run the merge twice on the same inputs; the chains_by_pattern
        # and chains_by_severity dicts must serialize in the same key
        # order so byte-level diffs across re-scans are stable.
        ms = self._load_merger()
        import json as _json
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact_a = root / "a.json"
            artifact_a.write_text(_json.dumps({
                "findings": [
                    {"id": "B1", "type": "mobile-allow-backup-true",
                     "file": "AndroidManifest.xml", "line": 50,
                     "kind": "hotspot", "severity": "medium",
                     "confidence": "high"},
                    {"id": "P1", "type": "mobile-shared-prefs-sensitive",
                     "file": "com/example/auth/a.java", "line": 96,
                     "kind": "finding", "severity": "high",
                     "confidence": "high"},
                    {"id": "M1", "type": "graphql-sensitive-client-mutation",
                     "file": "res/raw/x.graphql", "line": 1,
                     "kind": "finding", "severity": "medium", "confidence": "high",
                     "title": "Sensitive GraphQL mutation shipped in client resources: M"},
                ],
                "summary": {"total_findings": 0, "total_hotspots": 0,
                            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }))
            out1 = ms.merge_findings([artifact_a])
            out2 = ms.merge_findings([artifact_a])
            # Pattern keys sorted alphabetically; severity keys in canonical
            # priority order. Both should produce identical key sequences.
            self.assertEqual(
                list(out1["summary"]["chains_by_pattern"].keys()),
                sorted(out1["summary"]["chains_by_pattern"].keys()),
            )
            self.assertEqual(
                list(out1["summary"]["chains_by_pattern"].keys()),
                list(out2["summary"]["chains_by_pattern"].keys()),
            )
            sev_order = ["critical", "high", "medium", "low", "info"]
            keys = list(out1["summary"]["chains_by_severity"].keys())
            sev_ranks = [sev_order.index(k) for k in keys]
            self.assertEqual(sev_ranks, sorted(sev_ranks))

    def test_merge_summary_includes_chain_pattern_and_severity_rollups(self):
        # The merged summary should carry chain counts rolled up by
        # pattern and by severity so dashboards can chart them without
        # re-reading the chains array.
        ms = self._load_merger()
        import json as _json
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact_a = root / "a.json"
            artifact_a.write_text(_json.dumps({
                "findings": [
                    {"id": "B1", "type": "mobile-allow-backup-true",
                     "file": "AndroidManifest.xml", "line": 50,
                     "kind": "hotspot", "severity": "medium",
                     "confidence": "high"},
                    {"id": "P1", "type": "mobile-shared-prefs-sensitive",
                     "file": "com/example/auth/a.java", "line": 96,
                     "kind": "finding", "severity": "high",
                     "confidence": "high"},
                ],
                "summary": {"total_findings": 0, "total_hotspots": 0,
                            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }))
            out = ms.merge_findings([artifact_a])
            self.assertGreaterEqual(out["summary"]["total_chains"], 1)
            self.assertIn("chains_by_pattern", out["summary"])
            self.assertIn("chains_by_severity", out["summary"])
            self.assertIn(
                "mobile-backup-exfil",
                out["summary"]["chains_by_pattern"],
                f"expected backup-exfil rollup, got: {out['summary']['chains_by_pattern']}",
            )

    def test_chains_detected_across_merged_artifacts(self):
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # Artifact A: code-side findings (jadx_out)
            (tdp / "a.json").write_text(json.dumps({
                "findings": [
                    {
                        "id": "F1",
                        "stable_key": "k1",
                        "type": "mobile-remote-controlled-endpoint",
                        "file": "com/example/app/payment/processors/services/chase/api/X.java",
                        "line": 10,
                        "kind": "finding",
                        "severity": "high",
                    },
                    {
                        "id": "F2",
                        "stable_key": "k2",
                        "type": "mobile-webview-js-injection",
                        "file": "com/example/app/payment/processors/services/chase/js/a.java",
                        "line": 119,
                        "kind": "finding",
                        "severity": "medium",
                    },
                ],
            }))
            # Artifact B: resource-side findings (apktool_out)
            (tdp / "b.json").write_text(json.dumps({
                "findings": [
                    {
                        "id": "N1",
                        "stable_key": "k3",
                        "type": "mobile-nsc-narrow-pinning",
                        "file": "res/xml/network_security_config.xml",
                        "line": 1,
                        "kind": "hotspot",
                        "severity": "low",
                    },
                ],
            }))
            merged = ms.merge_findings([tdp / "a.json", tdp / "b.json"])
            chain_names = [c.get("name", "") for c in merged.get("chains", [])]
            self.assertTrue(
                any("WebView dispatch" in n for n in chain_names),
                f"expected WebView dispatch chain in merged output, got: {chain_names}",
            )
            self.assertTrue(
                any("MITM" in n for n in chain_names),
                f"expected MITM precondition chain in merged output, got: {chain_names}",
            )

    def test_deduplicates_by_stable_key(self):
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "a.json").write_text(json.dumps({
                "findings": [{
                    "stable_key": "abc",
                    "severity": "high",
                    "kind": "finding",
                    "evidence": [{"label": "a"}],
                }],
            }))
            (tdp / "b.json").write_text(json.dumps({
                "findings": [{
                    "stable_key": "abc",
                    "severity": "high",
                    "kind": "finding",
                    "evidence": [{"label": "b"}],
                }, {
                    "stable_key": "xyz",
                    "severity": "medium",
                    "kind": "hotspot",
                    "evidence": [],
                }],
            }))
            merged = ms.merge_findings([tdp / "a.json", tdp / "b.json"])
            self.assertEqual(len(merged["findings"]), 2)
            self.assertEqual(merged["summary"]["high"], 1)
            self.assertEqual(merged["summary"]["total_findings"], 1)
            self.assertEqual(merged["summary"]["total_hotspots"], 1)
            # Evidence from both inputs should be preserved on the merged finding
            same_key = next(f for f in merged["findings"] if f["stable_key"] == "abc")
            labels = sorted(e.get("label") for e in same_key["evidence"])
            self.assertEqual(labels, ["a", "b"])

    def test_discovery_finds_jadx_and_apktool(self):
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "jadx_out" / "sources").mkdir(parents=True)
            (root / "apktool_out").mkdir(parents=True)
            targets = ms.discover_mobile_targets(root)
            target_names = [t.name for t in targets]
            self.assertIn("sources", target_names)
            self.assertIn("apktool_out", target_names)

    def test_discovery_falls_back_to_root(self):
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src" / "main" / "java").mkdir(parents=True)
            targets = ms.discover_mobile_targets(root)
            self.assertEqual(targets, [root / "src" / "main" / "java"])

    def test_no_chains_and_top_chains_are_rejected(self):
        # Combination is incoherent — error out rather than silently no-op.
        import subprocess
        result = subprocess.run(
            ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
             "/tmp", "--no-chains", "--top-chains", "5"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incompatible", result.stderr.lower())

    def test_merge_findings_skip_chains_outputs_empty_chains(self):
        ms = self._load_merger()
        import json as _json
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact_a = root / "a.json"
            artifact_a.write_text(_json.dumps({
                "findings": [
                    {"id": "B1", "type": "mobile-allow-backup-true",
                     "file": "AndroidManifest.xml", "line": 50,
                     "kind": "hotspot", "severity": "medium"},
                    {"id": "P1", "type": "mobile-shared-prefs-sensitive",
                     "file": "com/example/auth/a.java", "line": 96,
                     "kind": "finding", "severity": "high"},
                ],
                "summary": {"total_findings": 0, "total_hotspots": 0,
                            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }))
            out = ms.merge_findings([artifact_a], skip_chains=True)
            self.assertEqual(out["chains"], [])
            self.assertEqual(len(out["findings"]), 2)
            self.assertEqual(out["summary"].get("total_chains", 0), 0)

    def test_findings_heading_lists_every_chain_for_multi_chain_finding(self):
        # A finding with two chain_participations should show both
        # `pattern:role` pairs in its heading. Single-chain findings
        # keep the canonical `[chain X — role]` form.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        findings = [{
            "kind": "finding", "severity": "high",
            "title": "Multi", "file": "a.java", "line": 1,
            "verdict": "unverified", "confidence": "medium", "id": "F1",
            "chain_id": "chain-001", "chain_role": "sink",
            "chain_pattern": "mobile-backup-exfil",
            "chain_participations": [
                {"chain_id": "chain-001", "role": "sink",
                 "pattern": "mobile-backup-exfil"},
                {"chain_id": "chain-005", "role": "source",
                 "pattern": "mobile-token-replay"},
            ],
        }]
        out = mr._all_findings(findings)
        self.assertIn("[chains", out)
        self.assertIn("mobile-backup-exfil`:sink", out)
        self.assertIn("mobile-token-replay`:source", out)

    def test_scan_diagnostics_renders_chain_pattern_failures(self):
        # When scan_metadata.chain_pattern_failures is populated, the
        # markdown report should surface a Scan Diagnostics section.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        out = mr._scan_diagnostics({
            "scan_metadata": {
                "chain_pattern_failures": [
                    {"pattern": "mobile-token-replay", "error": "RuntimeError: X"},
                ],
            },
        })
        self.assertIn("## Scan Diagnostics", out)
        self.assertIn("mobile-token-replay", out)
        self.assertIn("RuntimeError: X", out)
        # Empty artifact → empty section (graceful absence)
        self.assertEqual(mr._scan_diagnostics({}), "")
        self.assertEqual(mr._scan_diagnostics({"scan_metadata": {}}), "")

    def test_markdown_section_order_pinned(self):
        # Pin the canonical section order. Reviewers expect to see
        # Executive Summary → Diff → diagnostics → Chains before the
        # full Findings list. A reorder that buries chains under the
        # findings dump breaks this test.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        artifact = {
            "findings": [{
                "kind": "finding", "severity": "high", "title": "T",
                "file": "a.java", "line": 1, "verdict": "unverified",
                "confidence": "medium", "id": "F1",
            }],
            "chains": [{
                "id": "c1", "name": "Chain", "severity": "high",
                "impact": "i", "flow_description": "f",
                "finding_ids": ["F1"],
            }],
            "scan_metadata": {
                "chain_pattern_failures": [
                    {"pattern": "p", "error": "RT: x"},
                ],
            },
            "summary": {"total_findings": 1, "total_hotspots": 0,
                        "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "coverage": {},
        }
        out = mr.generate(artifact)
        # Required order: exec summary → scan diagnostics → attack chains → findings
        i_exec = out.index("## Executive Summary")
        i_diag = out.index("## Scan Diagnostics")
        i_chain = out.index("## Attack Chains")
        i_findings = out.index("## Findings")
        self.assertLess(i_exec, i_diag)
        self.assertLess(i_diag, i_chain)
        self.assertLess(i_chain, i_findings)

    def test_scan_diagnostics_appears_in_full_report(self):
        # When generate() runs over an artifact with failures, the Scan
        # Diagnostics section must actually appear in the full output.
        # Catches the case where someone removes _scan_diagnostics from
        # the sections list silently.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        artifact = {
            "findings": [],
            "scan_metadata": {
                "chain_pattern_failures": [
                    {"pattern": "mobile-token-replay", "error": "RT"},
                ],
            },
            "summary": {"total_findings": 0, "total_hotspots": 0,
                        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "coverage": {},
        }
        out = mr.generate(artifact)
        self.assertIn("## Scan Diagnostics", out)

    def test_scan_diagnostics_renders_detector_failures(self):
        # Symmetric to N+139's chain test — sub-detector failures from
        # tool_statuses['vuln-class-detector'].detector_failures must
        # also surface in Scan Diagnostics.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        out = mr._scan_diagnostics({
            "tool_statuses": {
                "vuln-class-detector": {
                    "state": "degraded",
                    "detector_failures": [
                        {"detector": "mobile WebView JS injection",
                         "error": "TypeError: bad"},
                    ],
                },
            },
        })
        self.assertIn("## Scan Diagnostics", out)
        self.assertIn("sub-detector(s)", out)
        self.assertIn("mobile WebView JS injection", out)
        self.assertIn("TypeError: bad", out)

    def test_diff_markdown_shows_no_changes_sentinel_when_stable(self):
        # When the diff is fully kept (no new/gone/drift), render a
        # "No changes vs prior scan" sentinel rather than an empty
        # section — reviewers want a positive stability signal.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        out = mr._diff_since_prior({
            "diff": {
                "new": [], "gone": [],
                "kept": [{"key": "k1"}, {"key": "k2"}],
                "chains": {
                    "new": [], "gone": [],
                    "kept": [{"stable_key": "C"}, {"stable_key": "D"}],
                    "severity_drift": [],
                },
            },
        })
        self.assertIn("No changes vs prior scan", out)
        self.assertIn("2 chain(s)", out)
        self.assertIn("2 finding(s)", out)

    def test_diff_markdown_renders_inline_delta_summary_lines(self):
        # Both _Chains: ..._ and _Findings: ..._ lines should appear
        # at the top of the diff section.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        out = mr._diff_since_prior({
            "diff": {
                "new": [{"severity": "high", "type": "x",
                         "file": "a.java", "line": 1}],
                "gone": [{"key": "k1"}],
                "kept": [{"key": "k2"}, {"key": "k3"}],
                "chains": {
                    "new": [{"stable_key": "A", "pattern": "p-a",
                             "severity": "high"}],
                    "gone": [], "kept": [{"stable_key": "C"}],
                    "severity_drift": [],
                },
            },
        })
        # Both summary lines present
        self.assertIn("_Chains:", out)
        self.assertIn("_Findings:", out)
        # Counts reflect actual bucket sizes
        self.assertIn("1 new", out)
        self.assertIn("1 unchanged", out)  # chains kept count
        self.assertIn("2 unchanged", out)  # findings kept count

    def test_diff_markdown_renders_all_sections_in_priority_order(self):
        # Snapshot-style test: all five diff sections populated; render
        # via _diff_since_prior and confirm each section appears in the
        # right priority order with worst-first sorting.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mr", SCRIPTS_DIR / "markdown_report.py"
        )
        mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mr)
        out = mr._diff_since_prior({
            "diff": {
                "new": [
                    {"severity": "medium", "type": "low-noise",
                     "file": "x.java", "line": 1},
                    {"severity": "critical", "type": "rce",
                     "file": "y.java", "line": 5},
                ],
                "gone": [{"key": "old1"}],
                "chains": {
                    "new": [
                        {"stable_key": "chain-mm", "pattern": "p-mm",
                         "severity": "medium"},
                        {"stable_key": "chain-cc", "pattern": "p-cc",
                         "severity": "critical"},
                    ],
                    "gone": [
                        {"stable_key": "chain-zz", "pattern": "p-zz"},
                    ],
                    "kept": [],
                    "severity_drift": [
                        {"stable_key": "chain-dd", "pattern": "p-dd",
                         "direction": "de-escalated",
                         "from_severity": "high", "to_severity": "low"},
                        {"stable_key": "chain-uu", "pattern": "p-uu",
                         "direction": "escalated",
                         "from_severity": "medium", "to_severity": "critical"},
                    ],
                },
            },
        })
        # Sections appear in the canonical order:
        # New chains → Resolved chains → Drift → New findings → Resolved
        idx_new = out.index("New chains")
        idx_gone = out.index("Resolved chains")
        idx_drift = out.index("Chain severity drift")
        idx_newf = out.index("New findings")
        idx_resf = out.index("Resolved findings")
        self.assertLess(idx_new, idx_gone)
        self.assertLess(idx_gone, idx_drift)
        self.assertLess(idx_drift, idx_newf)
        self.assertLess(idx_newf, idx_resf)
        # Worst-first within new-chains: critical before medium
        crit_idx = out.index("p-cc")
        med_idx = out.index("p-mm")
        self.assertLess(crit_idx, med_idx)
        # Escalations before de-escalations
        esc_idx = out.index("p-uu")
        de_idx = out.index("p-dd")
        self.assertLess(esc_idx, de_idx)
        # New findings: critical RCE before medium low-noise
        rce_idx = out.index("rce")
        noise_idx = out.index("low-noise")
        self.assertLess(rce_idx, noise_idx)

    def test_trim_to_top_chains_keeps_worst_first_and_clears_orphan_tags(self):
        ms = self._load_merger()
        merged = {
            "chains": [
                {"id": "chain-001", "name": "Worst", "severity": "critical"},
                {"id": "chain-002", "name": "Mid", "severity": "high"},
                {"id": "chain-003", "name": "Lower", "severity": "medium"},
            ],
            "findings": [
                {"id": "F1", "chain_id": "chain-001", "chain_role": "entry",
                 "chain_pattern": "worst-pat"},
                {"id": "F2", "chain_id": "chain-002", "chain_role": "sink",
                 "chain_pattern": "mid-pat"},
                {"id": "F3", "chain_id": "chain-003", "chain_role": "sink",
                 "chain_pattern": "lower-pat"},
            ],
        }
        ms._trim_to_top_chains(merged, 1)
        # Only the worst chain survives
        self.assertEqual([c["id"] for c in merged["chains"]], ["chain-001"])
        # F1 still tagged
        self.assertEqual(merged["findings"][0]["chain_id"], "chain-001")
        # F2 + F3 lost their orphaned tags
        self.assertNotIn("chain_id", merged["findings"][1])
        self.assertNotIn("chain_role", merged["findings"][1])
        self.assertNotIn("chain_pattern", merged["findings"][1])
        self.assertNotIn("chain_id", merged["findings"][2])

    def test_trim_to_top_chains_drops_dangling_participations(self):
        # Bug 27: --top-chains 1 kept chain-001 but findings tagged with
        # chain_participations referencing chain-002 (dropped) had
        # dangling entries — downstream renderers crash or reference
        # a chain not in the output.
        ms = self._load_merger()
        merged = {
            "chains": [
                {"id": "chain-001", "severity": "high", "name": "Kept"},
                {"id": "chain-002", "severity": "low", "name": "Dropped"},
            ],
            "findings": [
                {
                    "id": "F1",
                    "chain_id": "chain-001",
                    "chain_role": "source",
                    "chain_participations": [
                        {"chain_id": "chain-001", "role": "source"},
                        {"chain_id": "chain-002", "role": "sink"},
                    ],
                },
            ],
        }
        ms._trim_to_top_chains(merged, 1)
        # Only chain-001 reference remains in participations
        participations = merged["findings"][0].get("chain_participations") or []
        chain_ids = [p["chain_id"] for p in participations]
        self.assertEqual(chain_ids, ["chain-001"])

    def test_trim_to_top_chains_noop_when_count_fits(self):
        ms = self._load_merger()
        merged = {
            "chains": [{"id": "chain-001", "severity": "high"}],
            "findings": [{"id": "F1", "chain_id": "chain-001"}],
        }
        ms._trim_to_top_chains(merged, 5)
        self.assertEqual(len(merged["chains"]), 1)
        self.assertEqual(merged["findings"][0]["chain_id"], "chain-001")

    def test_validate_suppressions_flags_unknown_rule_prefix(self):
        # `foo:bar` doesn't start with any of the known rule prefixes —
        # apply_suppressions silently ignores it, so the linter must
        # warn the operator that the rule never fires.
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            ignore = Path(td) / ".vuln-scout-ignore"
            ignore.write_text(
                "chain_pattern:mobile-backup-exfil  valid\n"
                "foo:bar  unknown prefix\n"
                "unknownrule:something  also unknown\n"
            )
            result = subprocess.run(
                ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
                 "--validate-suppressions", str(ignore)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown rule prefix", result.stdout)
            self.assertIn("foo:bar", result.stdout)
            self.assertIn("unknownrule:something", result.stdout)

    def test_validate_suppressions_flags_unknown_slug(self):
        # An unknown chain_pattern slug should produce a warning + non-zero exit.
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            ignore = Path(td) / ".vuln-scout-ignore"
            ignore.write_text(
                "chain_pattern:mobile-this-does-not-exist  typo\n"
                "chain_pattern:mobile-backup-exfil  real one\n"
                "severity:bogus  bad level\n"
            )
            result = subprocess.run(
                ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
                 "--validate-suppressions", str(ignore)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mobile-this-does-not-exist", result.stdout)
            self.assertIn("bogus", result.stdout)
            self.assertIn("issue(s) found", result.stderr)

    def test_validate_suppressions_flags_wildcard_matching_nothing(self):
        # Typo'd wildcard like `mobile-debugable-*` (missing 'g') matches
        # zero known slugs and should be flagged. Dynamic-family
        # wildcards (ssrf-to-*) and well-formed wildcards stay silent.
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            ignore = Path(td) / ".vuln-scout-ignore"
            ignore.write_text(
                "chain_pattern:mobile-debugable-*  typo: missing g\n"
                "chain_pattern:mobile-debuggable-*  correct\n"
                "chain_pattern:ssrf-to-*  dynamic family\n"
            )
            result = subprocess.run(
                ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
                 "--validate-suppressions", str(ignore)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mobile-debugable-*", result.stdout)
            self.assertIn("matches no known slug", result.stdout)
            # Correct wildcard NOT flagged
            self.assertNotIn("mobile-debuggable-*", result.stdout)
            # Dynamic family NOT flagged
            self.assertNotIn("ssrf-to-*", result.stdout)

    def test_validate_suppressions_flags_duplicate_keys(self):
        # parse_suppressions silently overwrites; the linter must surface
        # duplicates so the operator knows which rule is the live one.
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            ignore = Path(td) / ".vuln-scout-ignore"
            ignore.write_text(
                "chain_pattern:mobile-backup-exfil  first reason\n"
                "chain_pattern:mobile-backup-exfil  second reason — overwrites\n"
            )
            result = subprocess.run(
                ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
                 "--validate-suppressions", str(ignore)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate", result.stdout.lower())
            # New format from N+117: `<path>:<line>: warn: ... (first at line N)`
            self.assertIn(":2: warn:", result.stdout)
            self.assertIn("first at line 1", result.stdout)

    def test_validate_suppressions_flags_malformed_stable_key(self):
        # `vscout:not_a_hex` should be flagged — canonical shape is
        # `vscout:[0-9a-f]{12}`. Operator typo from copy/paste accidents.
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            ignore = Path(td) / ".vuln-scout-ignore"
            ignore.write_text(
                "vscout:not_a_hash  copy-paste typo\n"
                "vscout:abcdef123456  good shape\n"
            )
            result = subprocess.run(
                ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
                 "--validate-suppressions", str(ignore)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not_a_hash", result.stdout)
            # Well-formed key should NOT be flagged
            self.assertNotIn("abcdef123456", result.stdout)

    def test_validate_suppressions_auto_resolves_directory(self):
        # Passing a directory should auto-resolve to <dir>/.vuln-scout-ignore.
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".vuln-scout-ignore").write_text(
                "chain_pattern:mobile-backup-exfil  reason\n"
            )
            result = subprocess.run(
                ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
                 "--validate-suppressions", str(td)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ok:", result.stdout)

    def test_validate_suppressions_errors_on_missing_file(self):
        # Missing file path → non-zero exit + explicit error, not a
        # silent "ok: 0 rules" success.
        import subprocess
        result = subprocess.run(
            ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
             "--validate-suppressions", "/nonexistent/path.ignore"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not found", result.stderr.lower())

    def test_validate_suppressions_passes_clean_file(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            ignore = Path(td) / ".vuln-scout-ignore"
            ignore.write_text(
                "chain_pattern:mobile-backup-exfil  test build\n"
                "chain_pattern:ios-*  Android-only target\n"
                "severity:low  CI noise floor\n"
                "file:*/test/*  test code\n"
            )
            result = subprocess.run(
                ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
                 "--validate-suppressions", str(ignore)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ok:", result.stdout)

    def test_list_chain_patterns_cli_works(self):
        # End-to-end smoke test: invoke mobile_scan.py --list-chain-patterns
        # via subprocess and confirm it prints every known slug.
        import subprocess
        result = subprocess.run(
            ["python3", str(SCRIPTS_DIR / "mobile_scan.py"), "--list-chain-patterns"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # Every static slug should appear in the output
        for slug in [
            "mobile-backup-exfil",
            "mobile-token-replay",
            "mobile-deeplink-webview",
            "ios-webview-injection",
            "ssrf-to-*",
        ]:
            self.assertIn(slug, result.stdout, f"missing {slug}")

    def test_list_chain_patterns_json_format(self):
        # --list-chain-patterns-format json should emit a JSON array
        # consumable by tooling.
        import subprocess, json as _json
        result = subprocess.run(
            ["python3", str(SCRIPTS_DIR / "mobile_scan.py"),
             "--list-chain-patterns",
             "--list-chain-patterns-format", "json"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = _json.loads(result.stdout)
        self.assertIsInstance(data, list)
        self.assertTrue(data, "expected non-empty list")
        # Each entry has pattern + name
        for entry in data:
            self.assertIn("pattern", entry)
            self.assertIn("name", entry)
        slugs = {e["pattern"] for e in data}
        self.assertIn("mobile-token-replay", slugs)

    def test_diff_against_prior_artifact(self):
        ms = self._load_merger()
        prior = {
            "findings": [
                {"stable_key": "A", "type": "x", "severity": "low", "file": "a", "line": 1},
                {"stable_key": "B", "type": "y", "severity": "high", "file": "b", "line": 2},
            ],
        }
        current = {
            "findings": [
                {"stable_key": "B", "type": "y", "severity": "high", "file": "b", "line": 2},
                {"stable_key": "C", "type": "z", "severity": "medium", "file": "c", "line": 3},
            ],
        }
        diff = ms._compute_diff(prior, current)
        self.assertEqual([n["key"] for n in diff["new"]], ["C"])
        self.assertEqual([g["key"] for g in diff["gone"]], ["A"])
        self.assertEqual([k["key"] for k in diff["kept"]], ["B"])

    def test_merge_handles_artifact_with_null_findings(self):
        # If an intermediate artifact JSON has `"findings": null` (not
        # `[]`), the merge should tolerate it rather than crashing.
        import json as _json
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a.json"
            a.write_text(_json.dumps({
                "findings": None,
                "summary": {"total_findings": 0, "total_hotspots": 0,
                            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }))
            b = root / "b.json"
            b.write_text(_json.dumps({
                "findings": [
                    {"id": "F1", "type": "x", "kind": "finding",
                     "severity": "high", "file": "y.java", "line": 1},
                ],
                "summary": {"total_findings": 0, "total_hotspots": 0,
                            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            }))
            out = ms.merge_findings([a, b])
            self.assertEqual(len(out["findings"]), 1)

    def test_merge_findings_keeps_max_severity_on_dup(self):
        # Bug 44: when two artifacts had the same finding key with
        # different severities, the merge kept the FIRST one — silently
        # downgrading a "critical" finding from artifact 2 to "medium"
        # from artifact 1. Now takes max severity.
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "a1.json"
            p2 = Path(td) / "a2.json"
            p1.write_text(json.dumps({
                "summary": {"total_findings": 1, "total_hotspots": 0,
                            "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
                "findings": [{
                    "id": "F1", "stable_key": "vscout:aaa",
                    "kind": "finding", "severity": "medium",
                    "type": "x", "title": "T", "file": "a.java", "line": 1,
                    "confidence": "low",
                }],
            }))
            p2.write_text(json.dumps({
                "summary": {"total_findings": 1, "total_hotspots": 0,
                            "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
                "findings": [{
                    "id": "F1", "stable_key": "vscout:aaa",
                    "kind": "finding", "severity": "critical",
                    "type": "x", "title": "T", "file": "a.java", "line": 1,
                    "confidence": "high",
                }],
            }))
            merged = ms.merge_findings([p1, p2], skip_chains=True)
            findings_by_key = {f["stable_key"]: f for f in merged["findings"]}
            self.assertEqual(findings_by_key["vscout:aaa"]["severity"], "critical")
            self.assertEqual(findings_by_key["vscout:aaa"]["confidence"], "high")

    def test_finding_key_handles_empty_finding_distinctly(self):
        # Pre-fix: an "anonymous" finding (no stable_key/file/line/type)
        # collapsed to "None:None:None" — TWO such findings would dedupe
        # into one bucket in the diff. After the fix, each falls back
        # to its own `id`.
        ms = self._load_merger()
        f1 = {"id": "F1"}
        f2 = {"id": "F2"}
        self.assertNotEqual(ms._finding_key(f1), ms._finding_key(f2))

    def test_diff_skips_suppressed_findings_like_chains(self):
        # Bug 30: chain diff filtered out suppressed entries but finding
        # diff didn't. A suppressed finding leaked into "kept"/"new"/
        # "gone" buckets even though the operator silenced it.
        ms = self._load_merger()
        prior = {"findings": [{"id": "F1", "stable_key": "vscout:aaa",
                                "suppressed": True}]}
        current = {"findings": [{"id": "F1", "stable_key": "vscout:aaa",
                                  "suppressed": True}]}
        diff = ms._compute_diff(prior, current)
        # Suppressed finding shouldn't appear in any bucket
        self.assertEqual(diff["new"], [])
        self.assertEqual(diff["gone"], [])
        self.assertEqual(diff["kept"], [])

    def test_diff_handles_null_chains_and_findings_fields(self):
        # An artifact with `"chains": null` or `"findings": null` should
        # not crash the diff computation. Use case: hand-written
        # fixtures, partially-populated artifacts.
        ms = self._load_merger()
        prior = {"findings": None, "chains": None}
        current = {
            "findings": [
                {"stable_key": "F1", "type": "x", "severity": "high",
                 "file": "a.java", "line": 1},
            ],
            "chains": [{"stable_key": "chain-1", "name": "X", "severity": "high"}],
        }
        # Must not raise
        diff = ms._compute_diff(prior, current)
        # Everything should be "new" (since prior is empty)
        self.assertEqual(len(diff["new"]), 1)
        self.assertEqual(len(diff["chains"]["new"]), 1)

    def test_diff_excludes_suppressed_chains(self):
        # A chain marked suppressed in the current scan must NOT appear
        # in diff.chains.kept/new/gone — suppression semantics propagate
        # to diff just like they do to rollups and reports.
        ms = self._load_merger()
        prior = {
            "findings": [],
            "chains": [
                {"stable_key": "chain-a", "name": "A", "pattern": "p-a", "severity": "high"},
                {"stable_key": "chain-b", "name": "B", "pattern": "p-b", "severity": "medium"},
            ],
        }
        current = {
            "findings": [],
            "chains": [
                {"stable_key": "chain-a", "name": "A", "pattern": "p-a", "severity": "high"},
                # B is still present but suppressed
                {"stable_key": "chain-b", "name": "B", "pattern": "p-b", "severity": "medium",
                 "suppressed": True},
                {"stable_key": "chain-c", "name": "C", "pattern": "p-c", "severity": "high"},
            ],
        }
        diff = ms._compute_diff(prior, current)
        kept_keys = [k["stable_key"] for k in diff["chains"]["kept"]]
        new_keys = [k["stable_key"] for k in diff["chains"]["new"]]
        gone_keys = [k["stable_key"] for k in diff["chains"]["gone"]]
        # B is suppressed in current → looks "gone" from diff's perspective
        self.assertIn("chain-b", gone_keys)
        # A stays in kept (unsuppressed both sides)
        self.assertIn("chain-a", kept_keys)
        # C is new
        self.assertIn("chain-c", new_keys)

    def test_diff_chain_buckets_carry_pattern_slug(self):
        # new/gone/severity_drift entries should expose chain.pattern so
        # downstream consumers can pivot on the slug, not the prose name.
        ms = self._load_merger()
        prior = {
            "findings": [],
            "chains": [
                {"stable_key": "chain-aaa", "name": "Old", "pattern": "old-pat", "severity": "high"},
                {"stable_key": "chain-bbb", "name": "Same", "pattern": "same-pat", "severity": "medium"},
            ],
        }
        current = {
            "findings": [],
            "chains": [
                # Same key but escalated severity
                {"stable_key": "chain-bbb", "name": "Same", "pattern": "same-pat", "severity": "critical"},
                {"stable_key": "chain-ccc", "name": "New", "pattern": "new-pat", "severity": "high"},
            ],
        }
        diff = ms._compute_diff(prior, current)
        self.assertEqual(diff["chains"]["new"][0]["pattern"], "new-pat")
        self.assertEqual(diff["chains"]["gone"][0]["pattern"], "old-pat")
        self.assertEqual(diff["chains"]["severity_drift"][0]["pattern"], "same-pat")

    def test_diff_flags_chain_severity_drift(self):
        # A chain that survived but escalated/de-escalated should land in
        # `severity_drift`, not silently in `kept`.
        ms = self._load_merger()
        prior = {
            "findings": [],
            "chains": [
                {"stable_key": "chain-bbb", "name": "Chain B", "severity": "medium"},
                {"stable_key": "chain-ccc", "name": "Chain C", "severity": "high"},
            ],
        }
        current = {
            "findings": [],
            "chains": [
                # Same chain B, escalated medium → critical
                {"stable_key": "chain-bbb", "name": "Chain B", "severity": "critical"},
                # Same chain C, de-escalated high → medium
                {"stable_key": "chain-ccc", "name": "Chain C", "severity": "medium"},
            ],
        }
        diff = ms._compute_diff(prior, current)
        drift = diff["chains"]["severity_drift"]
        self.assertEqual(len(drift), 2)
        by_key = {d["stable_key"]: d for d in drift}
        self.assertEqual(by_key["chain-bbb"]["direction"], "escalated")
        self.assertEqual(by_key["chain-bbb"]["from_severity"], "medium")
        self.assertEqual(by_key["chain-bbb"]["to_severity"], "critical")
        self.assertEqual(by_key["chain-ccc"]["direction"], "de-escalated")

    def test_diff_against_prior_artifact_includes_chains(self):
        # Now that chains carry stable_keys, the diff also reports
        # chain-level new/gone/kept.
        ms = self._load_merger()
        prior = {
            "findings": [],
            "chains": [
                {"stable_key": "chain-aaa", "name": "Chain A", "severity": "high"},
                {"stable_key": "chain-bbb", "name": "Chain B", "severity": "medium"},
            ],
        }
        current = {
            "findings": [],
            "chains": [
                {"stable_key": "chain-bbb", "name": "Chain B", "severity": "medium"},
                {"stable_key": "chain-ccc", "name": "Chain C", "severity": "critical"},
            ],
        }
        diff = ms._compute_diff(prior, current)
        self.assertIn("chains", diff)
        self.assertEqual(
            [c["stable_key"] for c in diff["chains"]["new"]],
            ["chain-ccc"],
        )
        self.assertEqual(
            [c["stable_key"] for c in diff["chains"]["gone"]],
            ["chain-aaa"],
        )
        self.assertEqual(
            [c["stable_key"] for c in diff["chains"]["kept"]],
            ["chain-bbb"],
        )
        # New chain entries should also carry severity so reviewers can
        # triage from the diff alone.
        self.assertEqual(diff["chains"]["new"][0]["severity"], "critical")

    def test_nsc_enrichment_lists_cross_target_unpinned_hosts(self):
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            code_dir = root / "jadx_out" / "sources"
            code_dir.mkdir(parents=True)
            res_dir = root / "apktool_out"
            res_dir.mkdir(parents=True)
            (code_dir / "Api.java").write_text(
                'class Api {\n'
                '    String a = "https://api.example.com/v1/users";\n'
                '    String b = "https://payments.firstdata.com/token";\n'
                '    String c = "https://usebutton.com/sdk";\n'
                '}\n'
            )
            merged = {
                "findings": [
                    {
                        "stable_key": "n1",
                        "type": "mobile-nsc-narrow-pinning",
                        "title": "network_security_config pins only: usebutton.com",
                        "message": (
                            "Pinning is configured but only covers the listed domains. "
                            "Other API hosts (payment processors, identity, config) still "
                            "rely on system CA trust. Audit whether tokenization and auth "
                            "flows are inside the pinned set. (CWE-295)"
                        ),
                        "file": "res/xml/network_security_config.xml",
                        "line": 1,
                        "kind": "hotspot",
                        "severity": "low",
                    }
                ]
            }
            ms._enrich_nsc_finding(merged, [code_dir, res_dir])
            nsc = merged["findings"][0]
            self.assertIn("App code references", nsc["message"])
            unpinned = nsc.get("metadata", {}).get("unpinned_hosts", [])
            self.assertIn("api.example.com", unpinned)
            self.assertIn("payments.firstdata.com", unpinned)
            # The pinned host must not appear in the unpinned set
            self.assertNotIn("usebutton.com", unpinned)

    def test_nsc_enrichment_is_idempotent(self):
        ms = self._load_merger()
        merged = {
            "findings": [
                {
                    "type": "mobile-nsc-narrow-pinning",
                    "title": "network_security_config pins only: a.com",
                    "message": (
                        "Pinning is configured but only covers the listed domains. "
                        "App code references 2 other host(s) (sample: b.com, c.com) "
                        "that fall back to system CA trust."
                    ),
                }
            ]
        }
        before = merged["findings"][0]["message"]
        ms._enrich_nsc_finding(merged, [])
        self.assertEqual(merged["findings"][0]["message"], before)

    def test_discovery_handles_ios_layout(self):
        ms = self._load_merger()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "Sources").mkdir()
            (root / "Payload").mkdir()
            targets = ms.discover_mobile_targets(root)
            # On case-insensitive filesystems the discovery may resolve via
            # ``sources``/``Sources`` first; either is acceptable.
            target_names_ci = [t.name.lower() for t in targets]
            self.assertIn("sources", target_names_ci)
            self.assertIn("payload", target_names_ci)


class SubmissionTemplateTests(unittest.TestCase):
    """Verify submission_template.py emits a markdown submission per chain
    and per high-severity standalone finding."""

    @staticmethod
    def _load_sub():
        return _load("submission_template", SCRIPTS_DIR / "submission_template.py")

    def test_chain_submission_includes_participants(self):
        sub = self._load_sub()
        chain = {
            "id": "chain-001",
            "name": "Test chain",
            "impact": "test impact",
            "flow_description": "flow goes here",
            "finding_ids": ["F1", "F2"],
        }
        findings_by_id = {
            "F1": {"id": "F1", "type": "x", "severity": "high", "file": "a.java",
                   "line": 10, "chain_role": "entry", "evidence": [{"excerpt": "code a"}],
                   "message": "Use safe API."},
            "F2": {"id": "F2", "type": "y", "severity": "medium", "file": "b.java",
                   "line": 20, "chain_role": "sink", "evidence": [{"excerpt": "code b"}],
                   "message": "Escape output."},
        }
        md = sub._format_chain_submission(chain, findings_by_id)
        self.assertIn("# Test chain", md)
        self.assertIn("Entry", md)
        self.assertIn("Sink", md)
        self.assertIn("a.java:10", md)
        self.assertIn("b.java:20", md)
        # Remediation section pulls last sentence from messages
        self.assertIn("Use safe API", md)

    def test_chain_submission_renders_stable_key_and_chain_severity(self):
        sub = self._load_sub()
        chain = {
            "id": "chain-007",
            "stable_key": "chain-abcdef012345",
            "severity": "critical",
            "name": "Chain with severity",
            "impact": "kaboom",
            "flow_description": "x -> y",
            "finding_ids": ["F1"],
        }
        findings_by_id = {
            "F1": {"id": "F1", "type": "x", "severity": "low", "file": "a.java",
                   "line": 1, "chain_role": "entry", "evidence": [{"excerpt": "x"}],
                   "message": "Patch."},
        }
        md = sub._format_chain_submission(chain, findings_by_id)
        # Chain.severity takes precedence over max participant severity
        # (here participant is low, chain is critical — submission must use critical)
        self.assertIn("Critical", md)
        # Stable key surfaced in the header so reviewers can correlate
        # across scans / submissions.
        self.assertIn("chain-abcdef012345", md)

    def test_chain_submission_strips_trailing_cwe_from_remediation(self):
        # Bug 24: Pre-fix, msg ending in "(CWE-925)" made "(CWE-925)"
        # the "remediation" — masking the actual fix sentence.
        sub = self._load_sub()
        chain = {
            "id": "chain-001", "name": "Test",
            "impact": "i", "flow_description": "f",
            "finding_ids": ["F1"],
        }
        findings_by_id = {
            "F1": {"id": "F1", "type": "x", "severity": "high",
                   "file": "a.java", "line": 1,
                   "chain_role": "sink", "evidence": [{"excerpt": "x"}],
                   "message": "Bad thing. Use SecureRandom() instead. (CWE-330)"},
        }
        md = sub._format_chain_submission(chain, findings_by_id)
        # The actual remediation must surface — not the CWE annotation
        self.assertIn("Use SecureRandom() instead", md)
        # And the bare CWE annotation must NOT be in the remediation
        # section. (It still appears in the CWE header line though.)
        # Check by looking for the bullet point form.
        self.assertNotIn("- (CWE-330)", md)

    def test_chain_submission_renders_pattern_and_cwes(self):
        sub = self._load_sub()
        chain = {
            "id": "chain-001",
            "stable_key": "chain-abc123def456",
            "pattern": "mobile-token-replay",
            "severity": "high",
            "cwes": ["CWE-312", "CWE-639"],
            "name": "Mobile token-replay chain",
            "impact": "x",
            "flow_description": "y",
            "finding_ids": ["F1"],
        }
        findings_by_id = {
            "F1": {"id": "F1", "type": "x", "severity": "high",
                   "file": "a.java", "line": 1, "chain_role": "sink",
                   "evidence": [{"excerpt": "..."}],
                   "message": "Patch."},
        }
        md = sub._format_chain_submission(chain, findings_by_id)
        # Pattern slug surfaced in the header for at-a-glance identification.
        self.assertIn("mobile-token-replay", md)
        # CWE references rendered as linked text so bug-bounty platforms
        # can render them as clickable.
        self.assertIn("CWE-312", md)
        self.assertIn("CWE-639", md)
        self.assertIn("cwe.mitre.org", md)

    def test_chain_submission_surfaces_confidence_boost(self):
        sub = self._load_sub()
        chain = {
            "id": "chain-001",
            "name": "Boosted chain",
            "impact": "x",
            "flow_description": "y",
            "finding_ids": ["F1"],
        }
        findings_by_id = {
            "F1": {
                "id": "F1", "type": "mobile-webview-js-injection",
                "severity": "medium", "confidence": "medium",
                "file": "Helper.java", "line": 50,
                "chain_role": "sink",
                "metadata": {"confidence_boosted_by_chain": "chain-001"},
                "evidence": [{"excerpt": "..."}],
                "message": "Escape values.",
            },
        }
        md = sub._format_chain_submission(chain, findings_by_id)
        # Audit trail surfaced so reviewers know this was a chain-corroborated
        # promotion, not an organic medium-confidence finding.
        self.assertIn("[boosted by chain]", md)

    def test_individual_finding_submission_shape(self):
        sub = self._load_sub()
        finding = {
            "id": "F99", "stable_key": "key99",
            "title": "Bad thing", "severity": "high",
            "file": "x.py", "line": 5,
            "message": "Found bad thing.",
            "evidence": [{"excerpt": "do_bad()"}],
        }
        md = sub._format_finding_submission(finding)
        self.assertIn("# Bad thing", md)
        self.assertIn("F99", md)
        self.assertIn("x.py:5", md)
        self.assertIn("do_bad()", md)

    def test_submission_main_skips_suppressed_chains(self):
        import json as _json
        import subprocess
        sub_path = SCRIPTS_DIR / "submission_template.py"
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1, "chain_role": "entry",
                 "evidence": [{"excerpt": "x"}], "message": "x.",
                 "suppressed": True}
            ],
            "chains": [
                {"id": "chain-001", "pattern": "mobile-debuggable-secret",
                 "stable_key": "chain-suppressed",
                 "name": "Suppressed chain",
                 "severity": "high", "suppressed": True,
                 "impact": "x", "flow_description": "y",
                 "finding_ids": ["F1"]},
                {"id": "chain-002", "pattern": "mobile-token-replay",
                 "stable_key": "chain-active",
                 "name": "Active chain", "severity": "high",
                 "impact": "x", "flow_description": "y",
                 "finding_ids": []},
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            ap = Path(td) / "art.json"
            ap.write_text(_json.dumps(artifact))
            out = Path(td) / "out"
            result = subprocess.run(
                ["python3", str(sub_path), str(ap), "--output-dir", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            files = sorted(p.name for p in out.iterdir())
            # Only the active chain should produce a submission file.
            self.assertTrue(
                any("mobile-token-replay" in name for name in files),
                f"expected active chain submission, got: {files}",
            )
            self.assertFalse(
                any("mobile-debuggable-secret" in name for name in files),
                f"suppressed chain should not produce a submission, got: {files}",
            )

    def test_chain_submission_filename_uses_pattern_and_stable_key(self):
        # When `submission_template.main` runs, files should be named by
        # pattern + stable_key (deterministic, descriptive) rather than the
        # volatile chain-NNN id.
        import json as _json
        import subprocess
        sub_path = SCRIPTS_DIR / "submission_template.py"
        artifact = {
            "findings": [
                {"id": "F1", "type": "x", "severity": "high", "kind": "finding",
                 "file": "a.java", "line": 1, "chain_role": "entry",
                 "evidence": [{"excerpt": "..."}], "message": "x."}
            ],
            "chains": [
                {"id": "chain-001",
                 "pattern": "mobile-token-replay",
                 "stable_key": "chain-9a79f7517365",
                 "name": "Mobile token-replay chain",
                 "severity": "high",
                 "impact": "i", "flow_description": "f",
                 "finding_ids": ["F1"]},
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            ap = Path(td) / "art.json"
            ap.write_text(_json.dumps(artifact))
            out = Path(td) / "out"
            result = subprocess.run(
                ["python3", str(sub_path), str(ap), "--output-dir", str(out)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            files = sorted(p.name for p in out.iterdir())
            # The chain file's name MUST include both the pattern slug
            # and the stable_key (without the "chain-" prefix duplicate).
            self.assertTrue(
                any(name.startswith("submission-mobile-token-replay-") for name in files),
                f"expected pattern-prefixed filename, got: {files}",
            )


class MobileScanIntegrationTests(unittest.TestCase):
    """End-to-end: build a synthetic jadx_out/sources + apktool_out target,
    invoke mobile_scan.main, and verify both code-side and resource-side
    findings end up in the same merged artifact with chains attached."""

    def test_full_pipeline_produces_chains(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Synthetic jadx_out/sources with the PIE-style tokenization shape
            chase = root / "jadx_out" / "sources" / "com" / "example" / "app" / "payment" / "processors" / "services" / "chase" / "js"
            chase.mkdir(parents=True)
            (chase / "a.java").write_text(r"""
package com.example.app.payment.processors.services.chase.js;
public final class a {
    public final String b(ap1 ap1Var, cja cjaVar) {
        int i = cjaVar.a;
        int i2 = cjaVar.b;
        String str = cjaVar.c;
        String str2 = cjaVar.d;
        StringBuilder sbC = no.c(i, i2, "var PIE = {L:", ",E:", ",K:\"");
        qn0.e(sbC, str, "\",key_id:\"", str2, "\",phase:");
        StringBuilder sbG = ue0.g("<script>", "x", "</script>");
        return apf.p(sbG.toString());
    }
}
""")
            # Sibling api/ with remote-controlled URL
            api = root / "jadx_out" / "sources" / "com" / "example" / "app" / "payment" / "processors" / "services" / "chase" / "api"
            api.mkdir(parents=True)
            (api / "X.java").write_text("""
package com.example.app.payment.processors.services.chase.api;
import com.example.app.networking.CoroutineCallFactory;
public final class X {
    public String url() {
        return this.a.getString("CHASE_URL", "https://default.example/x").concat("/path");
    }
}
""")
            # Synthetic apktool_out with NSC narrow pinning
            res = root / "apktool_out" / "res" / "xml"
            res.mkdir(parents=True)
            (res / "network_security_config.xml").write_text("""<?xml version="1.0"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set><pin digest="SHA-256">aaaa</pin></pin-set>
    </domain-config>
</network-security-config>""")

            out_file = root / "out.json"
            rc = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "mobile_scan.py"),
                 str(root), "--output", str(out_file)],
                capture_output=True, text=True,
            )
            self.assertEqual(rc.returncode, 0, f"stderr: {rc.stderr}")
            self.assertTrue(out_file.is_file())
            data = json.loads(out_file.read_text())
            types = [f["type"] for f in data.get("findings", [])]
            self.assertIn("mobile-webview-js-injection", types)
            self.assertIn("mobile-remote-controlled-endpoint", types)
            self.assertIn("mobile-nsc-narrow-pinning", types)
            chain_names = [c["name"] for c in data.get("chains", [])]
            self.assertTrue(
                any("WebView dispatch" in n for n in chain_names),
                f"expected WebView dispatch chain, got: {chain_names}",
            )


if __name__ == "__main__":
    unittest.main()
