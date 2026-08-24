"""End-to-end and unit tests for the APK Sentinel engine.

Run with either::

    python -m unittest discover -s tests
    python -m pytest tests

The tests build a synthetic vulnerable APK on the fly (no Android SDK needed)
via ``tools/make_sample_apk.py``, which also exercises the AXML *writer* against
the AXML *parser* as a round-trip.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

from apk_sentinel import axml, dex, secrets  # noqa: E402
from apk_sentinel.analyzer import analyze_apk  # noqa: E402
from apk_sentinel.manifest import _to_bool, _resolve_name, build as build_manifest  # noqa: E402
from apk_sentinel.models import AnalysisResult, Finding, Severity  # noqa: E402
from apk_sentinel.report import render_html, render_json, render_markdown  # noqa: E402
import make_sample_apk  # noqa: E402


def _sample_apk(dirpath: str) -> str:
    path = os.path.join(dirpath, "sample-vulnerable.apk")
    make_sample_apk.build_apk(path)
    return path


class SampleApkFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="apksentinel-test-")
        cls.apk = _sample_apk(cls.tmp)
        cls.result = analyze_apk(cls.apk)


class TestAxmlRoundTrip(SampleApkFixture):
    def test_manifest_decodes(self):
        m = self.result.manifest
        self.assertEqual(m.package, "com.example.vulnerableapp")
        self.assertEqual(m.version_name, "1.0")
        self.assertEqual(m.version_code, 1)
        self.assertEqual(m.min_sdk, 19)
        self.assertEqual(m.target_sdk, 26)

    def test_flags_decode(self):
        m = self.result.manifest
        self.assertTrue(m.debuggable)
        self.assertTrue(m.allow_backup)
        self.assertTrue(m.uses_cleartext_traffic)

    def test_components_decode(self):
        m = self.result.manifest
        names = {c.name for c in m.all_components}
        self.assertIn("com.example.vulnerableapp.SecretActivity", names)
        self.assertIn("com.example.vulnerableapp.DataProvider", names)
        provider = next(c for c in m.providers if c.name.endswith("DataProvider"))
        self.assertTrue(provider.effective_exported)
        self.assertEqual(provider.authorities, "com.example.vulnerableapp.provider")

    def test_permissions_decode(self):
        perms = self.result.manifest.permissions
        self.assertIn("android.permission.READ_SMS", perms)
        self.assertIn("android.permission.SYSTEM_ALERT_WINDOW", perms)

    def test_not_axml_raises(self):
        with self.assertRaises(axml.AXMLParseError):
            axml.parse(b"not binary xml at all")


class TestRulesFire(SampleApkFixture):
    def _ids(self):
        return {f.id for f in self.result.findings}

    def test_critical_findings(self):
        ids = self._ids()
        self.assertIn("android-debuggable", ids)
        self.assertIn("hardcoded-secret", ids)

    def test_high_findings(self):
        ids = self._ids()
        self.assertIn("cleartext-traffic-enabled", ids)
        self.assertIn("exported-content-provider", ids)

    def test_medium_findings(self):
        ids = self._ids()
        self.assertIn("exported-component-no-permission", ids)
        self.assertIn("weak-custom-permission", ids)
        self.assertIn("high-risk-permissions", ids)

    def test_grade_is_f(self):
        self.assertEqual(self.result.grade, "F")
        self.assertEqual(self.result.risk_score, 100)

    def test_launcher_activity_not_flagged(self):
        # MainActivity is the launcher; it must not appear in the exported finding
        exported = next(f for f in self.result.findings if f.id == "exported-component-no-permission")
        joined = " ".join(exported.evidence)
        self.assertNotIn("MainActivity", joined)
        self.assertIn("SecretActivity", joined)

    def test_every_finding_has_remediation(self):
        for f in self.result.findings:
            self.assertTrue(f.remediation, f"{f.id} missing remediation")
            self.assertIsInstance(f.severity, Severity)


class TestSecrets(SampleApkFixture):
    def test_secret_kinds_detected(self):
        kinds = {s.kind for s in self.result.secrets}
        self.assertIn("AWS Access Key ID", kinds)
        self.assertIn("Google API Key", kinds)

    def test_secret_values_masked(self):
        for s in self.result.secrets:
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", s.value_preview)

    def test_scan_strings_direct(self):
        found = secrets.scan_strings(["AKIAIOSFODNN7EXAMPLE", "nothing here"])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].kind, "AWS Access Key ID")

    def test_cleartext_urls_ignores_schemas(self):
        urls = secrets.find_cleartext_urls([
            "http://schemas.android.com/apk/res/android",
            "http://api.real-endpoint.example/login",
        ])
        self.assertEqual(urls, ["http://api.real-endpoint.example/login"])


class TestDex(SampleApkFixture):
    def test_dex_strings_extracted(self):
        # analyzer already ran; re-extract directly for a focused check
        import zipfile
        with zipfile.ZipFile(self.apk) as z:
            blob = z.read("classes.dex")
        strings = dex.extract_strings(blob)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", strings)
        self.assertIn("addJavascriptInterface", strings)

    def test_non_dex_returns_empty(self):
        self.assertEqual(dex.extract_strings(b"not a dex"), [])


class TestReports(SampleApkFixture):
    def test_json_round_trips(self):
        import json
        data = json.loads(render_json(self.result))
        self.assertEqual(data["manifest"]["package"], "com.example.vulnerableapp")
        self.assertEqual(data["grade"], "F")
        self.assertIn("findings", data)

    def test_markdown_has_sections(self):
        md = render_markdown(self.result)
        self.assertIn("# APK Sentinel Report", md)
        self.assertIn("Prioritized action plan", md)
        self.assertIn("android:debuggable", md)

    def test_html_is_self_contained(self):
        html = render_html(self.result)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertNotIn("http://cdn", html)          # no external resources
        self.assertIn("Executive summary", html)
        self.assertIn("Step-by-step", html)            # extended guide present

    def test_html_escapes_evidence(self):
        # a finding with an angle-bracket in evidence must be escaped
        html = render_html(self.result)
        self.assertNotIn("<application android:debuggable", html)
        self.assertIn("&lt;application", html)


class TestProtectionLevel(unittest.TestCase):
    """Regression: real aapt compiles protectionLevel to an integer, so the
    weak-custom-permission rule must handle "0"/"1"/"2" as well as names."""

    def test_weak_levels(self):
        from apk_sentinel.rules import _protection_is_weak
        for weak in (None, "", "0", "1", "0x0", "0x1", "normal", "dangerous"):
            self.assertTrue(_protection_is_weak(weak), weak)

    def test_strong_levels(self):
        from apk_sentinel.rules import _protection_is_weak
        for strong in ("2", "0x2", "signature", "signatureOrSystem", "18", "0x12"):
            self.assertFalse(_protection_is_weak(strong), strong)

    def test_sample_fires_with_integer_level(self):
        # The sample encodes protectionLevel as the integer 0 (like aapt);
        # the finding must still fire.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            apk = _sample_apk(d)
            result = analyze_apk(apk)
            self.assertIn("weak-custom-permission", {f.id for f in result.findings})


class TestLauncherDetection(unittest.TestCase):
    def _act(self, actions, categories):
        from apk_sentinel.models import Component
        return Component(kind="activity", name="A", intent_actions=actions,
                         intent_categories=categories, has_intent_filter=True)

    def test_requires_both_main_and_launcher(self):
        from apk_sentinel.rules import _launcher
        MAIN = "android.intent.action.MAIN"
        LAUNCHER = "android.intent.category.LAUNCHER"
        self.assertTrue(_launcher(self._act([MAIN], [LAUNCHER])))
        self.assertFalse(_launcher(self._act([MAIN], [])))          # MAIN only
        self.assertFalse(_launcher(self._act([], [LAUNCHER])))      # category only


class TestRobustness(unittest.TestCase):
    """Malformed binary input must fail gracefully, never with a raw
    struct.error / IndexError bubbling out of the engine."""

    def test_truncated_axml_raises_clean_error(self):
        from apk_sentinel import axml
        # Valid RES_XML magic header but nothing after it.
        blob = b"\x03\x00\x08\x00\x08\x00\x00\x00"
        with self.assertRaises(axml.AXMLParseError):
            axml.parse(blob)

    def test_garbage_after_header_does_not_crash(self):
        from apk_sentinel import axml
        blob = b"\x03\x00\x08\x00\xff\xff\x00\x00" + b"\xff" * 40
        try:
            axml.parse(blob)
        except axml.AXMLParseError:
            pass  # acceptable: a clean, typed error
        # any other exception type would fail the test


class TestModels(unittest.TestCase):
    def _result_with(self, *sevs):
        r = AnalysisResult(file_name="x", file_size=1, sha256="a", md5="b")
        for i, s in enumerate(sevs):
            r.findings.append(Finding(id=f"f{i}", title="t", severity=s,
                                      category="c", description="d"))
        return r

    def test_grade_critical(self):
        self.assertEqual(self._result_with(Severity.CRITICAL).grade, "F")

    def test_grade_high(self):
        self.assertEqual(self._result_with(Severity.HIGH).grade, "D")

    def test_grade_clean(self):
        self.assertEqual(self._result_with().grade, "A+")

    def test_risk_score_caps_at_100(self):
        r = self._result_with(*([Severity.CRITICAL] * 10))
        self.assertEqual(r.risk_score, 100)

    def test_severity_ordering(self):
        self.assertLess(Severity.CRITICAL.rank, Severity.LOW.rank)


class TestManifestHelpers(unittest.TestCase):
    def test_to_bool(self):
        self.assertTrue(_to_bool("true"))
        self.assertTrue(_to_bool("0xffffffff"))
        self.assertFalse(_to_bool("false"))
        self.assertIsNone(_to_bool(None))

    def test_resolve_name(self):
        self.assertEqual(_resolve_name(".Foo", "com.x"), "com.x.Foo")
        self.assertEqual(_resolve_name("Foo", "com.x"), "com.x.Foo")
        self.assertEqual(_resolve_name("com.y.Foo", "com.x"), "com.y.Foo")


if __name__ == "__main__":
    unittest.main(verbosity=2)
