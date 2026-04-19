import sys
import os
import pytest
import io
import json
import math
import unittest
from unittest.mock import MagicMock, patch

# ── 1. Path Management ────────────────────────────────────────────────────────
# Ensures the script can find 'app' regardless of where it's executed from.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app
from app.engine.entropy    import dga_score, EntropyResult
from app.engine.scorer     import analyse_url, _CRITICAL_OVERRIDE_FLOORS
from app.engine.reputation import is_allowlisted, is_blocklisted, is_highly_trusted
from app.utils.validators  import validate_url_payload

# ══════════════════════════════════════════════════════════════════════════════
# 🧪 PYTEST SUITES (For Automated Reports)
# ══════════════════════════════════════════════════════════════════════════════

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_qr_image_bytes(url: str) -> bytes:
    """
    Generate a valid PNG QR code for `url` using the `qrcode` library.
    The tests import this lazily so they can be skipped gracefully if the
    library is not installed (it's a test-only dependency).
    """
    try:
        import qrcode  # type: ignore
    except ImportError:
        raise unittest.SkipTest("`qrcode` package not installed — run: pip install qrcode[pil]")

    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

# ---------------------------------------------------------------------------
# F-08 / F-09 — entropy + pillar tests
# ---------------------------------------------------------------------------

class TestEntropyResult(unittest.TestCase):
    """F-08: assert the correct attributes (is_dga, entropy) not .normalized."""

    def test_known_dga_label_is_flagged(self):
        result = dga_score("xkj3mq7vptlz8nw")   # synthetic high-entropy
        # F-08 FIX: Assert using correct attribute is_dga instead of .normalized
        self.assertIsInstance(result.is_dga, bool)
        self.assertIsInstance(result.entropy, float)
        self.assertTrue(result.is_dga, f"Expected is_dga=True, entropy={result.entropy:.2f}")

    def test_real_brand_not_flagged(self):
        for label in ("github", "instagram", "microsoft", "amazon"):
            result = dga_score(label)
            self.assertFalse(
                result.is_dga,
                f"'{label}' should not be flagged as DGA (entropy={result.entropy:.2f})"
            )

    def test_entropy_is_float_in_range(self):
        result = dga_score("randomlabel")
        self.assertGreaterEqual(result.entropy, 0.0)
        # H_MAX = log2(36) ≈ 5.17; real entropy can't exceed character-set entropy
        self.assertLessEqual(result.entropy, math.log2(36) + 0.01)

    def test_short_label_not_scored(self):
        result = dga_score("ab")
        self.assertFalse(result.is_dga)
        self.assertEqual(result.entropy, 0.0)

    def test_digit_heavy_brand_not_flagged(self):
        """F-06: '365scores' and '123rf' should not be DGA after threshold fix."""
        for label in ("365scores", "123rf", "mp3"):
            result = dga_score(label)
            self.assertFalse(
                result.is_dga,
                f"'{label}' incorrectly flagged as DGA (entropy={result.entropy:.2f})"
            )

class TestReputation:
    def test_tranco_reputation_killer(self):
        """Verify that Tranco Top 100k domains are recognized as highly trusted."""
        assert is_highly_trusted("google.com")
        assert is_highly_trusted("facebook.com")
        assert not is_highly_trusted("x7z9q2mwpb.ru")

    def test_known_spoof_blocklisted(self):
        assert is_blocklisted("https://xn--pple-43d.com/login")


class TestScorerPillars(unittest.TestCase):

    def _score(self, url: str, trace_data: dict | None = None) -> dict:
        """Helper: run scorer with a minimal trace stub to avoid network calls."""
        if trace_data is None:
            trace_data = {
                "redirect_chain": [], "final_url": url, "hop_count": 0, "shortener_count": 0,
                "meta_refresh_found": False, "error": None
            }
        return analyse_url(url, trace_data=trace_data)

    # ── F-09: check all 11 pillar names ─────────────────────────────────────
    def test_all_11_pillar_names_present(self):
        """F-09: was checking only 8; now asserts all 11."""
        result = self._score("https://example.com")
        names = {c["name"] for c in result["checks"]}
        expected = {
            "reputation",       # F-09 addition
            "punycode",
            "ip_literal",
            "suspicious_tld",
            "subdomain_depth",
            "https_mismatch",
            "path_keywords",
            "dga_entropy",
            "redirect_depth",
            "nested_short",     # F-09 addition
            "html_evasion",     # F-09 addition
        }
        self.assertEqual(names, expected, f"Missing pillars: {expected - names}")

    # ── F-01: ip_literal uses full_host ──────────────────────────────────────
    def test_ip_literal_detected(self):
        """F-01: 192.168.1.1 must trigger ip_literal and hit the critical floor."""
        result = self._score("http://192.168.1.1/login")
        ip_check = next(c for c in result["checks"] if c["name"] == "ip_literal")
        self.assertTrue(ip_check["triggered"], "ip_literal should trigger for IPv4 host")
        self.assertGreaterEqual(
            result["risk_score"],
            _CRITICAL_OVERRIDE_FLOORS["ip_literal"],
            f"Score {result['risk_score']} below ip_literal floor {_CRITICAL_OVERRIDE_FLOORS['ip_literal']}"
        )

    def test_ip_literal_not_triggered_for_domain(self):
        result = self._score("https://example.com")
        ip_check = next(c for c in result["checks"] if c["name"] == "ip_literal")
        self.assertFalse(ip_check["triggered"])

    # ── Punycode / IDN ───────────────────────────────────────────────────────
    def test_punycode_detected(self):
        result = self._score("https://xn--pypal-4ve.com/account/login")
        puny = next(c for c in result["checks"] if c["name"] == "punycode")
        self.assertTrue(puny["triggered"])
        self.assertGreaterEqual(result["risk_score"], _CRITICAL_OVERRIDE_FLOORS["punycode"])

    # ── Critical floors apply ─────────────────────────────────────────────────
    def test_critical_floor_overrides_low_raw_score(self):
        """A single triggered critical pillar must push score above its floor."""
        # Force only the ip_literal pillar to trigger by using a raw IP URL
        # with HTTPS (no https_mismatch) and no keywords.
        result = self._score("https://10.0.0.1/")
        self.assertGreaterEqual(result["risk_score"], _CRITICAL_OVERRIDE_FLOORS["ip_literal"])

    # ── Risk labels ───────────────────────────────────────────────────────────
    def test_safe_label_for_clean_url(self):
        result = self._score("https://example.com")
        self.assertEqual(result["risk_label"], "safe")

    def test_danger_label_for_ip_url(self):
        result = self._score("http://192.168.1.1/verify/account")
        self.assertEqual(result["risk_label"], "danger")

    # ── Tranco immunity ───────────────────────────────────────────────────────
    def test_tranco_domain_gets_negative_score(self):
        """Reputation pillar returns −50 for a top-ranked domain."""
        with patch("app.engine.scorer.is_highly_trusted", return_value=True):
            result = self._score("https://google.com")
        rep = next(c for c in result["checks"] if c["name"] == "reputation")
        self.assertEqual(rep["score"], -50)
        self.assertTrue(rep["triggered"])

    # ── Nested shorteners ─────────────────────────────────────────────────────
    def test_nested_short_triggers_on_two_shorteners(self):
        trace = {
            "redirect_chain": ["https://bit.ly/abc", "https://tinyurl.com/xyz", "https://evil.tk/"],
            "final_url": "https://evil.tk/",
            "hop_count": 3,
            "shortener_count": 2,
            "meta_refresh_found": False,
            "error": None
        }
        result = self._score("https://bit.ly/abc", trace_data=trace)
        ns = next(c for c in result["checks"] if c["name"] == "nested_short")
        self.assertTrue(ns["triggered"])
        self.assertGreaterEqual(result["risk_score"], _CRITICAL_OVERRIDE_FLOORS["nested_short"])

    # ── HTML evasion ──────────────────────────────────────────────────────────
    def test_html_evasion_triggers_on_meta_refresh(self):
        trace = {
            "redirect_chain": [], "final_url": "https://example.com",
            "hop_count": 0, "shortener_count": 0, "meta_refresh_found": True,
            "error": None
        }
        result = self._score("https://example.com", trace_data=trace)
        ev = next(c for c in result["checks"] if c["name"] == "html_evasion")
        self.assertTrue(ev["triggered"])
        self.assertGreaterEqual(result["risk_score"], _CRITICAL_OVERRIDE_FLOORS["html_evasion"])


class TestValidator:
    def test_double_scheme_rejection(self):
        ok, _ = validate_url_payload("http://http://google.com")
        assert not ok

# ---------------------------------------------------------------------------
# F-10 — /api/v1/scan-image endpoint tests
# ---------------------------------------------------------------------------

class TestScanImageEndpoint(unittest.TestCase):
    """
    F-10: Previously no tests existed for this endpoint.
    These tests exercise the happy path, error paths, and ensure F-02
    (double-resolve elimination) is reachable through the HTTP layer.
    """

    def setUp(self):
        self.app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET": "test-secret",
            "SECRET_KEY": "test-secret",
        })
        self.client = self.app.test_client()

    # ── 400 — missing file field ──────────────────────────────────────────────
    def test_missing_file_returns_400(self):
        resp = self.client.post("/api/v1/scan-image", data={})
        self.assertEqual(resp.status_code, 400)
        body = json.loads(resp.data)
        self.assertIn("error", body)

    # ── 422 — non-image bytes ─────────────────────────────────────────────────
    def test_invalid_image_bytes_returns_415(self):
        resp = self.client.post(
            "/api/v1/scan-image",
            data={"file": (io.BytesIO(b"this is not an image"), "test.png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 415)

    # ── 200 — valid QR with URL ───────────────────────────────────────────────
    def test_valid_qr_returns_analysis(self):
        """
        Generate a real QR code for https://example.com, POST it, and assert
        the response includes analysis data.  Also verifies F-02: trace_redirects
        is called exactly once per code (not twice).
        """
        img_bytes = _make_qr_image_bytes("https://example.com")

        # Patch trace_redirects to count invocations (F-02 verification).
        with patch("app.routes.scan_image.trace_redirects") as mock_trace, \
             patch("app.routes.scan_image.analyse_url") as mock_analyse:

            mock_trace.return_value = {
                "redirect_chain": [], "final_url": "https://example.com",
                "hop_count": 0, "meta_refresh_found": False, "shortener_count": 0,
                "error": None
            }
            mock_analyse.return_value = {
                "url": "https://example.com",
                "resolved_url": "https://example.com",
                "risk_score": 0, "risk_label": "safe",
                "top_threat": "None", "redirect_chain": [], "hop_count": 0,
                "is_allowlisted": False, "is_blocklisted": False,
                "overall_assessment": "Analysis suggests SAFE.",
                "checks": [],
            }

            resp = self.client.post(
                "/api/v1/scan-image",
                data={"file": (io.BytesIO(img_bytes), "qr.png")},
                content_type="multipart/form-data",
            )

        self.assertEqual(resp.status_code, 200)
        body = json.loads(resp.data)
        self.assertIn("found", body)
        self.assertIn("codes", body)
        self.assertIsInstance(body["codes"], list)

        # F-02: trace_redirects must have been called exactly once per QR code.
        self.assertEqual(
            mock_trace.call_count, 1,
            "F-02 regression: trace_redirects should be called exactly once per code"
        )
        # analyse_url must receive the trace_data kwarg (not None).
        call_kwargs = mock_analyse.call_args.kwargs
        self.assertIn(
            "trace_data", call_kwargs,
            "F-02 regression: analyse_url must be called with trace_data="
        )
        self.assertIsNotNone(call_kwargs["trace_data"])

# ══════════════════════════════════════════════════════════════════════════════
# 🚀 VERBOSE TERMINAL TEST (For Manual Inspection)
# ══════════════════════════════════════════════════════════════════════════════

def run_verbose_test():
    print("\n" + "="*60)
    print("🚀 --- QUISHING GUARD HEURISTIC ENGINE: LIVE INSPECTION --- 🚀")
    print("="*60 + "\n")

    # Test Case 1: High Reputation
    print("🔍 [TEST 1] Legitimate Domain: google.com")
    res1 = analyse_url("https://google.com")
    print(f"   ➤ Score: {res1['risk_score']} | Label: {res1['risk_label'].upper()}")
    print(f"   ➤ Assessment: {res1['overall_assessment']}\n")

    # Test Case 2: Phishing Simulation
    phish_url = "https://auth.verify.secure.update.x7z9q2mwpb.ru"
    print(f"🔍 [TEST 2] Deceptive Link: {phish_url}")
    res2 = analyse_url(phish_url)
    
    print(f"   ➤ Score: {res2['risk_score']} | Label: {res2['risk_label'].upper()}")
    print(f"   ➤ Triggered Threat Indicators:")
    
    for check in res2['checks']:
        if check['triggered']:
            status_icon = "🔴" if check['score'] >= 20 else "🟡"
            print(f"      {status_icon} {check['label']} (+{check['score']} pts): {check['message']}")
    
    print("\n" + "="*60)
    print("✅ --- ANALYSIS COMPLETE --- ✅")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_verbose_test()
