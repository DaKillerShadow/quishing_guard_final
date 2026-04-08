"""
tests/test_engine.py — Quishing Guard Engine Tests
====================================================
Covers:
  - Shannon entropy computation
  - DGA detection thresholds
  - Heuristic scorer (each of 8 checks)
  - Risk label boundaries
  - Reputation allow/block list lookups
  - Input validator
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app.engine.entropy    import dga_score
from app.engine.scorer     import score
from app.engine.reputation import is_allowlisted, is_blocklisted
from app.utils.validators  import validate_url_payload


# ═══════════════════════════════════════════════════════════════
#  ENTROPY ENGINE
# ═══════════════════════════════════════════════════════════════

class TestEntropy:
    def test_legitimate_domain_low_entropy(self):
        """Human-readable domains should not trigger DGA detection."""
        for d in ["paypal", "google", "amazon", "facebook", "apple"]:
            r = dga_score(d)
            assert not r.is_dga, f"{d} falsely flagged as DGA (entropy={r.entropy})"

    def test_dga_domain_high_entropy(self):
        """Machine-generated strings should be flagged."""
        r = dga_score("kzxwmqbvptjd")
        assert r.is_suspicious or r.is_dga, f"DGA domain not flagged (entropy={r.entropy})"

    def test_short_label_ignored(self):
        """Labels shorter than MIN_LABEL_LEN should return zero entropy."""
        r = dga_score("io")
        assert r.entropy == 0.0

    def test_entropy_non_negative(self):
        """Entropy should always be ≥ 0."""
        for d in ["a", "abc", "x7z9q", "paypal", "kzxwmqbvptjd"]:
            r = dga_score(d)
            assert r.entropy >= 0.0

    def test_empty_string(self):
        r = dga_score("")
        assert r.entropy == 0.0 and not r.is_dga


# ═══════════════════════════════════════════════════════════════
#  REPUTATION LAYER
# ═══════════════════════════════════════════════════════════════

class TestReputation:
    def test_google_is_allowlisted(self):
        assert is_allowlisted("https://www.google.com/maps?q=test")

    def test_paypal_is_allowlisted(self):
        assert is_allowlisted("https://paypal.com/checkout")

    def test_random_domain_not_allowlisted(self):
        assert not is_allowlisted("https://x7z9q2.ru/login")

    def test_known_spoof_blocklisted(self):
        assert is_blocklisted("https://xn--pple-43d.com/login")

    def test_unknown_domain_not_blocklisted(self):
        assert not is_blocklisted("https://legitimate-example-brand.com")


# ═══════════════════════════════════════════════════════════════
#  HEURISTIC SCORER
# ═══════════════════════════════════════════════════════════════

class TestScorer:
    def test_safe_url_low_score(self):
        result = score(
            resolved_url="https://www.google.com/maps",
            allowlisted=True,
        )
        assert result.risk_score == 0
        assert result.risk_label == "safe"

    def test_ip_literal_detected(self):
        result = score(resolved_url="http://185.220.101.52/login")
        ip_check = next(c for c in result.checks if c.name == "ip_literal")
        assert ip_check.triggered
        assert ip_check.score > 0

    def test_punycode_detected(self):
        result = score(resolved_url="https://xn--pple-43d.com/account")
        pc = next(c for c in result.checks if c.name == "punycode")
        assert pc.triggered
        assert pc.score == 30

    def test_redirect_depth_flagged(self):
        result = score(
            resolved_url="https://evil.ru/phish",
            redirect_chain=["https://a.com", "https://b.com", "https://c.com", "https://evil.ru/phish"],
            hop_count=4,
        )
        rd = next(c for c in result.checks if c.name == "redirect_depth")
        assert rd.triggered

    def test_redirect_depth_not_flagged_short(self):
        result = score(
            resolved_url="https://example.com",
            redirect_chain=["https://short.ly/abc", "https://example.com"],
            hop_count=2,
        )
        rd = next(c for c in result.checks if c.name == "redirect_depth")
        assert not rd.triggered

    def test_suspicious_tld_flagged(self):
        result = score(resolved_url="https://login-secure.tk/verify")
        tld = next(c for c in result.checks if c.name == "suspicious_tld")
        assert tld.triggered

    def test_https_mismatch_flagged(self):
        result = score(resolved_url="http://example.com/login")
        https = next(c for c in result.checks if c.name == "https_mismatch")
        assert https.triggered

    def test_score_capped_at_100(self):
        """Multiple high-risk checks should not exceed 100."""
        result = score(
            resolved_url="http://xn--pple-43d.tk/login",
            redirect_chain=["a", "b", "c", "d"],
            hop_count=4,
        )
        assert result.risk_score <= 100

    def test_risk_labels(self):
        """Boundary conditions for safe/warning/danger labels."""
        assert score(resolved_url="https://paypal.com", allowlisted=True).risk_label == "safe"
        # Construct a score in the warning range
        r = score(resolved_url="http://example-legit.com")  # http = +7
        # Label reflects score
        if r.risk_score < 30:
            assert r.risk_label == "safe"
        elif r.risk_score < 60:
            assert r.risk_label == "warning"
        else:
            assert r.risk_label == "danger"

    def test_danger_compound(self):
        """Punycode + redirect + http + suspicious TLD should reach danger (score ≥ 60).

        Breakdown: punycode=30, redirect_depth=20, https_mismatch=7, suspicious_tld=8 → 65
        Using .tk ensures the suspicious_tld check fires to cross the 60-point threshold.
        """
        result = score(
            resolved_url="http://xn--pple-43d.tk/account",
            hop_count=4,
            redirect_chain=["a","b","c","d","http://xn--pple-43d.tk/account"],
        )
        assert result.risk_score >= 60
        assert result.risk_label == "danger"

    def test_blocklisted_instant_danger(self):
        result = score(
            resolved_url="https://xn--pple-43d.com",
            blocklisted=True,
        )
        assert result.risk_score == 100
        assert result.risk_label == "danger"

    def test_all_checks_present(self):
        """Response must contain all 7 standard checks (or allowlist/blocklist shortcut)."""
        result = score(resolved_url="https://example.com")
        check_names = {c.name for c in result.checks}
        expected = {"ip_literal", "punycode", "dga_entropy", "redirect_depth",
                    "suspicious_tld", "subdomain_depth", "https_mismatch"}
        assert expected == check_names

    def test_top_threat_highest_score(self):
        """top_threat must be the name of the highest-scoring triggered check."""
        result = score(
            resolved_url="https://xn--pple-43d.com/login",
            hop_count=4,
            redirect_chain=["a","b","c","d","https://xn--pple-43d.com/login"],
        )
        triggered = [c for c in result.checks if c.triggered]
        if triggered:
            best = max(triggered, key=lambda c: c.score)
            assert result.top_threat == best.name


# ═══════════════════════════════════════════════════════════════
#  INPUT VALIDATOR
# ═══════════════════════════════════════════════════════════════

class TestValidator:
    def test_valid_https_url(self):
        ok, msg = validate_url_payload("https://example.com/path")
        assert ok and msg == ""

    def test_valid_http_url(self):
        ok, _ = validate_url_payload("http://example.com")
        assert ok

    def test_bare_domain_accepted(self):
        ok, _ = validate_url_payload("example.com")
        assert ok

    def test_wifi_payload_rejected(self):
        ok, msg = validate_url_payload("WIFI:T:WPA;S:network;P:pass;;")
        assert not ok

    def test_vcard_payload_rejected(self):
        ok, msg = validate_url_payload("BEGIN:VCARD\nFN:John\nEND:VCARD")
        assert not ok

    def test_empty_rejected(self):
        ok, _ = validate_url_payload("")
        assert not ok

    def test_none_rejected(self):
        ok, _ = validate_url_payload(None)
        assert not ok

    def test_ftp_rejected(self):
        ok, _ = validate_url_payload("ftp://example.com/file.txt")
        assert not ok

    def test_very_long_payload_rejected(self):
        ok, _ = validate_url_payload("https://example.com/" + "a" * 9000)
        assert not ok
