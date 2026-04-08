import sys
import os
import pytest

# ── 1. Path Management ────────────────────────────────────────────────────────
# Ensures the script can find 'app' regardless of where it's executed from.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.engine.entropy    import dga_score
from app.engine.scorer     import analyse_url
from app.engine.reputation import is_allowlisted, is_blocklisted, is_highly_trusted
from app.utils.validators  import validate_url_payload

# ══════════════════════════════════════════════════════════════════════════════
# 🧪 PYTEST SUITES (For Automated Reports)
# ══════════════════════════════════════════════════════════════════════════════

class TestEntropy:
    def test_legitimate_domain_low_entropy(self):
        """Human-readable domains should have a low normalized ratio."""
        for d in ["paypal", "google", "amazon", "facebook", "apple"]:
            r = dga_score(d)
            assert not r.is_dga, f"{d} falsely flagged as DGA (ratio={r.normalized})"

    def test_dga_domain_high_entropy(self):
        """Randomized strings should hit high normalized ratios (near 1.0)."""
        r = dga_score("kzxwmqbvptjd")
        assert r.normalized > 0.85
        assert r.is_dga

class TestReputation:
    def test_tranco_reputation_killer(self):
        """Verify that Tranco Top 100k domains are recognized as highly trusted."""
        assert is_highly_trusted("google.com")
        assert is_highly_trusted("facebook.com")
        assert not is_highly_trusted("x7z9q2mwpb.ru")

    def test_known_spoof_blocklisted(self):
        assert is_blocklisted("https://xn--pple-43d.com/login")

class TestScorer:
    def test_all_8_checks_present(self):
        """Ensure the engine evaluates all 8 indicators defined in the report."""
        result = analyse_url("https://example.com")
        check_names = {c['name'] for c in result['checks']}
        expected = {
            "ip_literal", "punycode", "dga_entropy", "redirect_depth",
            "suspicious_tld", "subdomain_depth", "https_mismatch", "path_keywords"
        }
        assert expected.issubset(check_names)

    def test_reputation_score_reduction(self):
        """Trusted domains should have their heuristic score slashed."""
        result = analyse_url("http://google.com/verify-login-update")
        assert result['risk_score'] < 10 
        assert result['risk_label'] == "safe"

class TestValidator:
    def test_double_scheme_rejection(self):
        ok, _ = validate_url_payload("http://http://google.com")
        assert not ok

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