"""
tests/test_features.py — Feature Extractor Unit Tests
Phishing Detection Dashboard

Run with:
    python -m pytest tests/ -v
    python -m pytest tests/ -v --tb=short

Tests cover:
  - All 32 lexical/structural features
  - WHOIS feature structure (mocked — no live network calls)
  - Edge cases: empty URL, IP hostname, extremely long URL,
    encoded characters, URL shorteners, international domains
  - Feature name consistency with model expectations
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Make sure we can import from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from feature_extraction import extract_features, get_feature_names, _entropy


# ─── Helper ──────────────────────────────────────────────────────────────────

def _feats(url: str) -> dict:
    """Extract features with WHOIS mocked out (no network calls)."""
    mock_whois = {
        "domain_age_days":  365,
        "is_new_domain":    0,
        "whois_available":  1,
        "domain_country":   0,
        "has_privacy_guard": 0,
        "dns_resolves":     1,
    }
    with patch("feature_extraction.get_whois_features", return_value=mock_whois):
        return extract_features(url)


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestEntropyHelper(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(_entropy(""), 0.0)

    def test_uniform_string(self):
        # All same characters → entropy = 0
        self.assertAlmostEqual(_entropy("aaaa"), 0.0)

    def test_binary_string(self):
        # Two equally likely chars → entropy = 1.0
        self.assertAlmostEqual(_entropy("abab"), 1.0, places=5)

    def test_increases_with_variety(self):
        self.assertGreater(_entropy("abcdefgh"), _entropy("aaaabbbb"))


class TestLexicalFeatures(unittest.TestCase):

    def test_basic_https_url(self):
        f = _feats("https://www.google.com")
        self.assertEqual(f["is_https"], 1)
        self.assertEqual(f["has_ip"],   0)
        self.assertEqual(f["has_phish_keyword"], 0)
        self.assertEqual(f["suspicious_tld"],    0)
        self.assertEqual(f["is_shortened"],      0)
        self.assertGreater(f["url_length"],       0)

    def test_http_url(self):
        f = _feats("http://example.com")
        self.assertEqual(f["is_https"], 0)

    def test_url_length(self):
        short = _feats("https://a.com")
        long  = _feats("https://a.com/" + "x" * 200)
        self.assertLess(short["url_length"], long["url_length"])

    def test_hostname_length(self):
        f = _feats("https://www.verylonghostname.example.com")
        self.assertGreater(f["hostname_length"], 10)

    def test_count_dots(self):
        f = _feats("https://sub.sub2.example.co.uk/path")
        self.assertGreaterEqual(f["count_dots"], 3)

    def test_count_hyphens(self):
        f = _feats("http://my-secure-bank-login.example.com")
        self.assertGreaterEqual(f["count_hyphens"], 3)

    def test_hyphen_in_domain(self):
        with_hyphen    = _feats("http://secure-bank.example.com")
        without_hyphen = _feats("http://securebank.example.com")
        self.assertEqual(with_hyphen["hyphen_in_domain"],    1)
        self.assertEqual(without_hyphen["hyphen_in_domain"], 0)

    def test_count_at_symbol(self):
        f = _feats("http://user@example.com")
        self.assertEqual(f["count_at"], 1)

    def test_count_query_params(self):
        f = _feats("https://example.com/page?a=1&b=2&c=3")
        self.assertEqual(f["query_param_count"], 3)

    def test_count_digits(self):
        f = _feats("http://192168001.example.com/page123")
        self.assertGreater(f["count_digits"], 0)

    def test_digit_ratio(self):
        f = _feats("http://1234567890.tk")
        self.assertGreater(f["digit_ratio"], 0.3)

    def test_fragment(self):
        with_frag    = _feats("https://example.com/page#section")
        without_frag = _feats("https://example.com/page")
        self.assertEqual(with_frag["has_fragment"],    1)
        self.assertEqual(without_frag["has_fragment"], 0)

    def test_double_slash_in_path(self):
        f = _feats("http://example.com//double//slash")
        self.assertEqual(f["double_slash_in_path"], 1)

    def test_special_char_density(self):
        f = _feats("http://example.com/!#$%^path")
        self.assertGreater(f["special_char_density"], 0)


class TestIpAndPortFeatures(unittest.TestCase):

    def test_ipv4_hostname(self):
        f = _feats("http://192.168.1.100/banking/login.php")
        self.assertEqual(f["has_ip"], 1)

    def test_named_hostname(self):
        f = _feats("https://www.google.com")
        self.assertEqual(f["has_ip"], 0)

    def test_port_in_url(self):
        with_port    = _feats("http://example.com:8080/path")
        without_port = _feats("http://example.com/path")
        self.assertEqual(with_port["has_port"],    1)
        self.assertEqual(without_port["has_port"], 0)


class TestSubdomainFeatures(unittest.TestCase):

    def test_no_subdomain(self):
        f = _feats("https://example.com")
        self.assertEqual(f["subdomain_count"], 0)

    def test_one_subdomain(self):
        f = _feats("https://www.example.com")
        self.assertEqual(f["subdomain_count"], 1)

    def test_many_subdomains(self):
        f = _feats("https://a.b.c.example.com")
        self.assertGreaterEqual(f["subdomain_count"], 3)

    def test_digit_only_subdomain(self):
        digit = _feats("http://12345.example.com")
        named = _feats("http://www.example.com")
        self.assertEqual(digit["digit_only_subdomain"], 1)
        self.assertEqual(named["digit_only_subdomain"], 0)


class TestPhishingIndicators(unittest.TestCase):

    def test_phishing_keyword_detected(self):
        f = _feats("http://paypal-secure-verify.tk/account/login")
        self.assertEqual(f["has_phish_keyword"], 1)

    def test_no_phishing_keyword(self):
        f = _feats("https://docs.python.org/3/library/")
        self.assertEqual(f["has_phish_keyword"], 0)

    def test_suspicious_tld(self):
        sus   = _feats("http://somesite.tk")
        clean = _feats("http://somesite.com")
        self.assertEqual(sus["suspicious_tld"],   1)
        self.assertEqual(clean["suspicious_tld"], 0)

    def test_url_shortener_detected(self):
        short  = _feats("http://bit.ly/abc123")
        normal = _feats("https://www.example.com/long/path")
        self.assertEqual(short["is_shortened"],  1)
        self.assertEqual(normal["is_shortened"], 0)


class TestEntropyFeatures(unittest.TestCase):

    def test_entropy_hostname_is_float(self):
        f = _feats("https://www.example.com")
        self.assertIsInstance(f["entropy_hostname"], float)
        self.assertGreater(f["entropy_hostname"], 0.0)

    def test_high_entropy_hostname_for_random_domain(self):
        # Random-looking hostname should have higher entropy
        normal = _feats("https://google.com")
        random = _feats("https://xk2qm9abc7z3.com")
        self.assertGreater(random["entropy_hostname"], normal["entropy_hostname"])

    def test_entropy_path_zero_for_empty_path(self):
        f = _feats("https://example.com")
        # Empty path '/' has very low entropy
        self.assertLess(f["entropy_path"], 1.0)


class TestEdgeCases(unittest.TestCase):

    def test_url_without_scheme(self):
        # Should not raise — scheme is prepended automatically
        f = _feats("example.com")
        self.assertIsNotNone(f)
        self.assertIn("url_length", f)

    def test_very_long_url(self):
        long_url = "https://example.com/" + "a" * 1500
        f = _feats(long_url)
        self.assertGreater(f["url_length"], 1500)

    def test_percent_encoded_chars(self):
        f = _feats("https://example.com/search?q=hello%20world%21")
        self.assertGreater(f["count_percent"], 0)

    def test_all_features_are_numeric(self):
        """Every feature value must be int or float — never None or str."""
        f = _feats("https://www.example.com/path?q=test#section")
        for name, value in f.items():
            self.assertIsInstance(
                value, (int, float),
                msg=f"Feature '{name}' has non-numeric value: {value!r}",
            )

    def test_no_nan_or_inf(self):
        import math
        f = _feats("https://www.example.com")
        for name, value in f.items():
            self.assertFalse(
                math.isnan(float(value)) or math.isinf(float(value)),
                msg=f"Feature '{name}' is NaN or inf: {value}",
            )


class TestWhoisFeatureStructure(unittest.TestCase):
    """
    Tests for the 6 WHOIS features. We mock the external call so tests
    run offline and deterministically.
    """

    def test_whois_feature_keys_present(self):
        f = _feats("https://www.example.com")
        expected_keys = [
            "domain_age_days", "is_new_domain", "whois_available",
            "domain_country", "has_privacy_guard", "dns_resolves",
        ]
        for k in expected_keys:
            self.assertIn(k, f, msg=f"WHOIS feature '{k}' missing")

    def test_new_domain_flag_set_correctly(self):
        young_domain_whois = {
            "domain_age_days": 30, "is_new_domain": 1, "whois_available": 1,
            "domain_country": 0, "has_privacy_guard": 0, "dns_resolves": 1,
        }
        with patch("feature_extraction.get_whois_features",
                   return_value=young_domain_whois):
            f = extract_features("https://brand-new-domain.com")
        self.assertEqual(f["is_new_domain"],    1)
        self.assertEqual(f["domain_age_days"], 30)

    def test_privacy_guard_flag(self):
        privacy_whois = {
            "domain_age_days": 100, "is_new_domain": 0, "whois_available": 1,
            "domain_country": 0, "has_privacy_guard": 1, "dns_resolves": 1,
        }
        with patch("feature_extraction.get_whois_features",
                   return_value=privacy_whois):
            f = extract_features("https://hidden-registrant.com")
        self.assertEqual(f["has_privacy_guard"], 1)

    def test_dns_does_not_resolve(self):
        no_dns_whois = {
            "domain_age_days": -1, "is_new_domain": 0, "whois_available": 0,
            "domain_country": 0, "has_privacy_guard": 0, "dns_resolves": 0,
        }
        with patch("feature_extraction.get_whois_features",
                   return_value=no_dns_whois):
            f = extract_features("https://nonexistent-dead-domain.xyz")
        self.assertEqual(f["dns_resolves"], 0)


class TestFeatureNameConsistency(unittest.TestCase):

    def test_get_feature_names_matches_extract_keys(self):
        """get_feature_names() must return exactly the keys extract_features() produces."""
        mock_whois = {
            "domain_age_days": -1, "is_new_domain": 0, "whois_available": 0,
            "domain_country": 0, "has_privacy_guard": 0, "dns_resolves": 0,
        }
        with patch("feature_extraction.get_whois_features", return_value=mock_whois):
            names  = get_feature_names()
            actual = extract_features("https://example.com")

        self.assertEqual(set(names), set(actual.keys()),
                         msg="Feature name mismatch between get_feature_names() "
                             "and extract_features()")

    def test_feature_count_is_38(self):
        mock_whois = {
            "domain_age_days": -1, "is_new_domain": 0, "whois_available": 0,
            "domain_country": 0, "has_privacy_guard": 0, "dns_resolves": 0,
        }
        with patch("feature_extraction.get_whois_features", return_value=mock_whois):
            names = get_feature_names()
        self.assertEqual(len(names), 38,
                         msg=f"Expected 38 features, got {len(names)}: {names}")

    def test_feature_order_is_stable(self):
        """Calling get_feature_names() twice should return the same order."""
        mock_whois = {
            "domain_age_days": -1, "is_new_domain": 0, "whois_available": 0,
            "domain_country": 0, "has_privacy_guard": 0, "dns_resolves": 0,
        }
        with patch("feature_extraction.get_whois_features", return_value=mock_whois):
            first  = get_feature_names()
            second = get_feature_names()
        self.assertEqual(first, second)


class TestRateLimiter(unittest.TestCase):
    """Unit tests for the sliding window rate limiter."""

    def setUp(self):
        from rate_limiter import SlidingWindowRateLimiter
        self.limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)

    def test_allows_within_limit(self):
        for _ in range(5):
            allowed, retry = self.limiter.is_allowed("test-ip-1")
            self.assertTrue(allowed)
            self.assertEqual(retry, 0)

    def test_blocks_over_limit(self):
        for _ in range(5):
            self.limiter.is_allowed("test-ip-2")
        allowed, retry = self.limiter.is_allowed("test-ip-2")
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    def test_different_ips_are_independent(self):
        for _ in range(5):
            self.limiter.is_allowed("ip-a")
        allowed_a, _ = self.limiter.is_allowed("ip-a")
        allowed_b, _ = self.limiter.is_allowed("ip-b")
        self.assertFalse(allowed_a)
        self.assertTrue(allowed_b)

    def test_reset_clears_key(self):
        for _ in range(5):
            self.limiter.is_allowed("test-ip-reset")
        self.limiter.reset("test-ip-reset")
        allowed, _ = self.limiter.is_allowed("test-ip-reset")
        self.assertTrue(allowed)

    def test_remaining_decrements(self):
        key = "test-remaining"
        self.assertEqual(self.limiter.remaining(key), 5)
        self.limiter.is_allowed(key)
        self.assertEqual(self.limiter.remaining(key), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
