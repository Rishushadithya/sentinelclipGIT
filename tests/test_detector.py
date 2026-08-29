"""
SentinelClip — Detection Engine Unit Tests

Tests the detection/patterns.py scan() function and seed rules against
known positive and negative inputs. Target: ≥ 90% detection accuracy.

ALL test values are FAKE / clearly synthetic — see tests/fixtures/.
"""

import sys
import os
import pytest

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.patterns import PolicyRule, Detection, scan, SEED_RULES, rules_from_dicts
from clipboard_engine.sanitizer import sanitize_payload


# ---------------------------------------------------------------------------
# Helper: scan with seed rules
# ---------------------------------------------------------------------------

def scan_with_seeds(text: str) -> list[Detection]:
    """Scan text using all seed rules."""
    return scan(text, SEED_RULES)


def rule_names(detections: list[Detection]) -> set[str]:
    """Extract unique rule names from a list of detections."""
    return {d.rule_name for d in detections}


# ===========================================================================
# AWS Access Key Tests
# ===========================================================================

class TestAWSAccessKey:
    def test_positive_standard(self):
        text = "My key is AKIAIOSFODNN7EXAMPLE"
        dets = scan_with_seeds(text)
        assert "AWS Access Key" in rule_names(dets)

    def test_positive_embedded(self):
        text = "config: AKIAIOSFODNN7TESTKEY in production"
        dets = scan_with_seeds(text)
        assert "AWS Access Key" in rule_names(dets)

    def test_negative_too_short(self):
        text = "AKIA1234"
        dets = scan_with_seeds(text)
        assert "AWS Access Key" not in rule_names(dets)

    def test_negative_wrong_prefix(self):
        text = "ASIA1234567890ABCDEF"
        dets = scan_with_seeds(text)
        assert "AWS Access Key" not in rule_names(dets)


# ===========================================================================
# Generic API Key Tests
# ===========================================================================

class TestGenericAPIKey:
    def test_positive_equals(self):
        text = 'api_key = "sk_test_1234567890abcdef1234567890"'
        dets = scan_with_seeds(text)
        assert "Generic API Key" in rule_names(dets)

    def test_positive_colon(self):
        text = "API-KEY: abcdefghij1234567890klmnop"
        dets = scan_with_seeds(text)
        assert "Generic API Key" in rule_names(dets)

    def test_positive_case_insensitive(self):
        text = 'Api_Key="FAKE_KEY_FOR_TESTING_ONLY_1234"'
        dets = scan_with_seeds(text)
        assert "Generic API Key" in rule_names(dets)

    def test_negative_short_value(self):
        text = 'api_key = "short"'
        dets = scan_with_seeds(text)
        assert "Generic API Key" not in rule_names(dets)


# ===========================================================================
# Private IP Address Tests
# ===========================================================================

class TestPrivateIP:
    def test_positive_10_range(self):
        dets = scan_with_seeds("Server at 10.0.0.1")
        assert "Private IP Address" in rule_names(dets)

    def test_positive_192_range(self):
        dets = scan_with_seeds("Host: 192.168.1.100")
        assert "Private IP Address" in rule_names(dets)

    def test_positive_172_range(self):
        dets = scan_with_seeds("Internal: 172.16.0.50")
        assert "Private IP Address" in rule_names(dets)

    def test_positive_172_31(self):
        dets = scan_with_seeds("Address: 172.31.255.255")
        assert "Private IP Address" in rule_names(dets)

    def test_negative_public_ip(self):
        text = "Public: 8.8.8.8"
        dets = scan_with_seeds(text)
        assert "Private IP Address" not in rule_names(dets)

    def test_positive_public_ip(self):
        text = "Public endpoint: 8.8.8.8"
        dets = scan_with_seeds(text)
        assert "Public IP Address" in rule_names(dets)

    def test_negative_172_public(self):
        # 172.32.x.x is NOT private
        text = "Address: 172.32.0.1"
        dets = scan_with_seeds(text)
        assert "Private IP Address" not in rule_names(dets)


# ===========================================================================
# Email Address Tests
# ===========================================================================

class TestEmailAddress:
    def test_positive_standard(self):
        dets = scan_with_seeds("Contact: john.doe@example.com")
        assert "Email Address" in rule_names(dets)

    def test_positive_subdomain(self):
        dets = scan_with_seeds("Email: user@mail.company.co.uk")
        assert "Email Address" in rule_names(dets)

    def test_positive_plus(self):
        dets = scan_with_seeds("support+test@example.org")
        assert "Email Address" in rule_names(dets)

    def test_negative_no_domain(self):
        dets = scan_with_seeds("Not email: user@")
        assert "Email Address" not in rule_names(dets)

    def test_negative_no_user(self):
        dets = scan_with_seeds("Not email: @example.com")
        assert "Email Address" not in rule_names(dets)


# ===========================================================================
# NIC / National ID Tests
# ===========================================================================

class TestNIC:
    def test_positive_old_format_v(self):
        dets = scan_with_seeds("NIC: 199512345v")
        assert "NIC / National ID (LK)" in rule_names(dets)

    def test_positive_old_format_V(self):
        dets = scan_with_seeds("NIC: 882345678V")
        assert "NIC / National ID (LK)" in rule_names(dets)

    def test_positive_new_format(self):
        dets = scan_with_seeds("NIC: 200012345678")
        assert "NIC / National ID (LK)" in rule_names(dets)

    def test_negative_too_short(self):
        dets = scan_with_seeds("Number: 12345678")
        assert "NIC / National ID (LK)" not in rule_names(dets)


# ===========================================================================
# Credit Card Number Tests
# ===========================================================================

class TestCreditCard:
    def test_positive_spaces(self):
        dets = scan_with_seeds("Card: 4111 1111 1111 1111")
        assert "Credit Card Number" in rule_names(dets)

    def test_positive_dashes(self):
        dets = scan_with_seeds("Visa: 4242-4242-4242-4242")
        assert "Credit Card Number" in rule_names(dets)

    def test_negative_too_short(self):
        dets = scan_with_seeds("Number: 12345")
        assert "Credit Card Number" not in rule_names(dets)


# ===========================================================================
# JWT Token Tests
# ===========================================================================

class TestJWT:
    def test_positive_standard(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        dets = scan_with_seeds(f"Bearer {jwt}")
        assert "JWT Token" in rule_names(dets)

    def test_negative_partial(self):
        # Only one segment — not a valid JWT format
        dets = scan_with_seeds("eyJhbGciOiJIUzI1NiJ9")
        assert "JWT Token" not in rule_names(dets)


# ===========================================================================
# Password Assignment Tests
# ===========================================================================

class TestPassword:
    def test_positive_equals(self):
        dets = scan_with_seeds('password = "SuperSecret123!"')
        assert "Password Assignment" in rule_names(dets)

    def test_positive_colon(self):
        dets = scan_with_seeds("passwd: my_fake_password")
        assert "Password Assignment" in rule_names(dets)

    def test_positive_pwd(self):
        dets = scan_with_seeds("pwd='test_only_pwd_456'")
        assert "Password Assignment" in rule_names(dets)

    def test_positive_pass_alias(self):
        dets = scan_with_seeds("pass=my_packet_secret")
        assert "Password Assignment" in rule_names(dets)

    def test_positive_pw_alias(self):
        dets = scan_with_seeds('"pw":"raw_payload_pwd_2026"')
        assert "Password Assignment" in rule_names(dets)

    def test_positive_password_tag(self):
        dets = scan_with_seeds("<password>raw_tag_secret</password>")
        assert "Password Assignment" in rule_names(dets)

    def test_positive_passcode(self):
        dets = scan_with_seeds("passcode: 438912")
        assert "Password Assignment" in rule_names(dets)

    def test_positive_passphrase(self):
        dets = scan_with_seeds('passphrase="correct horse battery staple"')
        assert "Password Assignment" in rule_names(dets)

    def test_positive_db_password_tag(self):
        dets = scan_with_seeds("<db_password>mysql_root_secret</db_password>")
        assert "Password Assignment" in rule_names(dets)

    def test_negative_just_word(self):
        # "password" at end of sentence without an assignment operator or value
        dets = scan_with_seeds("Please remember to change your password")
        assert "Password Assignment" not in rule_names(dets)


# ===========================================================================
# Multi-match / benign text tests
# ===========================================================================

class TestMultiMatch:
    def test_multiple_rules_in_one_text(self):
        text = (
            "AWS: AKIAIOSFODNN7EXAMPLE\n"
            "Server: 192.168.1.1\n"
            "Email: user@test.com\n"
            "password = secret123"
        )
        dets = scan_with_seeds(text)
        names = rule_names(dets)
        assert "AWS Access Key" in names
        assert "Private IP Address" in names
        assert "Email Address" in names
        assert "Password Assignment" in names

    def test_benign_text_no_detections(self):
        text = "This is a normal paragraph about programming."
        dets = scan_with_seeds(text)
        # Filter out any spurious matches — we expect very few/none
        # Only high-confidence rules should match here
        high_severity = [d for d in dets if d.severity == "HIGH"]
        assert len(high_severity) == 0


# ===========================================================================
# Detection metadata tests
# ===========================================================================

class TestDetectionMetadata:
    def test_detection_has_no_raw_value(self):
        """Ensure Detection objects don't leak raw sensitive data."""
        text = "password = SuperSecret123!"
        dets = scan_with_seeds(text)
        for det in dets:
            # Detection should not have the matched text as an attribute
            assert not hasattr(det, "matched_text")
            assert not hasattr(det, "raw_value")
            assert not hasattr(det, "matched_string")
            # It should have position and length only
            assert hasattr(det, "match_start")
            assert hasattr(det, "match_end")
            assert hasattr(det, "matched_len")

    def test_detection_position_is_correct(self):
        text = "key is AKIAIOSFODNN7EXAMPLE here"
        dets = scan_with_seeds(text)
        aws_dets = [d for d in dets if d.rule_name == "AWS Access Key"]
        assert len(aws_dets) == 1
        det = aws_dets[0]
        assert text[det.match_start:det.match_end] == "AKIAIOSFODNN7EXAMPLE"
        assert det.matched_len == 20


# ===========================================================================
# rules_from_dicts tests
# ===========================================================================

class TestRulesFromDicts:
    def test_converts_correctly(self):
        dicts = [
            {
                "rule_name": "Test Rule",
                "pattern": "test_pattern",
                "pattern_type": "regex",
                "severity": "LOW",
                "action": "WARN",
            }
        ]
        rules = rules_from_dicts(dicts)
        assert len(rules) == 1
        assert rules[0].rule_name == "Test Rule"
        assert rules[0].enabled is True

    def test_preserves_optional_fields(self):
        dicts = [
            {
                "rule_name": "Obfuscation Rule",
                "pattern": "secret",
                "pattern_type": "keyword",
                "severity": "MEDIUM",
                "action": "OBFUSCATE",
                "replacement_value": "[HIDDEN]",
                "enabled": False,
            }
        ]
        rules = rules_from_dicts(dicts)
        assert rules[0].replacement_value == "[HIDDEN]"
        assert rules[0].enabled is False


# ===========================================================================
# Sanitizer tests
# ===========================================================================

class TestSanitizer:
    def test_redact_password(self):
        text = 'password = "SuperSecret123!"'
        sanitized, log = sanitize_payload(text, SEED_RULES)
        assert "[REDACTED]" in sanitized
        assert "SuperSecret123!" not in sanitized

    def test_obfuscate_ip(self):
        text = "Server at 192.168.1.100 is running"
        sanitized, log = sanitize_payload(text, SEED_RULES)
        assert "[PRIVATE_IP]" in sanitized
        assert "192.168.1.100" not in sanitized

    def test_block_aws_key(self):
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        sanitized, log = sanitize_payload(text, SEED_RULES)
        assert "[BLOCKED" in sanitized
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized

    def test_warn_email(self):
        text = "Email: user@example.com"
        sanitized, log = sanitize_payload(text, SEED_RULES)
        # WARN action should NOT modify the text
        assert "user@example.com" in sanitized
        warning_entries = [e for e in log if e.get("type") == "warning_required"]
        assert len(warning_entries) > 0

    def test_benign_text_unchanged(self):
        text = "This is a normal paragraph about programming."
        sanitized, log = sanitize_payload(text, SEED_RULES)
        assert sanitized == text

    def test_detection_log_has_metadata(self):
        text = "password = secret123"
        _, log = sanitize_payload(text, SEED_RULES)
        rule_entries = [e for e in log if "rule_name" in e]
        assert len(rule_entries) > 0
        for entry in rule_entries:
            assert "rule_name" in entry
            assert "severity" in entry
            assert "action" in entry


# ===========================================================================
# Fixture file tests
# ===========================================================================

class TestFixtureFiles:
    @pytest.fixture
    def sample_secrets_text(self):
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "sample_secrets.txt"
        )
        with open(fixture_path, "r") as f:
            return f.read()

    def test_fixture_detects_all_rule_types(self, sample_secrets_text):
        """The sample_secrets.txt fixture should trigger all seed rules."""
        dets = scan_with_seeds(sample_secrets_text)
        names = rule_names(dets)
        expected_rules = {
            "AWS Access Key",
            "Generic API Key",
            "Private IP Address",
            "Email Address",
            "NIC / National ID (LK)",
            "JWT Token",
            "Password Assignment",
        }
        for rule in expected_rules:
            assert rule in names, f"Expected rule '{rule}' not detected in fixture"

    def test_fixture_credit_card(self, sample_secrets_text):
        dets = scan_with_seeds(sample_secrets_text)
        names = rule_names(dets)
        assert "Credit Card Number" in names
