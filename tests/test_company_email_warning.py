"""Tests for company email warning detection in clipboard engine."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from clipboard_engine.main import SentinelClipEngine


def test_detects_company_hint_domain():
    engine = SentinelClipEngine()
    domains = engine._find_company_email_domains("Contact: jane@company.com")
    assert "company.com" in domains


def test_detects_configured_company_domain():
    os.environ["SENTINELCLIP_COMPANY_DOMAINS"] = "acme.io"
    try:
        engine = SentinelClipEngine()
        domains = engine._find_company_email_domains("Email team@eng.acme.io now")
        assert "eng.acme.io" in domains
    finally:
        del os.environ["SENTINELCLIP_COMPANY_DOMAINS"]


def test_ignores_non_company_email_domain():
    engine = SentinelClipEngine()
    domains = engine._find_company_email_domains("Public mail: user@gmail.com")
    assert domains == set()
