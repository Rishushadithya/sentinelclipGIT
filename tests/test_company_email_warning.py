"""Tests for company email warning detection in clipboard engine."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import clipboard_engine.main as main_module
from detection.patterns import SEED_RULES
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


def test_company_warning_is_shown_with_other_sanitization(monkeypatch):
    """Company warnings must not be skipped when another rule changes text."""
    engine = SentinelClipEngine()

    class FakePolicyCache:
        def get_rules(self):
            return SEED_RULES

        def is_api_reachable(self):
            return False

    notifications = []
    monkeypatch.setattr(engine, "policy_cache", FakePolicyCache())
    monkeypatch.setattr(main_module.pyperclip, "copy", lambda text: None)
    monkeypatch.setattr(
        main_module,
        "show_warning_notification",
        lambda title, message: notifications.append((title, message)),
    )

    engine.handle_clipboard_change(
        'password = "Secret123!"; send to employee@company.com'
    )

    assert len(notifications) == 1
    assert "Company Email Copied" in notifications[0][0]
    assert "company.com" in notifications[0][1]
