"""
SentinelClip — Clipboard Detector

Thin wrapper around the shared detection engine that fetches policy rules
from the Flask API and caches them with a TTL to avoid per-event HTTP calls.
"""

import time
import logging
import os
import requests
from detection.patterns import PolicyRule, Detection, scan, rules_from_dicts
from clipboard_engine.device_credentials import get_device_token

logger = logging.getLogger("sentinelclip.detector")

API_BASE = os.getenv("SENTINELCLIP_API_BASE", "http://127.0.0.1:5000/api/v1")
CACHE_TTL_SECONDS = 30  # Refresh rules from API every 30 seconds


class PolicyCache:
    """
    Caches policy rules fetched from the Flask API with a TTL.
    Falls back to an empty rule set if the API is unreachable.
    """

    def __init__(self, api_base: str = API_BASE, ttl: int = CACHE_TTL_SECONDS):
        self.api_base = api_base
        self.ttl = ttl
        self._rules: list[PolicyRule] = []
        self._last_fetch: float = 0
        self._api_reachable: bool = False

    def get_rules(self) -> list[PolicyRule]:
        """Get cached rules, refreshing from API if TTL expired."""
        now = time.time()
        if now - self._last_fetch > self.ttl:
            self._refresh()
        return self._rules

    def is_api_reachable(self) -> bool:
        """Check if the Flask API was reachable on last fetch."""
        return self._api_reachable

    def _refresh(self):
        """Fetch rules from the Flask API."""
        try:
            device_token = get_device_token(self.api_base)
            if not device_token:
                self._api_reachable = False
                logger.warning("No enrolled device credentials available")
                return
            resp = requests.get(
                f"{self.api_base}/policy",
                headers={"Authorization": f"Bearer {device_token}"},
                timeout=2,
            )
            resp.raise_for_status()
            data = resp.json()
            self._rules = rules_from_dicts(data.get("rules", []))
            self._api_reachable = True
            self._last_fetch = time.time()
            logger.debug(f"Refreshed {len(self._rules)} policy rules from API")
        except requests.RequestException as e:
            self._api_reachable = False
            logger.warning(f"Could not fetch rules from API: {e}")
            # Keep using cached rules if available


def detect_sensitive_content(
    text: str,
    policy_cache: PolicyCache,
) -> list[Detection]:
    """
    Run detection against cached policy rules.
    
    Args:
        text: The text to scan.
        policy_cache: PolicyCache instance for rule retrieval.
        
    Returns:
        List of Detection objects.
    """
    rules = policy_cache.get_rules()
    if not rules:
        logger.warning("No policy rules available — skipping detection")
        return []
    return scan(text, rules)
