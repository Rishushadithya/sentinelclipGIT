"""
SentinelClip — Dashboard API Client

Wraps all calls to the Flask API hub.
Used by Streamlit dashboard pages — never touches SQLite directly.
"""

import requests
import pandas as pd
import os
from typing import Optional


class SentinelClipAPI:
    """Client for the SentinelClip Flask API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        admin_token: Optional[str] = None,
    ):
        self.base_url = base_url or os.getenv(
            "SENTINELCLIP_API_BASE", "http://127.0.0.1:5000/api/v1"
        )
        self.admin_token = admin_token

    def _headers(self, auth: bool = False) -> dict:
        headers = {"Content-Type": "application/json"}
        if auth and self.admin_token:
            headers["Authorization"] = f"Bearer {self.admin_token}"
        return headers

    # -------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------

    def health(self) -> dict:
        """Check API health."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=3)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            return {"status": "error", "message": str(e)}

    def is_healthy(self) -> bool:
        return self.health().get("status") == "ok"

    # -------------------------------------------------------------------
    # Admin auth
    # -------------------------------------------------------------------

    def login(self, username: str, password: str) -> dict:
        """Exchange credentials for the admin bearer token."""
        resp = requests.post(
            f"{self.base_url}/admin/login",
            json={"username": username, "password": password},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    def change_credentials(self, new_username: str, new_password: str) -> dict:
        """Update admin username/password — requires current admin token."""
        resp = requests.post(
            f"{self.base_url}/admin/credentials",
            json={"new_username": new_username, "new_password": new_password},
            headers=self._headers(auth=True),
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------------
    # Policy
    # -------------------------------------------------------------------

    def get_policies(self) -> list[dict]:
        """Get active policy rules."""
        resp = requests.get(f"{self.base_url}/policy", timeout=5)
        resp.raise_for_status()
        return resp.json().get("rules", [])

    def get_all_policies(self) -> list[dict]:
        """Get all policy rules (including disabled) — requires auth."""
        resp = requests.get(
            f"{self.base_url}/policy/all",
            headers=self._headers(auth=True),
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json().get("rules", [])

    def update_policy(self, rule_data: dict) -> dict:
        """Create or update a policy rule — requires auth."""
        resp = requests.post(
            f"{self.base_url}/policy/update",
            json=rule_data,
            headers=self._headers(auth=True),
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_policy(self, policy_id: int) -> dict:
        """Delete a policy rule — requires auth."""
        resp = requests.delete(
            f"{self.base_url}/policy/{policy_id}",
            headers=self._headers(auth=True),
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    def get_devices(self) -> list[dict]:
        """Get enrolled devices for the administrator dashboard."""
        resp = requests.get(
            f"{self.base_url}/devices",
            headers=self._headers(auth=True),
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json().get("devices", [])

    def get_enrollment_code(self) -> dict:
        """Get the current active agent enrollment code (or auto-generates if none active)."""
        resp = requests.get(
            f"{self.base_url}/devices/enrollment-code",
            headers=self._headers(auth=True),
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    def create_enrollment_code(self, expires_minutes: int = 1440) -> dict:
        """Manually rotate or create a new agent enrollment code."""
        resp = requests.post(
            f"{self.base_url}/devices/enrollment-codes",
            json={"expires_minutes": expires_minutes},
            headers=self._headers(auth=True),
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------------
    # Events
    # -------------------------------------------------------------------

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> dict:
        """Get paginated/filtered audit log events."""
        params = {"limit": limit, "offset": offset}
        if severity:
            params["severity"] = severity
        if source:
            params["source"] = source
        if date_from:
            params["from"] = date_from
        if date_to:
            params["to"] = date_to

        resp = requests.get(
            f"{self.base_url}/events",
            params=params,
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()

    def get_events_dataframe(self, **kwargs) -> pd.DataFrame:
        """Get events as a pandas DataFrame."""
        data = self.get_events(**kwargs)
        events = data.get("events", [])
        if not events:
            return pd.DataFrame()
        return pd.DataFrame(events)

    # -------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Get dashboard summary statistics."""
        resp = requests.get(f"{self.base_url}/stats", timeout=5)
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------------
    # Audit
    # -------------------------------------------------------------------

    def verify_audit(self) -> dict:
        """Verify audit log chain integrity."""
        resp = requests.get(f"{self.base_url}/audit/verify", timeout=30)
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------------
    # Export
    # -------------------------------------------------------------------

    def export_events_csv(self, **kwargs) -> str:
        """Export events as CSV string."""
        df = self.get_events_dataframe(**kwargs)
        if df.empty:
            return ""
        return df.to_csv(index=False)
