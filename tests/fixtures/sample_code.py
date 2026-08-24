# SentinelClip Test Fixture — Sample Python Code
# ALL VALUES ARE FAKE — for testing detection rules only.

import os

# Fake AWS credentials for testing
AWS_ACCESS_KEY = "AKIAIOSFODNN7FAKEKEY"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCFAKEKEY123"

# Fake API configuration
API_KEY = "sk_live_FAKE_1234567890abcdefghijklmnop"

# Database config with fake private IPs
DB_CONFIG = {
    "host": "192.168.1.200",
    "port": 5432,
    "user": "admin@internal-db.example.com",
    "password": "fake_database_password_2024",
}

# Fake JWT token for testing
AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.fake_signature"

def connect_to_database():
    """Connect using hardcoded credentials (intentionally bad practice for testing)."""
    pwd = "another_fake_password_123"
    return f"postgresql://{DB_CONFIG['user']}:{pwd}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/mydb"
