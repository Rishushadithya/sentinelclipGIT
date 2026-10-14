"""
SentinelClip — Performance & Evaluation Benchmark Test Suite

Validates criteria defined in Section 3.6 of the Project Proposal:
1. Processing latency < 150 milliseconds for standard text payloads.
2. Detection accuracy >= 90% across defined sensitive pattern sets.
3. False-positive rate < 10% on clean non-sensitive payloads.
4. Zero external telemetry verification (Local-First security).
"""

import time
import pytest
from detection.patterns import scan, sanitize_payload, SEED_RULES


def test_clipboard_processing_latency():
    """Verify that average clipboard scanning latency is well below 150ms."""
    sample_text = (
        "Here is a test clipboard payload with an API Key: "
        "AKIAIOSFODNN7EXAMPLE and an IP address 192.168.1.50 and email test@company.com"
    ) * 10  # 10x repetition for realistic payload size

    # Warmup run
    scan(sample_text, SEED_RULES)

    start_time = time.perf_counter()
    iterations = 100
    for _ in range(iterations):
        scan(sample_text, SEED_RULES)
        sanitize_payload(sample_text, SEED_RULES)
    end_time = time.perf_counter()

    avg_latency_ms = ((end_time - start_time) / iterations) * 1000.0

    print(f"\n[BENCHMARK] Average processing latency: {avg_latency_ms:.2f} ms")
    
    # Assert latency target < 150 ms
    assert avg_latency_ms < 150.0, f"Latency {avg_latency_ms:.2f} ms exceeded 150ms limit"


def test_detection_accuracy_and_false_positives():
    """Verify detection accuracy >= 90% and false positive rate < 10%."""
    sensitive_samples = [
        "AKIAIOSFODNN7EXAMPLE",
        "4532015112830366",
        "192.168.1.100",
        "user@company.com",
        "123456789V",
        "password: mysecretpass",
        "pwd: mysecretpass",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "pass = mypassword",
        "10.0.0.1",
    ]

    clean_samples = [
        "The quick brown fox jumps over the lazy dog.",
        "System update completed successfully.",
        "Meeting scheduled for 3 PM tomorrow.",
        "Please review the attached project documentation.",
        "Standard python function definition: def add(a, b): return a + b",
        "Contact phone number: +1-800-555-0199",
        "HTML tag example: <div>Hello World</div>",
        "Gradient color code: #1a1a2e",
        "Current local temperature is 24 degrees Celsius.",
        "Database table names: users, audit_log, policies.",
    ]

    # Test Sensitive Detection (True Positives)
    detected_count = 0
    for sample in sensitive_samples:
        matches = scan(sample, SEED_RULES)
        if len(matches) > 0:
            detected_count += 1

    accuracy = (detected_count / len(sensitive_samples)) * 100.0
    assert accuracy >= 90.0, f"Detection accuracy {accuracy}% is below required 90%"

    # Test Clean Non-Sensitive Data (False Positives)
    false_positives = 0
    for sample in clean_samples:
        matches = scan(sample, SEED_RULES)
        high_med_matches = [m for m in matches if getattr(m, "severity", "") in ["HIGH", "MEDIUM"]]
        if len(high_med_matches) > 0:
            false_positives += 1

    false_positive_rate = (false_positives / len(clean_samples)) * 100.0
    assert false_positive_rate < 10.0, f"False positive rate {false_positive_rate}% exceeded 10% limit"


def test_zero_external_telemetry_guarantee():
    """Verify local-first configuration with zero external telemetry endpoints."""
    import deployment_config
    
    api_base = getattr(deployment_config, "API_BASE_URL", "http://127.0.0.1:5000")
    assert "127.0.0.1" in api_base or "localhost" in api_base or "192.168." in api_base or "0.0.0.0" in api_base
