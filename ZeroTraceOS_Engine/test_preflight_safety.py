#!/usr/bin/env python3
"""Static regression checks for the read-only pre-execution safety gate."""

from pathlib import Path

source = Path("app/engine.py").read_text()

required = [
    "def device_identity_fingerprint",
    "def validate_preflight_safety",
    "def print_preflight",
    '"preflight"',
    "Re-checking target identity immediately before execution",
    "refreshed_fingerprint != original_fingerprint",
    "validate_preflight_safety(refreshed)",
]

for item in required:
    assert item in source, f"Missing preflight safety feature: {item}"

print("PASS: pre-execution safety gate and identity re-check are present.")
print("NOTE: this test does NOT execute a sanitization command.")
