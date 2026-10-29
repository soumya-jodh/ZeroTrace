#!/usr/bin/env python3
"""Static checks for the real executor safety gates."""

from pathlib import Path

source = Path("app/engine.py").read_text()

assert "shell=False" in source
assert "require_root()" in source
assert "device.protected" in source
assert "device.mountpoints" in source
assert "confirm_device" in source
assert "i-understand-this-is-destructive" in source
assert 'device.device_type == "NVMe SSD"' in source
assert "_run_ata_security_erase" in source
assert "security-set-pass" in source
assert "security-erase" in source
assert "security-disable" in source
assert "_nvme_sanitize_log" in source

print("PASS: real executor contains the expected safety gates.")
print("NOTE: this test does NOT execute a sanitization command.")
