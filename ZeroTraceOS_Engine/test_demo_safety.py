#!/usr/bin/env python3
"""Static safety check for the Phase 1 Demo/Sandbox path."""

from pathlib import Path

source = Path("app/engine.py").read_text()

start = source.index("def run_demo_operation")
end = source.index("\ndef run_demo_for_device", start)
demo_source = source[start:end]

for dangerous in ("subprocess.run", "nwipe", "hdparm", "nvme format"):
    assert dangerous not in demo_source, (
        f"Unsafe operation reference found in demo function: {dangerous}"
    )

assert "NO storage write or destructive command will be executed." in demo_source
print("PASS: Demo/Sandbox operation contains no destructive command execution.")
