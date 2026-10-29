#!/usr/bin/env python3
"""Quick regression test for the ZeroTrace mock scoring profiles."""

import subprocess
import sys
import re

SCENARIOS = [
    "hdd-healthy",
    "hdd-worn",
    "hdd-failed",
    "sata-healthy",
    "sata-worn",
    "nvme-healthy",
    "nvme-worn",
    "nvme-critical",
]

def get_score(scenario: str) -> int:
    result = subprocess.run(
        [sys.executable, "app/engine.py", "mock", scenario],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr)
        raise SystemExit(result.returncode)

    match = re.search(r"Reusability\s+:\s+(\d+)%", result.stdout)
    if not match:
        raise RuntimeError(f"No numeric score found for {scenario}")
    return int(match.group(1))

scores = {scenario: get_score(scenario) for scenario in SCENARIOS}

print("ZeroTrace mock score regression test")
for scenario, score in scores.items():
    print(f"{scenario:16} -> {score}%")

assert scores["hdd-healthy"] > scores["hdd-worn"] > scores["hdd-failed"]
assert scores["sata-healthy"] > scores["sata-worn"]
assert scores["nvme-healthy"] > scores["nvme-worn"] > scores["nvme-critical"]

print("\nPASS: scoring order behaves as expected.")
