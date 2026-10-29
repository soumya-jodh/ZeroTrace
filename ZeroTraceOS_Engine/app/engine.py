#!/usr/bin/env python3
"""
ZeroTrace-OS - Core Storage Engine

Phase 1:
- Detect block devices using lsblk
- Classify HDD / SATA SSD / NVMe
- Read SMART information when available
- Calculate a preliminary Reusability Score
- Select a device-appropriate sanitization plan
- Provide safe dry-run output

IMPORTANT:
This engine is intentionally conservative.
Destructive sanitization is NOT exposed by the default CLI.
The first implementation is for detection, assessment, planning and
safe development/testing. The actual destructive executor should be
added only after device-specific validation and a separate safety layer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    from .capabilities import detect_capabilities
    from .certificate import generate_certificate, verify_certificate
except ImportError:
    from capabilities import detect_capabilities
    from certificate import generate_certificate, verify_certificate


# ---------------------------------------------------------------------------
# Safety configuration
# ---------------------------------------------------------------------------

# Devices whose names commonly represent virtual/live/system devices.
# This is NOT a replacement for checking the actual mountpoints.
PROTECTED_DEVICE_NAMES = {
    "/dev/sda",
}

# Filesystems/mountpoints that should never be considered wipe targets.
PROTECTED_MOUNTPOINTS = {
    "/",
    "/boot",
    "/boot/efi",
    "/target",
    "/cdrom",
    "/run",
    "/proc",
    "/sys",
    "/dev",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Device:
    name: str
    path: str
    size_bytes: int
    size_human: str
    device_type: str
    model: str = ""
    serial: str = ""
    transport: str = ""
    rotational: bool | None = None
    mountpoints: list[str] = field(default_factory=list)
    filesystem: str = ""
    read_only: bool = False
    removable: bool = False
    root_disk: bool = False
    protected: bool = False
    protection_reason: str = ""
    smart_available: bool = False
    smart_health: str = "UNKNOWN"
    smart_attributes: dict[str, Any] = field(default_factory=dict)
    reusability_score: int | None = None
    score_reasons: list[str] = field(default_factory=list)
    sanitization_capabilities: dict[str, Any] = field(default_factory=dict)


@dataclass
class SanitizationPlan:
    device: str
    media_type: str
    method: str
    standard_category: str
    utility: str
    command_preview: list[str]
    notes: list[str] = field(default_factory=list)
    executable: bool = False


@dataclass
class DemoResult:
    device: str
    media_type: str
    method: str
    status: str
    verification: str
    started_at: str
    completed_at: str
    log: list[str] = field(default_factory=list)


@dataclass
class PostVerification:
    device_detected: bool
    device_path: str
    size_bytes: int
    size_matches: bool
    filesystem: str
    mountpoints: list[str]
    filesystem_absent: bool
    unmounted: bool
    first_mib_all_zero: bool | None
    wipefs_signatures_absent: bool | None = None
    blkid_identification_absent: bool | None = None
    raw_device_is_unrecognized_data: bool | None = None
    signature_check_details: dict[str, Any] = field(default_factory=dict)
    native_sanitization_verified: bool | None = None
    native_status_details: dict[str, Any] = field(default_factory=dict)
    verification_basis: list[str] = field(default_factory=list)
    status: str = "UNKNOWN"
    checked_at: str = ""


# ---------------------------------------------------------------------------
# Command helpers
# ---------------------------------------------------------------------------

def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(
    command: list[str],
    *,
    timeout: int = 15,
) -> subprocess.CompletedProcess[str]:
    """Run a read-only/system-information command."""
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def parse_int(value: str | None, default: int = 0) -> int:
    if value is None:
        return default
    value = value.strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def human_size(size: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024

    return f"{size} B"


# ---------------------------------------------------------------------------
# Device detection
# ---------------------------------------------------------------------------

def get_lsblk_devices() -> list[dict[str, Any]]:
    """
    Obtain block-device information in JSON form.

    lsblk is preferred over parsing human-readable output because JSON is
    much less fragile across Linux distributions.
    """
    if not command_exists("lsblk"):
        raise RuntimeError("lsblk was not found on this system.")

    result = run_command(
        [
            "lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,PATH,SIZE,TYPE,RO,RM,MODEL,SERIAL,"
            "TRAN,ROTA,MOUNTPOINTS,FSTYPE",
        ]
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"lsblk failed: {result.stderr.strip() or 'unknown error'}"
        )

    try:
        return json.loads(result.stdout).get("blockdevices", [])
    except json.JSONDecodeError as exc:
        raise RuntimeError("Could not parse lsblk JSON output.") from exc


def flatten_disks(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only whole-disk entries, excluding partitions and loop devices."""
    disks: list[dict[str, Any]] = []

    for entry in entries:
        if entry.get("type") == "disk":
            disks.append(entry)

    return disks


def normalize_mountpoints(value: Any) -> list[str]:
    if not value:
        return []

    if isinstance(value, list):
        return [str(v) for v in value if v]

    return [str(value)]


def is_root_device(path: str) -> bool:
    """
    Determine whether a block device backs the current root filesystem.

    Uses findmnt when available. Falls back to mount information.
    """
    if command_exists("findmnt"):
        result = run_command(
            ["findmnt", "-n", "-o", "SOURCE", "/"],
            timeout=5,
        )
        if result.returncode == 0:
            source = result.stdout.strip()

            # Root may be a partition such as /dev/sda2. Check the parent
            # disk using lsblk when possible.
            if source == path:
                return True

            if command_exists("lsblk"):
                parent = run_command(
                    ["lsblk", "-no", "PKNAME", source],
                    timeout=5,
                )
                if parent.returncode == 0:
                    parent_name = parent.stdout.strip()
                    return f"/dev/{parent_name}" == path

    return False


def detect_device(entry: dict[str, Any]) -> Device:
    path = entry.get("path") or f"/dev/{entry.get('name', '')}"

    rotational_value = entry.get("rota")
    rotational: bool | None
    if rotational_value is None:
        rotational = None
    else:
        rotational = bool(int(rotational_value))

    name = str(entry.get("name", ""))

    # NVMe namespaces normally appear as nvme0n1, nvme1n1, etc.
    if re.match(r"^nvme\d+n\d+$", name):
        device_type = "NVMe SSD"
    elif rotational is True:
        device_type = "HDD"
    elif rotational is False:
        device_type = "SATA/Other SSD"
    else:
        device_type = "Unknown"

    mountpoints = normalize_mountpoints(entry.get("mountpoints"))
    root_disk = is_root_device(path)

    protected_reasons: list[str] = []

    if path in PROTECTED_DEVICE_NAMES:
        protected_reasons.append("explicitly protected system/VM disk")

    if root_disk:
        protected_reasons.append("backs the running root filesystem")

    if any(mp in PROTECTED_MOUNTPOINTS for mp in mountpoints):
        protected_reasons.append("contains a protected mountpoint")

    # A read-only disk is not a useful destructive target.
    if bool(entry.get("ro")):
        protected_reasons.append("device is read-only")

    protected = bool(protected_reasons)

    return Device(
        name=name,
        path=path,
        size_bytes=parse_int(str(entry.get("size", "0"))),
        size_human=human_size(parse_int(str(entry.get("size", "0")))),
        device_type=device_type,
        model=str(entry.get("model") or "").strip(),
        serial=str(entry.get("serial") or "").strip(),
        transport=str(entry.get("tran") or "").strip(),
        rotational=rotational,
        mountpoints=mountpoints,
        filesystem=str(entry.get("fstype") or ""),
        read_only=bool(entry.get("ro")),
        removable=bool(entry.get("rm")),
        root_disk=root_disk,
        protected=protected,
        protection_reason="; ".join(protected_reasons),
    )


def detect_devices() -> list[Device]:
    entries = get_lsblk_devices()
    disks = flatten_disks(entries)
    return [detect_device(entry) for entry in disks]


# ---------------------------------------------------------------------------
# Mock SMART data for safe development/testing
# ---------------------------------------------------------------------------

MOCK_SMART_SCENARIOS: dict[str, dict[str, Any]] = {
    "hdd-healthy": {
        "device_type": "HDD",
        "smart_available": True,
        "smart_health": "PASSED",
        "smart_attributes": {
            "temperature": 35,
            "power_on_hours": 1200,
            "reallocated_sectors": 0,
            "current_pending_sectors": 0,
            "offline_uncorrectable": 0,
        },
    },
    "hdd-worn": {
        "device_type": "HDD",
        "smart_available": True,
        "smart_health": "PASSED",
        "smart_attributes": {
            "temperature": 55,
            "power_on_hours": 9000,
            "reallocated_sectors": 8,
            "current_pending_sectors": 2,
            "offline_uncorrectable": 1,
        },
    },
    "hdd-failed": {
        "device_type": "HDD",
        "smart_available": True,
        "smart_health": "FAILED",
        "smart_attributes": {
            "temperature": 48,
            "power_on_hours": 15000,
            "reallocated_sectors": 20,
            "current_pending_sectors": 4,
            "offline_uncorrectable": 3,
        },
    },
    "sata-healthy": {
        "device_type": "SATA/Other SSD",
        "smart_available": True,
        "smart_health": "PASSED",
        "smart_attributes": {
            "temperature": 32,
            "power_on_hours": 1500,
            "percentage_used": 8,
            "media_errors": 0,
        },
    },
    "sata-worn": {
        "device_type": "SATA/Other SSD",
        "smart_available": True,
        "smart_health": "PASSED",
        "smart_attributes": {
            "temperature": 60,
            "power_on_hours": 8000,
            "percentage_used": 65,
            "media_errors": 4,
        },
    },
    "nvme-healthy": {
        "device_type": "NVMe SSD",
        "smart_available": True,
        "smart_health": "PASSED",
        "smart_attributes": {
            "temperature": 35,
            "power_on_hours": 900,
            "critical_warning": "0x00",
            "percentage_used": 5,
            "available_spare": 100,
            "available_spare_threshold": 10,
            "media_errors": 0,
        },
    },
    "nvme-worn": {
        "device_type": "NVMe SSD",
        "smart_available": True,
        "smart_health": "PASSED",
        "smart_attributes": {
            "temperature": 68,
            "power_on_hours": 7000,
            "critical_warning": "0x00",
            "percentage_used": 72,
            "available_spare": 8,
            "available_spare_threshold": 10,
            "media_errors": 3,
        },
    },
    "nvme-critical": {
        "device_type": "NVMe SSD",
        "smart_available": True,
        "smart_health": "FAILED",
        "smart_attributes": {
            "temperature": 78,
            "power_on_hours": 12000,
            "critical_warning": "0x01",
            "percentage_used": 95,
            "available_spare": 5,
            "available_spare_threshold": 10,
            "media_errors": 12,
        },
    },
}


def apply_mock_smart(device: Device, scenario: str) -> None:
    """Apply a predefined SMART profile without touching any real disk."""
    if scenario not in MOCK_SMART_SCENARIOS:
        available = ", ".join(sorted(MOCK_SMART_SCENARIOS))
        raise ValueError(
            f"Unknown mock scenario '{scenario}'. Available: {available}"
        )

    data = MOCK_SMART_SCENARIOS[scenario]

    # Use a synthetic device identity. No physical/virtual disk is opened.
    device.name = f"mock-{scenario}"
    device.path = f"MOCK://{scenario}"
    device.size_bytes = 1_000_000_000
    device.size_human = "1.0 GB (mock)"
    device.device_type = str(data["device_type"])
    device.model = "ZeroTrace Mock Device"
    device.serial = f"MOCK-{scenario.upper()}"
    device.transport = (
        "sata" if data["device_type"] != "NVMe SSD" else "nvme"
    )
    device.rotational = data["device_type"] == "HDD"
    device.mountpoints = []
    device.filesystem = ""
    device.read_only = False
    device.removable = False
    device.root_disk = False
    device.protected = False
    device.protection_reason = ""

    device.smart_available = bool(data["smart_available"])
    device.smart_health = str(data["smart_health"])
    device.smart_attributes = dict(data["smart_attributes"])


# ---------------------------------------------------------------------------
# SMART
# ---------------------------------------------------------------------------

SMART_PATTERNS = {
    # Common NVMe indicators
    "percentage_used": [
        r"Percentage Used:\s*(\d+)\s*%?",
        r"Percentage used:\s*(\d+)\s*%?",
    ],
    "available_spare": [
        r"Available Spare:\s*(\d+)\s*%?",
    ],
    "available_spare_threshold": [
        r"Available Spare Threshold:\s*(\d+)\s*%?",
    ],
    "media_errors": [
        r"Media and Data Integrity Errors:\s*(\d+)",
        r"Media Errors:\s*(\d+)",
    ],
    "critical_warning": [
        r"Critical Warning:\s*(0x[0-9a-fA-F]+|\d+)",
    ],
    # Common ATA/SATA indicators
    "temperature": [
        r"Temperature:\s*(\d+)",
        r"Current Drive Temperature:\s*(\d+)",
        r"Airflow_Temperature_Cel.*?(\d+)\s*$",
        r"Temperature_Celsius.*?(\d+)\s*$",
    ],
    "power_on_hours": [
        r"Power On Hours:\s*(\d+)",
        r"Power_On_Hours.*?(\d+)\s*$",
    ],
    "reallocated_sectors": [
        r"Reallocated_Sector_Ct.*?(\d+)\s*$",
        r"Reallocated_Event_Count.*?(\d+)\s*$",
    ],
    "reported_uncorrectable": [
        r"Reported_Uncorrect.*?(\d+)\s*$",
    ],
    "current_pending_sectors": [
        r"Current_Pending_Sector.*?(\d+)\s*$",
    ],
    "offline_uncorrectable": [
        r"Offline_Uncorrectable.*?(\d+)\s*$",
    ],
}


def extract_smart_value(text: str, patterns: list[str]) -> int | None:
    for pattern in patterns:
        for line in text.splitlines():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, IndexError):
                    continue
    return None


def collect_smart(device: Device) -> None:
    """
    Collect SMART information when the device exposes it.

    VirtualBox VDI disks commonly do not expose host SMART data to the guest.
    In that case we report SMART as unavailable rather than inventing values.
    """
    if not command_exists("smartctl"):
        device.smart_health = "UNAVAILABLE"
        device.smart_attributes = {}
        device.smart_available = False
        return

    # -H gives health, -A gives attributes. -x asks for all available SMART
    # information and is useful across ATA/SATA and NVMe where supported.
    result = run_command(
        ["smartctl", "-x", device.path],
        timeout=20,
    )

    text = (result.stdout or "") + "\n" + (result.stderr or "")

    if "SMART support is: Disabled" in text:
        device.smart_health = "DISABLED"
        device.smart_attributes = {}
        device.smart_available = False
        return

    upper = text.upper()

    if (
        "SMART OVERALL-HEALTH SELF-ASSESSMENT TEST RESULT: PASSED" in upper
        or "SMART HEALTH STATUS: OK" in upper
    ):
        device.smart_health = "PASSED"
    elif "SMART OVERALL-HEALTH SELF-ASSESSMENT TEST RESULT: FAILED" in upper:
        device.smart_health = "FAILED"
    elif "SMART HEALTH STATUS: FAILED" in upper:
        device.smart_health = "FAILED"
    else:
        # Some devices expose SMART attributes without the classic overall
        # health line.
        device.smart_health = "UNKNOWN"

    attributes: dict[str, Any] = {}

    for key, patterns in SMART_PATTERNS.items():
        value = extract_smart_value(text, patterns)
        if value is not None:
            attributes[key] = value

    device.smart_attributes = attributes

    # smartctl return code 0 is normal. Non-zero can still mean that useful
    # information was returned, so regard output containing SMART data as
    # available rather than treating every non-zero result as failure.
    smart_markers = (
        "SMART",
        "PERCENTAGE USED",
        "CRITICAL WARNING",
        "REMAINING LIFE",
        "AVAILABLE SPARE",
    )
    device.smart_available = any(marker in upper for marker in smart_markers)

    # VirtualBox commonly presents VDI disks as VBOX HARDDISK and does not
    # expose host SMART telemetry to the guest.
    if "VBOX HARDDISK" in upper and not attributes:
        device.smart_health = "UNAVAILABLE"
        device.smart_available = False


# ---------------------------------------------------------------------------
# Reusability score
# ---------------------------------------------------------------------------

def calculate_reusability_score(device: Device) -> int | None:
    """
    Calculate a transparent, preliminary 0-100 Reusability Score.

    This score is a project heuristic, not a manufacturer-independent health
    standard. SMART attributes vary between devices. The score is calculated
    only when usable SMART data is available.

    Scoring philosophy:
      Start at 100 and apply evidence-based penalties.

    HDD:
      - SMART failure: -60
      - Reallocated sectors: up to -25
      - Pending sectors: up to -30
      - Uncorrectable sectors: up to -30
      - High temperature (>=70 C): -10

    SATA/Other SSD:
      - SMART failure: -60
      - Wear indicators where exposed: percentage-used * 0.35
      - Media errors: up to -35
      - High temperature (>=70 C): -10

    NVMe:
      - Critical Warning != 0: -40
      - Percentage Used: up to -35
      - Available Spare below its threshold: -25
      - Media/Data Integrity Errors: up to -35
      - High temperature (>=70 C): -10

    Missing optional attributes are not penalized. If SMART itself is not
    available, the result is N/A rather than 100%.
    """
    if not device.smart_available:
        device.reusability_score = None
        device.score_reasons = [
            "SMART data is unavailable; a reliable health score cannot be calculated."
        ]
        return None

    score = 100
    reasons: list[str] = []
    attrs = device.smart_attributes

    # A failed overall SMART result is a strong warning for any media type.
    if device.smart_health == "FAILED":
        score -= 60
        reasons.append("SMART reports a failure")
    elif device.smart_health == "UNKNOWN":
        reasons.append(
            "SMART data is available, but no overall health result was detected"
        )

    if device.device_type == "HDD":
        reallocated = attrs.get("reallocated_sectors")
        pending = attrs.get("current_pending_sectors")
        uncorrectable = attrs.get("offline_uncorrectable")

        if isinstance(reallocated, int) and reallocated > 0:
            penalty = min(25, 5 + reallocated)
            score -= penalty
            reasons.append(
                f"{reallocated} reallocated sector(s): -{penalty} points"
            )

        if isinstance(pending, int) and pending > 0:
            penalty = min(30, 10 + pending * 2)
            score -= penalty
            reasons.append(
                f"{pending} pending sector(s): -{penalty} points"
            )

        if isinstance(uncorrectable, int) and uncorrectable > 0:
            penalty = min(30, 10 + uncorrectable * 2)
            score -= penalty
            reasons.append(
                f"{uncorrectable} uncorrectable sector(s): -{penalty} points"
            )

    elif device.device_type == "NVMe SSD":
        critical = attrs.get("critical_warning")
        if isinstance(critical, str):
            try:
                critical_value = int(critical, 0)
            except ValueError:
                critical_value = None
        elif isinstance(critical, int):
            critical_value = critical
        else:
            critical_value = None

        if critical_value is not None and critical_value != 0:
            score -= 40
            reasons.append("NVMe Critical Warning is non-zero: -40 points")

        percentage_used = attrs.get("percentage_used")
        if isinstance(percentage_used, int):
            percentage_used = max(0, min(100, percentage_used))
            penalty = round(percentage_used * 0.35)
            if penalty:
                score -= penalty
                reasons.append(
                    f"NVMe percentage used is {percentage_used}%: -{penalty} points"
                )
            else:
                reasons.append("NVMe percentage used is 0%: no wear penalty")

        spare = attrs.get("available_spare")
        spare_threshold = attrs.get("available_spare_threshold")
        if (
            isinstance(spare, int)
            and isinstance(spare_threshold, int)
            and spare < spare_threshold
        ):
            score -= 25
            reasons.append(
                f"Available spare ({spare}%) is below threshold "
                f"({spare_threshold}%): -25 points"
            )

        media_errors = attrs.get("media_errors")
        if isinstance(media_errors, int) and media_errors > 0:
            penalty = min(35, 10 + media_errors)
            score -= penalty
            reasons.append(
                f"{media_errors} media/data-integrity error(s): -{penalty} points"
            )

    else:
        # SATA/Other SSD or an unknown future media class.
        media_errors = attrs.get("media_errors")
        if isinstance(media_errors, int) and media_errors > 0:
            penalty = min(35, 10 + media_errors)
            score -= penalty
            reasons.append(
                f"{media_errors} media error(s): -{penalty} points"
            )

        percentage_used = attrs.get("percentage_used")
        if isinstance(percentage_used, int):
            percentage_used = max(0, min(100, percentage_used))
            penalty = round(percentage_used * 0.35)
            if penalty:
                score -= penalty
                reasons.append(
                    f"SSD percentage used is {percentage_used}%: -{penalty} points"
                )

    temperature = attrs.get("temperature")
    if isinstance(temperature, int) and temperature >= 70:
        score -= 10
        reasons.append(f"high reported temperature ({temperature}°C): -10 points")

    score = max(0, min(100, score))

    if not reasons:
        reasons.append("no penalizing SMART indicators were detected")

    device.reusability_score = score
    device.score_reasons = reasons
    return score


# ---------------------------------------------------------------------------
# Sanitization planning
# ---------------------------------------------------------------------------

def build_sanitization_plan(device: Device) -> SanitizationPlan:
    """Build a hardware-aware sanitization plan without executing it."""
    if device.protected:
        return SanitizationPlan(device.path, device.device_type, "BLOCKED", "N/A", "N/A", [],
                                ["Device is protected and cannot be selected as a target.", device.protection_reason], False)

    if device.device_type == "HDD":
        return SanitizationPlan(device.path, device.device_type, "Overwrite-based sanitization",
                                "NIST-approved/organizationally approved technique (HDD)", "nwipe",
                                ["nwipe", "--autonuke", "--nogui", "--method=zero", "--verify=last", device.path],
                                ["One-pass zero overwrite with tool verification is used for the tested HDD path."], True)

    if device.device_type in {"SATA/Other SSD", "NVMe SSD"}:
        caps = device.sanitization_capabilities
        recommended = caps.get("recommended_method")
        if device.device_type == "NVMe SSD":
            action = {"crypto-erase": "0x04", "block-erase": "0x02", "overwrite": "0x03"}.get(recommended or "")
            preview = ["nvme", "sanitize", device.path, f"--sanact={action or '<SUPPORTED_ACTION>'}", "--wait"]
            method = f"NVMe native {recommended}" if recommended else "NVMe native sanitize (unsupported/unverified)"
            notes = ["Capabilities are queried from the controller before execution."] + caps.get("blocked_reasons", [])
            return SanitizationPlan(device.path, device.device_type, method,
                                    "Hardware-native sanitization / validation required", "nvme-cli", preview,
                                    notes, bool(recommended and caps.get("capability_query_succeeded")))
        recommended = recommended or ""
        method = recommended.replace("-", " ").title() if recommended else "ATA native sanitization (unsupported/unverified)"
        return SanitizationPlan(device.path, device.device_type, method,
                                "Hardware-native sanitization / validation required", "hdparm",
                                ["hdparm", "--user-master", "u", "<generated-password>",
                                 "<security-erase-or-enhanced>", device.path],
                                ["ZeroTrace generates a one-time in-memory ATA security password, sets it, executes the selected native erase, and removes the password when the device reports that security remains enabled.",
                                 "The device must not report SECURITY FROZEN before execution."] + caps.get("blocked_reasons", []),
                                bool(recommended and caps.get("capability_query_succeeded")
                                     and not caps.get("raw_summary", {}).get("security_frozen")))

    return SanitizationPlan(device.path, device.device_type, "No automatic method", "Manual review", "N/A", [],
                            ["Unknown media type; automatic sanitization is blocked."], False)


# ---------------------------------------------------------------------------
# Real sanitization executor
# ---------------------------------------------------------------------------

def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError(
            "Real sanitization requires root privileges. "
            "Run the command with sudo."
        )


def is_whole_block_device(path: str) -> bool:
    try:
        return stat.S_ISBLK(os.stat(path).st_mode)
    except FileNotFoundError:
        return False
    except OSError:
        return False


def get_device_by_path(devices: list[Device], path: str) -> Device | None:
    requested = os.path.realpath(path)
    for device in devices:
        if os.path.realpath(device.path) == requested:
            return device
    return None


def device_identity_fingerprint(device: Device) -> str:
    """Create a stable identity fingerprint for a pre-execution safety gate.

    The fingerprint is based only on read-only device identity/metadata. It is
    not a security credential and is not used as proof that a wipe occurred.
    """
    identity = {
        "path": os.path.realpath(device.path),
        "size_bytes": device.size_bytes,
        "model": device.model.strip(),
        "serial": device.serial.strip(),
        "device_type": device.device_type,
        "transport": device.transport.strip().lower(),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_preflight_safety(device: Device) -> list[str]:
    """Return safety failures for a read-only pre-execution inspection."""
    failures: list[str] = []

    if not is_whole_block_device(device.path):
        failures.append("target is not a whole block device")

    if device.protected:
        failures.append(f"device is protected: {device.protection_reason}")

    if device.mountpoints:
        failures.append(
            "target has active mountpoints: " + ", ".join(device.mountpoints)
        )

    if device.read_only:
        failures.append("device is read-only")

    if device.device_type == "HDD" and not command_exists("nwipe"):
        failures.append("nwipe is not installed")

    if device.device_type == "NVMe SSD":
        caps = device.sanitization_capabilities or {}
        if not caps.get("capability_query_succeeded"):
            failures.append("NVMe capability query did not succeed")
        if not caps.get("recommended_method"):
            failures.append("No supported NVMe native sanitize action was discovered")

    if device.device_type == "SATA/Other SSD":
        caps = device.sanitization_capabilities or {}
        if not command_exists("hdparm"):
            failures.append("hdparm is not installed")
        if not caps.get("capability_query_succeeded"):
            failures.append("ATA capability query did not succeed")
        if not caps.get("recommended_method"):
            failures.append("No safe ATA Security Erase capability was discovered")
        if caps.get("raw_summary", {}).get("security_frozen"):
            failures.append("ATA security is frozen; ZeroTrace will not attempt to bypass the frozen state")

    return failures


def print_preflight(device: Device) -> None:
    """Print the complete read-only safety snapshot used before execution."""
    failures = validate_preflight_safety(device)
    fingerprint = device_identity_fingerprint(device)

    print("=" * 72)
    print("ZeroTrace-OS — PRE-EXECUTION SAFETY CHECK")
    print("=" * 72)
    print("This check is READ-ONLY. No data will be modified.")
    print()
    print(f"Target path       : {device.path}")
    print(f"Canonical path    : {os.path.realpath(device.path)}")
    print(f"Size              : {device.size_human} ({device.size_bytes} bytes)")
    print(f"Media type        : {device.device_type}")
    print(f"Transport         : {device.transport or 'Unknown'}")
    print(f"Model             : {device.model or 'Unavailable'}")
    print(f"Serial            : {device.serial or 'Unavailable'}")
    print(f"Mountpoints       : {', '.join(device.mountpoints) or 'None'}")
    print(f"Read-only         : {'YES' if device.read_only else 'NO'}")
    print(f"Root/system disk  : {'YES' if device.root_disk else 'NO'}")
    print(f"Protected         : {'YES' if device.protected else 'NO'}")
    print(f"Whole block disk  : {'YES' if is_whole_block_device(device.path) else 'NO'}")
    print(f"nwipe available   : {'YES' if command_exists('nwipe') else 'NO'}")
    print(f"Identity fingerprint: {fingerprint}")
    print()

    if failures:
        print("PRE-FLIGHT RESULT: BLOCKED")
        for failure in failures:
            print(f"  - {failure}")
    else:
        print("PRE-FLIGHT RESULT: PASS")
        print("The device currently satisfies the engine's HDD safety gates.")
    print("=" * 72)


def validate_real_execution_target(
    device: Device,
    *,
    confirm_device: str,
    confirm_model: str | None,
    confirm_serial: str | None,
    confirm_size: int | None,
) -> list[str]:
    """Final preflight for a destructive operation."""
    failures = validate_preflight_safety(device)

    if os.path.realpath(confirm_device) != os.path.realpath(device.path):
        failures.append("confirmation device does not exactly match target")

    if confirm_model is not None:
        if not device.model or confirm_model.strip() != device.model.strip():
            failures.append("confirmed model does not match detected model")

    if confirm_serial is not None:
        if not device.serial or confirm_serial.strip() != device.serial.strip():
            failures.append("confirmed serial does not match detected serial")

    if confirm_size is not None and confirm_size != device.size_bytes:
        failures.append("confirmed size does not match detected size")

    return failures


def build_real_command(device: Device) -> list[str]:
    """Return a safe command preview; SATA uses a runtime-generated password."""
    if device.device_type == "HDD":
        return ["nwipe", "--autonuke", "--nogui", "--method=zero", "--verify=last", device.path]

    if device.device_type == "NVMe SSD":
        method = device.sanitization_capabilities.get("recommended_method")
        action = {"crypto-erase": "0x04", "block-erase": "0x02", "overwrite": "0x03"}.get(method)
        if not action:
            raise ValueError("No verified NVMe sanitize action is available.")
        if not command_exists("nvme"):
            raise ValueError("nvme-cli is not installed.")
        return ["nvme", "sanitize", device.path, f"--sanact={action}", "--wait"]

    if device.device_type == "SATA/Other SSD":
        method = device.sanitization_capabilities.get("recommended_method")
        if method == "ata-enhanced-security-erase":
            erase_flag = "<security-erase-enhanced>"
        elif method == "ata-security-erase":
            erase_flag = "<security-erase>"
        else:
            raise ValueError("No verified ATA Security Erase action is available.")
        return ["hdparm", "--user-master", "u", "<generated-password>", erase_flag, device.path]

    raise ValueError("No supported destructive executor for this media type.")



def _generate_ata_password() -> str:
    """Generate a temporary printable ATA security password."""
    return secrets.token_hex(16)


def _run_destructive_step(command: list[str], *, label: str) -> tuple[int, list[str]]:
    """Run a destructive/native storage command without shell=True."""
    print(f"{label}:")
    print("  " + " ".join(command))
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False,
        )
        assert proc.stdout is not None
        lines: list[str] = []
        for line in proc.stdout:
            line = line.rstrip("\\n")
            lines.append(line)
            print(line, flush=True)
        return proc.wait(), lines
    except FileNotFoundError as exc:
        print(f"ERROR: command not found: {command[0]}")
        return 127, [str(exc)]
    except OSError as exc:
        print(f"ERROR: failed to start command: {exc}")
        return 126, [str(exc)]


def _run_ata_security_erase(device: Device) -> tuple[int, list[str], list[str]]:
    """Execute ATA Secure Erase using a one-time in-memory password."""
    caps = device.sanitization_capabilities or {}
    method = caps.get("recommended_method")
    if method == "ata-enhanced-security-erase":
        erase_option = "--security-erase-enhanced"
        label = "ATA Enhanced Security Erase"
    elif method == "ata-security-erase":
        erase_option = "--security-erase"
        label = "ATA Security Erase"
    else:
        return 2, ["No supported ATA Security Erase method was selected."], []

    if not command_exists("hdparm"):
        return 2, ["hdparm is not installed."], []

    password = _generate_ata_password()
    redacted = [
        "hdparm --user-master u --security-set-pass <generated-password> " + device.path,
        "hdparm --user-master u " + erase_option + " <generated-password> " + device.path,
    ]
    output: list[str] = []

    rc, lines = _run_destructive_step(
        ["hdparm", "--user-master", "u", "--security-set-pass", password, device.path],
        label="ATA security password setup",
    )
    output.extend(lines)
    if rc != 0:
        return rc, output, redacted[:1]

    # Confirm that the temporary security state was accepted.
    caps_after_set = detect_capabilities(device.path, device.device_type)
    if not caps_after_set.raw_summary.get("security_enabled"):
        cleanup_rc, cleanup_lines = _run_destructive_step(
            ["hdparm", "--user-master", "u", "--security-disable", password, device.path],
            label="ATA temporary-password cleanup",
        )
        output.extend(cleanup_lines)
        return 20 if cleanup_rc == 0 else cleanup_rc, output + [
            "ERROR: ATA security did not report ENABLED after password setup."
        ], redacted + [
            "hdparm --user-master u --security-disable <generated-password> " + device.path
        ]

    rc, lines = _run_destructive_step(
        ["hdparm", "--user-master", "u", erase_option, password, device.path],
        label=label,
    )
    output.extend(lines)

    # If the drive still reports SECURITY ENABLED, remove the temporary
    # password. The password is never written to the audit record.
    after = detect_capabilities(device.path, device.device_type)
    if after.raw_summary.get("security_enabled"):
        cleanup_rc, cleanup_lines = _run_destructive_step(
            ["hdparm", "--user-master", "u", "--security-disable", password, device.path],
            label="ATA temporary-password cleanup",
        )
        output.extend(cleanup_lines)
        redacted.append(
            "hdparm --user-master u --security-disable <generated-password> " + device.path
        )
        if rc == 0 and cleanup_rc != 0:
            return 21, output, redacted

    return rc, output, redacted


def _nvme_sanitize_log(device_path: str) -> tuple[bool | None, dict[str, Any], list[str]]:
    """Read NVMe Sanitize Log Page 0x81 and interpret SSTAT."""
    if not command_exists("nvme"):
        return None, {"error": "nvme-cli is not installed"}, []

    candidates = [
        ["nvme", "log", "sanitize", device_path],
        ["nvme", "sanitize-log", device_path],
    ]
    result = None
    used = None
    for command in candidates:
        try:
            p = run_command(command, timeout=20)
        except OSError:
            continue
        if p.returncode == 0:
            result, used = p, command
            break

    if result is None:
        return False, {"error": "NVMe sanitize log query failed", "commands": candidates}, []

    text = (result.stdout or "") + "\n" + (result.stderr or "")
    details: dict[str, Any] = {
        "command": used,
        "return_code": result.returncode,
        "raw_output": text.strip(),
    }

    prog = re.search(r"Sanitize Progress\s*\(SPROG\)\s*:\s*([0-9]+)", text, re.I)
    sstat = re.search(r"Sanitize Status\s*\(SSTAT\)\s*:\s*(0x[0-9a-fA-F]+|[0-9]+)", text, re.I)
    if prog:
        details["sprog"] = int(prog.group(1), 0)
    if sstat:
        value = int(sstat.group(1), 0)
        status_code = value & 0x7
        details["sstat"] = value
        details["sstat_status"] = status_code
        details["sstat_global_data_erased"] = bool(value & 0x100)
        details["sstat_media_verification_canceled"] = bool(value & 0x200)
        if status_code == 1:
            return True, details, [f"NVMe Sanitize Log reports successful completion (SSTAT={value:#x})."]
        if status_code == 2:
            return False, details, [f"NVMe Sanitize Log reports sanitization still in progress (SSTAT={value:#x})."]
        if status_code == 3:
            return False, details, [f"NVMe Sanitize Log reports the most recent sanitization failed (SSTAT={value:#x})."]
        if status_code == 4:
            return True, details, [f"NVMe Sanitize Log reports successful completion with deallocation (SSTAT={value:#x})."]
        return False, details, [f"NVMe Sanitize Log reports status code {status_code} (SSTAT={value:#x})."]

    return None, details, ["NVMe Sanitize Log did not expose a parseable SSTAT field."]

def execute_real_sanitization(
    device: Device,
    *,
    confirm_device: str,
    confirm_model: str | None,
    confirm_serial: str | None,
    confirm_size: int | None,
    acknowledgement: bool,
    typed_confirmation: str | None = None,
) -> int:
    """Execute a real destructive operation only after all safety gates pass."""
    try:
        require_root()
    except PermissionError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    print("=" * 72)
    print("ZeroTrace-OS — REAL SANITIZATION")
    print("=" * 72)
    print(f"Target       : {device.path}")
    print(f"Media type   : {device.device_type}")
    print(f"Size         : {device.size_human}")
    print(f"Model        : {device.model or 'Unavailable'}")
    print(f"Serial       : {device.serial or 'Unavailable'}")
    print(f"Mountpoints  : {', '.join(device.mountpoints) or 'None'}")
    print(f"Protected    : {'YES' if device.protected else 'NO'}")
    print(f"Identity ID  : {device_identity_fingerprint(device)}")
    print()
    print("WARNING: THIS OPERATION IS DESTRUCTIVE.")
    print("ALL DATA ON THE SELECTED TARGET WILL BE ERASED.")
    print()

    if not acknowledgement:
        print("BLOCKED: You must explicitly acknowledge the destructive operation with --i-understand-this-is-destructive.")
        return 3

    failures = validate_real_execution_target(
        device,
        confirm_device=confirm_device,
        confirm_model=confirm_model,
        confirm_serial=confirm_serial,
        confirm_size=confirm_size,
    )
    if failures:
        print("BLOCKED — preflight checks failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 4

    try:
        preview = build_real_command(device)
    except ValueError as exc:
        print(f"BLOCKED: {exc}")
        return 4

    print("Preflight checks: PASS")
    print("Planned operation:")
    print("  " + " ".join(preview))
    print()

    typed = (typed_confirmation if typed_confirmation is not None else input(
        f"Type the exact target path '{device.path}' to continue: "
    )).strip()
    if typed != device.path:
        print("ABORTED: confirmation text did not match the target path.")
        return 5

    print()
    print("Re-checking target identity immediately before execution...")
    try:
        refreshed_devices = detect_devices()
    except Exception as exc:
        print(f"ABORTED: final device re-check failed: {exc}")
        return 9

    refreshed = get_device_by_path(refreshed_devices, device.path)
    if refreshed is None:
        print("ABORTED: target is no longer detected as the same whole disk.")
        return 9

    collect_smart(refreshed)
    calculate_reusability_score(refreshed)
    refreshed_fingerprint = device_identity_fingerprint(refreshed)
    original_fingerprint = device_identity_fingerprint(device)
    if refreshed_fingerprint != original_fingerprint:
        print("ABORTED: target identity changed after confirmation.")
        print(f"  Original fingerprint : {original_fingerprint}")
        print(f"  Current fingerprint  : {refreshed_fingerprint}")
        return 9

    if refreshed.device_type in {"SATA/Other SSD", "NVMe SSD"}:
        caps = detect_capabilities(refreshed.path, refreshed.device_type)
        refreshed.sanitization_capabilities = caps.__dict__

    final_failures = validate_preflight_safety(refreshed)
    if final_failures:
        print("ABORTED: final safety/capability re-check failed:")
        for failure in final_failures:
            print(f"  - {failure}")
        return 9

    print("Final target identity: MATCH")
    print("Final safety re-check: PASS")
    print()
    print("Starting sanitization...")
    print("Do NOT close the terminal or power off the machine during the operation.")
    print()

    started = datetime.now(timezone.utc)
    redacted_command = preview
    native_verified: bool | None = None
    native_details: dict[str, Any] = {}
    native_basis: list[str] = []

    if refreshed.device_type == "SATA/Other SSD":
        return_code, _, redacted_commands = _run_ata_security_erase(refreshed)
        redacted_command = redacted_commands[0] if redacted_commands else preview
    else:
        label = "HDD overwrite + nwipe verification" if refreshed.device_type == "HDD" else "NVMe Sanitize"
        return_code, _ = _run_destructive_step(preview, label=label)
        if refreshed.device_type == "NVMe SSD" and return_code == 0:
            native_verified, native_details, native_basis = _nvme_sanitize_log(refreshed.path)
            for item in native_basis:
                print(f"  - {item}")

    completed = datetime.now(timezone.utc)

    if return_code == 0:
        print()
        print("SANITIZATION COMMAND RESULT: SUCCESS")

        if refreshed.device_type == "HDD":
            post_verification = post_sanitization_verify(
                refreshed, operation_success=True, verification_mode="overwrite"
            )
        else:
            post_verification = post_sanitization_verify(
                refreshed,
                operation_success=True if refreshed.device_type == "SATA/Other SSD" else (native_verified is True),
                verification_mode="native",
                native_verified=True if refreshed.device_type == "SATA/Other SSD" else native_verified,
                native_status_details=({"method": "ATA Secure Erase"} if refreshed.device_type == "SATA/Other SSD" else native_details),
                native_basis=(["ATA Secure Erase command completed successfully."] if refreshed.device_type == "SATA/Other SSD" else native_basis),
            )

        print(f"Post-verification status : {post_verification.status}")
        print(f"Filesystem              : {post_verification.filesystem or 'None detected'}")
        print(f"Mountpoints             : {', '.join(post_verification.mountpoints) or 'None'}")
        print(f"First 1 MiB all zero    : {post_verification.first_mib_all_zero}")
        for basis in post_verification.verification_basis:
            print(f"  - {basis}")

        audit_path = save_sanitization_audit(
            refreshed,
            plan=build_sanitization_plan(refreshed),
            command=redacted_command,
            started=started,
            completed=completed,
            return_code=return_code,
            post_verification=post_verification,
        )
        print(f"Audit record            : {audit_path}")
        certificate_ready = post_verification.status == "VERIFIED"
        print(f"Certificate-ready       : {certificate_ready}")
        if certificate_ready:
            try:
                cert_json, cert_pdf = generate_certificate(audit_path)
                print(f"Certificate JSON        : {cert_json}")
                print(f"Certificate PDF         : {cert_pdf}")
            except Exception as exc:
                print(f"Certificate generation  : FAILED ({exc})")
                return 12
        print(f"Started                 : {started.isoformat()}")
        print(f"Completed               : {completed.isoformat()}")
        return 0 if certificate_ready else 11

    print("SANITIZATION RESULT: FAILED")
    print(f"Sanitization command returned exit code {return_code}.")
    post_verification = post_sanitization_verify(
        refreshed,
        operation_success=False,
        verification_mode="native" if refreshed.device_type in {"SATA/Other SSD", "NVMe SSD"} else "overwrite",
        native_verified=native_verified,
        native_status_details=native_details,
        native_basis=native_basis,
    )
    audit_path = save_sanitization_audit(
        refreshed,
        plan=build_sanitization_plan(refreshed),
        command=redacted_command,
        started=started,
        completed=completed,
        return_code=return_code,
        post_verification=post_verification,
    )
    print(f"Audit record: {audit_path}")
    print("DO NOT issue an erasure certificate for this device until the failure has been investigated.")
    return 10


def sample_first_mib_is_zero(path: str) -> bool | None:
    """Read-only post-wipe sample of the first 1 MiB.

    This is supporting evidence only. It is deliberately not treated as
    proof of a complete wipe; nwipe's full-device verification is the
    authoritative verification result for the HDD operation.
    """
    try:
        with open(path, "rb", buffering=0) as handle:
            data = handle.read(1024 * 1024)
        return len(data) == 1024 * 1024 and data == b"\x00" * len(data)
    except OSError:
        return None


def check_post_wipe_signatures(path: str) -> tuple[bool | None, bool | None, bool | None, dict[str, Any], list[str]]:
    """Independently check for filesystem/partition signatures after wiping.

    lsblk can retain cached FSTYPE information after a whole-device overwrite.
    wipefs/blkid probe the on-disk signatures directly, so they are used as the
    authoritative signature-absence checks. file(1) is additional evidence.
    All checks are read-only.
    """
    details: dict[str, Any] = {}
    basis: list[str] = []

    wipefs_absent: bool | None = None
    if command_exists("wipefs"):
        result = run_command(["wipefs", "-n", path], timeout=10)
        details["wipefs_return_code"] = result.returncode
        details["wipefs_stdout"] = result.stdout.strip()
        details["wipefs_stderr"] = result.stderr.strip()
        if result.returncode == 0:
            wipefs_absent = not bool(result.stdout.strip())
            if wipefs_absent:
                basis.append("wipefs -n found no on-disk filesystem or partition signatures.")
            else:
                basis.append("wipefs -n detected one or more on-disk signatures.")
        else:
            basis.append("wipefs -n could not complete successfully.")
    else:
        details["wipefs_available"] = False
        basis.append("wipefs is unavailable; independent signature check is incomplete.")

    blkid_absent: bool | None = None
    if command_exists("blkid"):
        result = run_command(["blkid", "-p", path], timeout=10)
        details["blkid_return_code"] = result.returncode
        details["blkid_stdout"] = result.stdout.strip()
        details["blkid_stderr"] = result.stderr.strip()
        # blkid normally returns 2 when no recognizable signature exists.
        if result.returncode in (0, 2):
            blkid_absent = not bool(result.stdout.strip())
            if blkid_absent:
                basis.append("blkid -p found no recognizable filesystem or partition signature.")
            else:
                basis.append("blkid -p identified a filesystem or partition signature.")
        else:
            basis.append("blkid -p could not complete successfully.")
    else:
        details["blkid_available"] = False
        basis.append("blkid is unavailable; independent identification check is incomplete.")

    raw_data = None
    if command_exists("file"):
        result = run_command(["file", "-s", path], timeout=10)
        output = result.stdout.strip()
        details["file_return_code"] = result.returncode
        details["file_output"] = output
        if result.returncode == 0:
            raw_data = output.endswith(": data") or output.endswith(": data\n")
            if raw_data:
                basis.append("file -s reports the raw device as unrecognized data.")
            else:
                basis.append("file -s reports a recognizable structure or type on the raw device.")
        else:
            basis.append("file -s could not complete successfully.")
    else:
        details["file_available"] = False
        basis.append("file is unavailable; raw-device type check is incomplete.")

    return wipefs_absent, blkid_absent, raw_data, details, basis


def post_sanitization_verify(
    original: Device,
    *,
    nwipe_success: bool | None = None,
    operation_success: bool | None = None,
    verification_mode: str = "overwrite",
    native_verified: bool | None = None,
    native_status_details: dict[str, Any] | None = None,
    native_basis: list[str] | None = None,
) -> PostVerification:
    """Perform read-only post-operation checks and create an audit record."""
    checked_at = datetime.now(timezone.utc).isoformat()
    if operation_success is None:
        operation_success = nwipe_success is True
    native_status_details = native_status_details or {}
    native_basis = native_basis or []
    verification_basis: list[str] = []

    try:
        devices = detect_devices()
    except Exception as exc:
        return PostVerification(
            device_detected=False,
            device_path=original.path,
            size_bytes=0,
            size_matches=False,
            filesystem="",
            mountpoints=[],
            filesystem_absent=False,
            unmounted=False,
            first_mib_all_zero=None,
            signature_check_details={},
            native_sanitization_verified=native_verified,
            native_status_details=native_status_details,
            verification_basis=[f"Post-operation device detection failed: {exc}"],
            status="INCONCLUSIVE",
            checked_at=checked_at,
        )

    current = get_device_by_path(devices, original.path)
    if current is None:
        return PostVerification(
            device_detected=False,
            device_path=original.path,
            size_bytes=0,
            size_matches=False,
            filesystem="",
            mountpoints=[],
            filesystem_absent=False,
            unmounted=False,
            first_mib_all_zero=None,
            signature_check_details={},
            native_sanitization_verified=native_verified,
            native_status_details=native_status_details,
            verification_basis=[
                "Target is no longer detected as a whole disk after sanitization."
            ],
            status="INCONCLUSIVE",
            checked_at=checked_at,
        )

    # Do not use lsblk FSTYPE as the deciding post-wipe filesystem check.
    # Linux can retain stale filesystem metadata there after a whole-disk overwrite.
    wipefs_absent, blkid_absent, raw_data, signature_details, signature_basis = (
        check_post_wipe_signatures(current.path)
    )
    filesystem_absent = wipefs_absent is True and blkid_absent is True
    unmounted = not bool(current.mountpoints)
    size_matches = current.size_bytes == original.size_bytes
    first_zero = sample_first_mib_is_zero(current.path)

    if verification_mode == "overwrite" and operation_success:
        verification_basis.append(
            "The overwrite sanitization utility reported successful full-device verification."
        )
    if verification_mode == "native":
        verification_basis.extend(native_basis)
    verification_basis.extend(signature_basis)
    if current.filesystem:
        verification_basis.append(
            f"lsblk reports stale/informational FSTYPE={current.filesystem!r}; "
            "direct signature probes are used for the post-wipe decision."
        )
    if unmounted:
        verification_basis.append("lsblk reports no active mountpoints on the target disk.")
    if first_zero is True:
        verification_basis.append("Read-only sample: first 1 MiB is zero-filled.")
    elif first_zero is False:
        verification_basis.append("Read-only sample: first 1 MiB is not entirely zero-filled.")
    else:
        verification_basis.append("First-MiB sample could not be read.")

    if verification_mode == "native":
        # Native controller sanitization is verified from the device/controller
        # status rather than requiring filesystem signatures to disappear.
        status = (
            "VERIFIED"
            if (
                operation_success
                and native_verified is True
                and size_matches
                and unmounted
            )
            else "FAILED"
            if not operation_success or native_verified is False
            else "INCONCLUSIVE"
        )
    else:
        status = (
            "VERIFIED"
            if (
                operation_success
                and size_matches
                and filesystem_absent
                and unmounted
            )
            else "FAILED"
            if not operation_success
            else "INCONCLUSIVE"
        )

    return PostVerification(
        device_detected=True,
        device_path=current.path,
        size_bytes=current.size_bytes,
        size_matches=size_matches,
        filesystem=current.filesystem,
        mountpoints=current.mountpoints,
        filesystem_absent=filesystem_absent,
        unmounted=unmounted,
        first_mib_all_zero=first_zero,
        wipefs_signatures_absent=wipefs_absent,
        blkid_identification_absent=blkid_absent,
        raw_device_is_unrecognized_data=raw_data,
        signature_check_details=signature_details,
        native_sanitization_verified=native_verified,
        native_status_details=native_status_details,
        verification_basis=verification_basis,
        status=status,
        checked_at=checked_at,
    )


def save_sanitization_audit(
    original: Device,
    *,
    plan: SanitizationPlan,
    command: list[str],
    started: datetime,
    completed: datetime,
    return_code: int,
    post_verification: PostVerification,
) -> Path:
    """Save a structured local audit record for the next certificate phase."""
    audit_dir = Path("audit_output")
    audit_dir.mkdir(exist_ok=True)
    audit_path = audit_dir / "last_sanitization.json"

    audit_data = {
        "schema_version": "1.0",
        "record_type": "ZeroTrace sanitization audit",
        "device_before": asdict(original),
        "sanitization_plan": asdict(plan),
        "execution": {
            "command": command,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "return_code": return_code,
            "result": "SUCCESS" if return_code == 0 else "FAILED",
        },
        "post_verification": asdict(post_verification),
        "certificate_ready": (
            return_code == 0 and post_verification.status == "VERIFIED"
        ),
    }

    audit_path.write_text(
        json.dumps(audit_data, indent=2),
        encoding="utf-8",
    )
    return audit_path


def run_real_for_device(
    device_path: str,
    *,
    confirm_device: str,
    confirm_model: str | None,
    confirm_serial: str | None,
    confirm_size: int | None,
    acknowledgement: bool,
    typed_confirmation: str | None = None,
) -> int:
    try:
        require_root()
    except PermissionError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2

    try:
        devices = detect_devices()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    device = get_device_by_path(devices, device_path)

    if device is None:
        print(
            f"ERROR: {device_path} is not a detected whole-disk device.",
            file=sys.stderr,
        )
        return 2

    # Re-read SMART before execution. This is assessment only and does not
    # modify the disk.
    collect_smart(device)
    calculate_reusability_score(device)
    if device.device_type in {"SATA/Other SSD", "NVMe SSD"}:
        caps = detect_capabilities(device.path, device.device_type)
        device.sanitization_capabilities = caps.__dict__

    return execute_real_sanitization(
        device,
        confirm_device=confirm_device,
        confirm_model=confirm_model,
        confirm_serial=confirm_serial,
        confirm_size=confirm_size,
        acknowledgement=acknowledgement,
        typed_confirmation=typed_confirmation,
    )


# ---------------------------------------------------------------------------
# Demo / Sandbox operation
# ---------------------------------------------------------------------------

def run_demo_operation(device: Device, plan: SanitizationPlan) -> DemoResult:
    """
    Simulate the complete sanitization workflow without touching storage.

    Demo mode is intentionally synthetic:
      detection -> plan -> progress -> verification -> completed

    It does not open the target device, overwrite sectors, send ATA commands,
    or send NVMe format/sanitize commands.
    """
    started = datetime.now(timezone.utc)
    logs: list[str] = []

    def log(message: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        logs.append(line)
        print(line, flush=True)

    log("ZeroTrace-OS Demo/Sandbox Mode started.")
    log(f"Target: {device.path}")
    log(f"Media type: {device.device_type}")
    log(f"Selected method: {plan.method}")
    log("Safety: NO storage write or destructive command will be executed.")

    steps = [
        "Validating target safety",
        "Loading device-specific sanitization workflow",
        "Preparing sanitization operation",
        "Executing simulated sanitization",
        "Performing simulated post-sanitization verification",
    ]

    for step_index, step in enumerate(steps, start=1):
        log(f"Step {step_index}/{len(steps)}: {step}")

        # Simulated progress only. This sleep is deliberately short so the
        # demo feels like an operation without wasting time.
        for percent in (25, 50, 75, 100):
            time.sleep(0.08)
            log(f"Progress: {percent}%")

    log("Verification result: PASS (simulation)")
    log("Demo operation completed successfully.")
    log("No sectors, partitions, files, or controller commands were modified.")

    completed = datetime.now(timezone.utc)

    return DemoResult(
        device=device.path,
        media_type=device.device_type,
        method=plan.method,
        status="DEMO_COMPLETED",
        verification="PASS_SIMULATED",
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
        log=logs,
    )


def run_demo_for_device(device_path: str) -> int:
    """Inspect a real visible device, but perform only a synthetic operation."""
    try:
        devices = detect_devices()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    requested = os.path.realpath(device_path)

    matches = [
        device
        for device in devices
        if os.path.realpath(device.path) == requested
    ]

    if not matches:
        print(
            f"ERROR: {device_path} is not a detected whole-disk device.",
            file=sys.stderr,
        )
        return 2

    device, plan = inspect_device(matches[0])

    print("=" * 72)
    print("ZeroTrace-OS — DEMO / SANDBOX MODE")
    print("=" * 72)

    if device.protected:
        print("BLOCKED: This device is protected.")
        print(f"Reason: {device.protection_reason}")
        print("Demo operation was not started.")
        return 3

    if not plan.command_preview:
        print("BLOCKED: No sanitization plan exists for this device.")
        return 3

    result = run_demo_operation(device, plan)

    print()
    print("DEMO RESULT")
    print(f"Status       : {result.status}")
    print(f"Verification : {result.verification}")
    print(f"Started      : {result.started_at}")
    print(f"Completed    : {result.completed_at}")
    print()
    print("IMPORTANT: This was a simulation. The disk was NOT wiped.")

    # Save a local audit record. This is not yet the final signed certificate.
    audit_dir = Path("demo_output")
    audit_dir.mkdir(exist_ok=True)

    audit_path = audit_dir / "last_demo_operation.json"
    audit_data = {
        "device": asdict(device),
        "sanitization_plan": asdict(plan),
        "demo_result": asdict(result),
        "warning": "DEMO/SANDBOX ONLY — NO STORAGE DATA WAS MODIFIED",
    }

    audit_path.write_text(
        json.dumps(audit_data, indent=2),
        encoding="utf-8",
    )

    print(f"Audit record : {audit_path}")
    return 0


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def device_to_dict(device: Device) -> dict[str, Any]:
    return asdict(device)


def print_device(device: Device, plan: SanitizationPlan) -> None:
    print("=" * 72)
    print(f"Device          : {device.path}")
    print(f"Size            : {device.size_human}")
    print(f"Type            : {device.device_type}")
    print(f"Model           : {device.model or 'Unknown'}")
    print(f"Serial          : {device.serial or 'Unavailable'}")
    print(f"Transport       : {device.transport or 'Unknown'}")
    print(f"Rotational      : {device.rotational}")
    print(f"Mountpoints     : {', '.join(device.mountpoints) or 'None'}")
    print(f"Read-only       : {device.read_only}")
    print(f"Root disk       : {device.root_disk}")
    print(f"Protected       : {device.protected}")

    if device.protection_reason:
        print(f"Protection      : {device.protection_reason}")

    print(f"SMART available  : {'YES' if device.smart_available else 'NO'}")
    print(f"SMART health     : {device.smart_health}")
    print(
        f"SMART attributes : "
        f"{json.dumps(device.smart_attributes) if device.smart_attributes else 'None available'}"
    )

    if device.reusability_score is None:
        print("Reusability      : N/A")
    else:
        print(f"Reusability      : {device.reusability_score}%")

    if device.score_reasons:
        print("Score notes      :")
        for reason in device.score_reasons:
            print(f"  - {reason}")

    if device.reusability_score is not None:
        score = device.reusability_score
        if score >= 80:
            rating = "GOOD"
        elif score >= 60:
            rating = "FAIR"
        elif score >= 40:
            rating = "POOR"
        else:
            rating = "CRITICAL"
        print(f"Reusability band : {rating}")

    print("-" * 72)
    print("SANITIZATION PLAN")
    print(f"Method          : {plan.method}")
    print(f"Category        : {plan.standard_category}")
    print(f"Utility         : {plan.utility}")
    print(
        "Command preview : "
        + (" ".join(plan.command_preview) if plan.command_preview else "NONE")
    )
    print(f"Executable      : {plan.executable}")

    for note in plan.notes:
        print(f"  NOTE: {note}")


def inspect_device(device: Device) -> tuple[Device, SanitizationPlan]:
    collect_smart(device)
    calculate_reusability_score(device)
    if device.device_type in {"SATA/Other SSD", "NVMe SSD"}:
        caps = detect_capabilities(device.path, device.device_type)
        device.sanitization_capabilities = caps.__dict__
    plan = build_sanitization_plan(device)
    return device, plan


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ZeroTrace-OS Phase 1 storage detection and sanitization planner."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "list",
        help="List detected whole-disk devices and safety status.",
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect one device and generate a sanitization plan.",
    )
    inspect_parser.add_argument(
        "device",
        help="Device path, e.g. /dev/sdb",
    )

    json_parser = subparsers.add_parser(
        "json",
        help="Output all detected devices as JSON.",
    )

    mock_parser = subparsers.add_parser(
        "mock",
        help="Run the Reusability Score against safe synthetic SMART data.",
    )
    mock_parser.add_argument(
        "scenario",
        choices=sorted(MOCK_SMART_SCENARIOS.keys()),
        help="Synthetic SMART profile to evaluate.",
    )

    demo_parser = subparsers.add_parser(
        "demo",
        help="Run the complete sanitization workflow in safe simulation mode.",
    )
    demo_parser.add_argument(
        "device",
        help="Detected whole-disk path, e.g. /dev/sdb",
    )

    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Run a READ-ONLY safety and device-identity check before wiping.",
    )
    preflight_parser.add_argument(
        "device",
        help="Detected whole-disk path, e.g. /dev/sdb",
    )

    execute_parser = subparsers.add_parser(
        "execute",
        help="Run a REAL destructive sanitization after strict safety checks.",
    )
    execute_parser.add_argument(
        "device",
        help="Detected whole-disk path, e.g. /dev/sdb",
    )
    execute_parser.add_argument(
        "--confirm-device",
        required=True,
        help="Repeat the exact target device path.",
    )
    execute_parser.add_argument(
        "--confirm-model",
        help="Exact detected device model. Recommended safety check.",
    )
    execute_parser.add_argument(
        "--confirm-serial",
        help="Exact detected device serial. Recommended safety check.",
    )
    execute_parser.add_argument(
        "--confirm-size",
        type=int,
        help="Exact detected size in bytes. Recommended safety check.",
    )
    execute_parser.add_argument(
        "--i-understand-this-is-destructive",
        action="store_true",
        help="Required acknowledgement that ALL target data will be erased.",
    )
    execute_parser.add_argument(
        "--confirm-path",
        help="Exact target path confirmation for non-interactive frontends such as the web UI.",
    )

    cap_parser = subparsers.add_parser("capabilities", help="Read-only SSD/NVMe sanitization capability discovery.")
    cap_parser.add_argument("device", help="Detected whole-disk path, e.g. /dev/nvme0n1")

    verify_wipe_parser = subparsers.add_parser(
        "verify-wipe",
        help="Run READ-ONLY post-sanitization verification against an existing audit record.",
    )
    verify_wipe_parser.add_argument(
        "device",
        help="Detected whole-disk path, e.g. /dev/sdb",
    )
    verify_wipe_parser.add_argument(
        "audit",
        nargs="?",
        default="audit_output/last_sanitization.json",
        help="Existing sanitization audit JSON to update.",
    )

    cert_parser = subparsers.add_parser("certificate", help="Generate a signed certificate from a verified audit record.")
    cert_parser.add_argument("audit", nargs="?", default="audit_output/last_sanitization.json")

    verify_parser = subparsers.add_parser("verify-certificate", help="Verify an Ed25519-signed certificate JSON file.")
    verify_parser.add_argument("certificate")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        devices = detect_devices()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.command == "list":
        print("ZeroTrace-OS — detected storage devices")
        print(
            "WARNING: This phase is inspection/planning only. "
            "No sanitization command is executed."
        )
        print()

        for device in devices:
            print(
                f"{device.path:12} "
                f"{device.size_human:10} "
                f"{device.device_type:15} "
                f"{'PROTECTED' if device.protected else 'AVAILABLE'}"
            )
            if device.protection_reason:
                print(f"  └─ {device.protection_reason}")

        return 0

    if args.command == "json":
        results = []

        for device in devices:
            device, plan = inspect_device(device)
            results.append(
                {
                    "device": device_to_dict(device),
                    "sanitization_plan": asdict(plan),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            )

        print(json.dumps(results, indent=2))
        return 0

    if args.command == "preflight":
        requested = os.path.realpath(args.device)
        matches = [
            device
            for device in devices
            if os.path.realpath(device.path) == requested
        ]

        if not matches:
            print(
                f"ERROR: {args.device} is not a detected whole-disk device.",
                file=sys.stderr,
            )
            return 2

        device = matches[0]
        collect_smart(device)
        calculate_reusability_score(device)
        if device.device_type in {"SATA/Other SSD", "NVMe SSD"}:
            caps = detect_capabilities(device.path, device.device_type)
            device.sanitization_capabilities = caps.__dict__
        print_preflight(device)
        return 0 if not validate_preflight_safety(device) else 3

    if args.command == "capabilities":
        match = next((d for d in devices if os.path.realpath(d.path) == os.path.realpath(args.device)), None)
        if match is None:
            print(f"ERROR: {args.device} is not a detected whole-disk device.", file=sys.stderr)
            return 2
        match, plan = inspect_device(match)
        caps = match.sanitization_capabilities or {}

        # Human-readable capability report.  Keep JSON available via the
        # dedicated `json` command, but do not make an HDD look broken just
        # because SSD/NVMe-native capability discovery is not applicable.
        print("=" * 72)
        print("ZeroTrace-OS — READ-ONLY SANITIZATION CAPABILITY CHECK")
        print("=" * 72)
        print(f"Device                 : {match.path}")
        print(f"Media type             : {match.device_type}")
        print(f"Transport              : {match.transport or 'Unknown'}")
        print(f"Model                  : {match.model or 'Unavailable'}")
        print(f"Serial                 : {match.serial or 'Unavailable'}")

        if match.device_type == "HDD":
            print("Capability discovery   : Not applicable (HDD)")
            print("Native SSD/NVMe utility: N/A")
            print("Sanitization utility   : nwipe")
            print("Recommended method    : HDD zero-fill + verification")
        else:
            print(f"Utility                : {caps.get('utility', 'N/A')}")
            print(f"Utility available      : {str(caps.get('utility_available', False)).upper()}")
            print(f"Capability query       : {'SUCCESS' if caps.get('capability_query_succeeded') else 'FAILED'}")
            supported = caps.get('supported_methods') or []
            print("Supported methods      : " + (", ".join(supported) if supported else "None discovered"))
            print("Recommended method     : " + (caps.get('recommended_method') or "None"))
            reasons = caps.get('blocked_reasons') or []
            if reasons:
                print("Notes / blockers       :")
                for reason in reasons:
                    print(f"  - {reason}")

        print("\nRecommended plan:")
        print("  " + (" ".join(plan.command_preview) if plan.command_preview else "NONE"))
        return 0

    if args.command == "verify-wipe":
        try:
            audit_path = Path(args.audit)
            if not audit_path.exists():
                print(f"ERROR: Audit file not found: {audit_path}", file=sys.stderr)
                return 2

            audit_data = json.loads(audit_path.read_text(encoding="utf-8"))
            original_data = audit_data.get("device_before")
            execution_data = audit_data.get("execution", {})

            if not isinstance(original_data, dict):
                print("ERROR: Audit does not contain device_before metadata.", file=sys.stderr)
                return 2

            original = Device(**original_data)
            operation_success = execution_data.get("return_code") == 0
            plan_data = audit_data.get("sanitization_plan", {})
            media_type = str(plan_data.get("media_type") or original.device_type)
            verification_mode = "native" if media_type in {"SATA/Other SSD", "NVMe SSD"} else "overwrite"
            native_verified = None
            native_details: dict[str, Any] = {}
            native_basis: list[str] = []
            if verification_mode == "native" and operation_success:
                if media_type == "NVMe SSD":
                    native_verified, native_details, native_basis = _nvme_sanitize_log(args.device)
                else:
                    native_verified = True
                    native_basis = ["Existing audit reports a successful ATA native sanitization command; no password is retained for replay."]

            print("=" * 72)
            print("ZeroTrace-OS — READ-ONLY POST-SANITIZATION VERIFICATION")
            print("=" * 72)
            print(f"Target: {args.device}")
            print("Safety: NO storage writes or destructive commands will be executed.")
            print()

            result = post_sanitization_verify(
                original,
                operation_success=operation_success,
                verification_mode=verification_mode,
                native_verified=native_verified,
                native_status_details=native_details,
                native_basis=native_basis,
            )

            print(f"Device detected        : {result.device_detected}")
            print(f"Size matches           : {result.size_matches}")
            print(f"lsblk FSTYPE           : {result.filesystem or 'None'}")
            print(f"Mounted                : {not result.unmounted}")
            print(f"Filesystem signatures  : {'None detected' if result.wipefs_signatures_absent else 'Detected/unknown'}")
            print(f"blkid identification   : {'None' if result.blkid_identification_absent else 'Detected/unknown'}")
            print(f"Raw device type        : {'data' if result.raw_device_is_unrecognized_data else 'Recognized/unknown'}")
            print(f"First 1 MiB all zero   : {result.first_mib_all_zero}")
            print(f"Status                 : {result.status}")

            if result.verification_basis:
                print("Verification evidence:")
                for item in result.verification_basis:
                    print(f"  - {item}")

            audit_data["post_verification"] = asdict(result)
            audit_data["certificate_ready"] = (
                execution_data.get("return_code") == 0
                and result.status == "VERIFIED"
            )
            audit_data["verification_updated_at"] = datetime.now(timezone.utc).isoformat()
            audit_path.write_text(
                json.dumps(audit_data, indent=2),
                encoding="utf-8",
            )

            print()
            print(f"Audit updated          : {audit_path}")
            print(f"Certificate ready      : {audit_data['certificate_ready']}")
            return 0 if result.status == "VERIFIED" else 3
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if args.command == "certificate":
        try:
            audit_path = Path(args.audit)
            cert_json, cert_pdf = generate_certificate(audit_path)
            print(f"Certificate JSON: {cert_json}")
            print(f"Certificate PDF : {cert_pdf}")
            return 0
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if args.command == "verify-certificate":
        try:
            ok, message = verify_certificate(Path(args.certificate))
            print(message)
            return 0 if ok else 1
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if args.command == "execute":
        return run_real_for_device(
            args.device,
            confirm_device=args.confirm_device,
            confirm_model=args.confirm_model,
            confirm_serial=args.confirm_serial,
            confirm_size=args.confirm_size,
            acknowledgement=args.i_understand_this_is_destructive,
            typed_confirmation=args.confirm_path,
        )

    if args.command == "demo":
        return run_demo_for_device(args.device)

    if args.command == "mock":
        device = Device(
            name="mock",
            path="MOCK://device",
            size_bytes=1_000_000_000,
            size_human="1.0 GB (mock)",
            device_type="Unknown",
        )

        apply_mock_smart(device, args.scenario)
        calculate_reusability_score(device)

        # Mock scenarios are for scoring only. We do not create or execute
        # a sanitization command for them.
        plan = SanitizationPlan(
            device=device.path,
            media_type=device.device_type,
            method="MOCK / scoring test only",
            standard_category="N/A",
            utility="N/A",
            command_preview=[],
            notes=[
                "Synthetic SMART data was used.",
                "No physical or virtual disk was accessed.",
                "No sanitization command can be executed in mock mode.",
            ],
            executable=False,
        )

        print("ZeroTrace-OS — SAFE MOCK SMART TEST")
        print(f"Scenario        : {args.scenario}")
        print_device(device, plan)
        return 0

    if args.command == "inspect":
        requested = os.path.realpath(args.device)

        matches = [
            device
            for device in devices
            if os.path.realpath(device.path) == requested
        ]

        if not matches:
            print(
                f"ERROR: {args.device} is not a detected whole-disk device.",
                file=sys.stderr,
            )
            return 2

        device, plan = inspect_device(matches[0])
        print_device(device, plan)
        return 0

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
