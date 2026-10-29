"""Read-only hardware sanitization capability discovery for ZeroTrace-OS."""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


def _exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(cmd: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False)


@dataclass
class SanitizationCapabilities:
    device: str
    media_type: str
    utility: str
    utility_available: bool
    capability_query_succeeded: bool
    supported_methods: list[str]
    recommended_method: str | None
    blocked_reasons: list[str]
    raw_summary: dict[str, Any]


def detect_nvme_capabilities(path: str) -> SanitizationCapabilities:
    reasons: list[str] = []
    supported: list[str] = []
    raw: dict[str, Any] = {}

    if not _exists("nvme"):
        return SanitizationCapabilities(path, "NVMe SSD", "nvme-cli", False, False, [], None,
                                        ["nvme-cli is not installed"], raw)

    # Identify the controller. nvme id-ctrl is read-only.
    result = _run(["nvme", "id-ctrl", path])
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    raw["id_ctrl_exit_code"] = result.returncode

    if result.returncode != 0:
        result = _run(["nvme", "id", "ctrl", path])
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        raw["id_ctrl_fallback_exit_code"] = result.returncode
        if result.returncode != 0:
            reasons.append("NVMe controller capability query failed; capabilities could not be trusted")
            return SanitizationCapabilities(path, "NVMe SSD", "nvme-cli", True, False, [], None, reasons, raw)

    # SANICAP is normally printed as a hexadecimal value by nvme-cli.
    m = re.search(r"Sanitize Capabilities\s*:\s*(0x[0-9a-fA-F]+|[0-9]+)", text, re.I)
    if not m:
        # Some nvme-cli versions use "sanicap" in JSON-ish/verbose output.
        m = re.search(r"sanicap\s*[:=]\s*(0x[0-9a-fA-F]+|[0-9]+)", text, re.I)

    if m:
        try:
            sanicap = int(m.group(1), 0)
            raw["sanicap"] = sanicap
            # NVMe SANICAP: bit 0 crypto erase, bit 1 block erase, bit 2 overwrite.
            if sanicap & 0x1:
                supported.append("crypto-erase")
            if sanicap & 0x2:
                supported.append("block-erase")
            if sanicap & 0x4:
                supported.append("overwrite")
        except ValueError:
            reasons.append("SANICAP value could not be parsed")
    else:
        reasons.append("SANICAP was not exposed by this nvme-cli/controller output")

    # Prefer crypto erase because it is controller-native and avoids host-side
    # multi-pass writes; otherwise use block erase, then overwrite.
    recommended = next((m for m in ("crypto-erase", "block-erase", "overwrite") if m in supported), None)
    if recommended is None:
        reasons.append("No supported NVMe sanitize action was discovered")

    return SanitizationCapabilities(path, "NVMe SSD", "nvme-cli", True, True,
                                    supported, recommended, reasons, raw)


def detect_ata_capabilities(path: str) -> SanitizationCapabilities:
    reasons: list[str] = []
    supported: list[str] = []
    raw: dict[str, Any] = {}

    if not _exists("hdparm"):
        return SanitizationCapabilities(path, "SATA/Other SSD", "hdparm", False, False, [], None,
                                        ["hdparm is not installed"], raw)

    result = _run(["hdparm", "-I", path])
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    raw["identify_exit_code"] = result.returncode

    if result.returncode != 0:
        reasons.append("hdparm -I failed; ATA security capabilities could not be trusted")
        return SanitizationCapabilities(path, "SATA/Other SSD", "hdparm", True, False, [], None, reasons, raw)

    lower = text.lower()
    frozen = bool(re.search(r"security:\s*.*\bfrozen\b|\bfrozen\b", lower))
    enabled = bool(re.search(r"security:\s*.*\benabled\b", lower))
    supported_flag = bool(re.search(r"security erase unit", lower))
    enhanced_flag = bool(re.search(r"enhanced security erase", lower))
    raw.update({"security_frozen": frozen, "security_enabled": enabled,
                "security_erase_supported": supported_flag,
                "enhanced_security_erase_supported": enhanced_flag})

    if supported_flag:
        supported.append("ata-security-erase")
    if enhanced_flag:
        supported.append("ata-enhanced-security-erase")
    if frozen:
        reasons.append("ATA security is frozen; an unfrozen state is required before security erase")

    recommended = None
    if not frozen:
        if enhanced_flag:
            recommended = "ata-enhanced-security-erase"
        elif supported_flag:
            recommended = "ata-security-erase"
    else:
        reasons.append("Native ATA erase is not executable while the device reports SECURITY FROZEN")

    if not supported:
        reasons.append("No ATA Security Erase capability was reported")

    return SanitizationCapabilities(path, "SATA/Other SSD", "hdparm", True, True,
                                    supported, recommended, reasons, raw)


def detect_capabilities(device_path: str, media_type: str) -> SanitizationCapabilities:
    if media_type == "NVMe SSD":
        return detect_nvme_capabilities(device_path)
    if media_type == "SATA/Other SSD":
        return detect_ata_capabilities(device_path)
    return SanitizationCapabilities(device_path, media_type, "N/A", False, True, [], None,
                                    ["Capability discovery is only required for SSD/NVMe media"], {})


def as_dict(caps: SanitizationCapabilities) -> dict[str, Any]:
    return asdict(caps)
