"""Unit tests for SATA/NVMe native sanitization orchestration.

These tests mock subprocess calls and never touch a real storage device.
"""
from unittest.mock import patch
from app.engine import Device, _nvme_sanitize_log, _run_ata_security_erase


def test_nvme_log_success():
    class R:
        returncode = 0
        stdout = "Sanitize Progress (SPROG) : 65535\nSanitize Status (SSTAT) : 0x101\n"
        stderr = ""

    with patch("app.engine.command_exists", return_value=True), \
         patch("app.engine.run_command", return_value=R()):
        ok, details, basis = _nvme_sanitize_log("/dev/nvme0n1")

    assert ok is True
    assert details["sstat_status"] == 1
    assert details["sstat_global_data_erased"] is True


def test_nvme_log_in_progress():
    class R:
        returncode = 0
        stdout = "Sanitize Progress (SPROG) : 100\nSanitize Status (SSTAT) : 0x2\n"
        stderr = ""

    with patch("app.engine.command_exists", return_value=True), \
         patch("app.engine.run_command", return_value=R()):
        ok, details, basis = _nvme_sanitize_log("/dev/nvme0n1")

    assert ok is False
    assert details["sstat_status"] == 2


def test_ata_lifecycle_uses_redacted_password():
    device = Device(
        name="sdc",
        path="/dev/sdc",
        size_bytes=100,
        size_human="100 B",
        device_type="SATA/Other SSD",
        model="TEST SSD",
        serial="TEST123",
        transport="sata",
        sanitization_capabilities={
            "recommended_method": "ata-security-erase",
            "raw_summary": {"security_frozen": False},
        },
    )

    calls = []

    def fake_step(command, *, label):
        calls.append(command)
        return 0, ["ok"]

    class Caps:
        raw_summary = {"security_enabled": True, "security_frozen": False}

    class CapsAfter:
        raw_summary = {"security_enabled": False, "security_frozen": False}

    with patch("app.engine.command_exists", return_value=True), \
         patch("app.engine._run_destructive_step", side_effect=fake_step), \
         patch("app.engine.detect_capabilities", side_effect=[Caps(), CapsAfter()]):

        rc, output, redacted = _run_ata_security_erase(device)

    assert rc == 0
    assert len(calls) == 2
    assert "--security-set-pass" in calls[0]
    assert "--security-erase" in calls[1]
    assert device.path in calls[1]
    assert any("<generated-password>" in cmd for cmd in redacted)
    # The generated password must never appear in the redacted audit commands.
    assert not any("password" in str(cmd).lower() and "<generated-password>" not in str(cmd) for cmd in redacted)


def test_sata_plan_is_executable_when_capability_is_safe():
    from app.engine import build_sanitization_plan

    device = Device(
        name="sdc",
        path="/dev/sdc",
        size_bytes=100,
        size_human="100 B",
        device_type="SATA/Other SSD",
        sanitization_capabilities={
            "recommended_method": "ata-enhanced-security-erase",
            "capability_query_succeeded": True,
            "raw_summary": {"security_frozen": False},
            "blocked_reasons": [],
        },
    )
    plan = build_sanitization_plan(device)
    assert plan.executable is True
    assert "<generated-password>" in " ".join(plan.command_preview)


def test_sata_plan_blocks_frozen_drive():
    from app.engine import build_sanitization_plan

    device = Device(
        name="sdc",
        path="/dev/sdc",
        size_bytes=100,
        size_human="100 B",
        device_type="SATA/Other SSD",
        sanitization_capabilities={
            "recommended_method": "ata-security-erase",
            "capability_query_succeeded": True,
            "raw_summary": {"security_frozen": True},
            "blocked_reasons": ["ATA security is frozen"],
        },
    )
    plan = build_sanitization_plan(device)
    assert plan.executable is False
