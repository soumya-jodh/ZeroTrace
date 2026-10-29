import tempfile
from pathlib import Path

from app.engine import Device, PostVerification, sample_first_mib_is_zero


def test_zero_sample():
    with tempfile.NamedTemporaryFile() as f:
        f.write(b"\x00" * (1024 * 1024))
        f.flush()
        assert sample_first_mib_is_zero(f.name) is True


def test_nonzero_sample():
    with tempfile.NamedTemporaryFile() as f:
        f.write(b"\x00" * (1024 * 1024 - 1) + b"X")
        f.flush()
        assert sample_first_mib_is_zero(f.name) is False


def test_post_wipe_signature_probe_on_zero_file():
    from app.engine import check_post_wipe_signatures

    with tempfile.NamedTemporaryFile() as f:
        f.write(b"\x00" * (1024 * 1024))
        f.flush()
        wipefs_absent, blkid_absent, raw_data, details, basis = check_post_wipe_signatures(f.name)

    assert wipefs_absent is True
    assert blkid_absent is True
    assert raw_data is True
    assert details["wipefs_return_code"] == 0
    assert details["blkid_return_code"] in (0, 2)
    assert any("wipefs -n found no" in item for item in basis)
