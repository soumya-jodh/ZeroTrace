import json
from pathlib import Path
from app.engine import build_parser


def test_verify_wipe_parser_is_read_only_command():
    args = build_parser().parse_args(["verify-wipe", "/dev/sdb"])
    assert args.command == "verify-wipe"
    assert args.device == "/dev/sdb"
    assert args.audit == "audit_output/last_sanitization.json"
