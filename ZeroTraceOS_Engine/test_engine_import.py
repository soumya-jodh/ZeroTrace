#!/usr/bin/env python3
"""Basic syntax/import regression test for ZeroTrace engine."""

import py_compile
from pathlib import Path

engine = Path("app/engine.py")
py_compile.compile(str(engine), doraise=True)

print("PASS: engine.py compiles successfully.")
