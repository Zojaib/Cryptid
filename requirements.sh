#!/usr/bin/env bash
# Creates a private Python environment (.venv) with everything Cryptid needs.
set -e
cd "$(dirname "$0")"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install cryptography argon2-cffi zstandard send2trash "PySide6-Essentials>=6.6,<6.12"
echo
echo "Done. Start the app with:  .venv/bin/python cryptid_gui.py"
echo "If the window does not open on Debian/Ubuntu: sudo apt install libxcb-cursor0"
