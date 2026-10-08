#!/usr/bin/env bash
# Builds a standalone Cryptid program: dist/Cryptid/Cryptid
set -e
cd "$(dirname "$0")"
[ -d .venv ] || ./requirements.sh
.venv/bin/python -m pip install pyinstaller
.venv/bin/python -m PyInstaller --noconfirm --clean --windowed --name Cryptid \
    --collect-all argon2 --collect-all _argon2_cffi_bindings \
    --collect-all send2trash cryptid_gui.py
echo
echo "Done. Run:  dist/Cryptid/Cryptid"
echo "To share it, copy the whole dist/Cryptid folder."
