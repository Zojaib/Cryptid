# Cryptid

Desktop app to encrypt and decrypt  files and folders before uploading them to the cloud.
AES-256-GCM + Argon2id, optional key file as a second factor. Python + PySide6, Windows and Linux.

**There is no recovery.** If you lose the password or the key file, the data is gone.

## Run

Python 3.10 or newer.

**Windows:** `requirements.bat` once, then `run\_cryptid.bat`. `build\_exe.bat` builds `dist\\Cryptid\\Cryptid.exe`.

**Linux:** `./requirements.sh` once, then `.venv/bin/python cryptid\_gui.py`. `./build\_linux.sh` builds a standalone binary.

