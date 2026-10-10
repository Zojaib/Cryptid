# Cryptid

Desktop app to encrypt and decrypt files and folders before uploading them to the cloud.
You choose what gets encrypted; each file or folder becomes one `.enc` file.
AES-256-GCM + Argon2id, optional key file as a second factor. Python + PySide6, Windows and Linux.

**There is no recovery.** If you lose the password or the key file, the data is gone.

## Run

Python 3.10 or newer.

**Windows:** `requirements.bat` once, then `run_cryptid.bat`. `build_exe.bat` builds `dist\Cryptid\Cryptid.exe`.

**Linux:** `./requirements.sh` once, then `.venv/bin/python cryptid_gui.py`. `./build_linux.sh` builds a standalone binary.

## What it does

- **Encrypt / Decrypt / Verify.** Verify reads a file completely and writes nothing: use it on the uploaded copy before you delete an original.
- **Key file** (optional): the files then need the password *and* the key file.
- **Hide the file names:** the encrypted file gets a random name; the real one is stored inside and comes back on decrypt.
- **Generate a strong password** (about 124 bits). Save it in a password manager: it is not stored anywhere.
- **Recover what is readable from damaged files:** off by default. A damaged file normally restores nothing; with this option the part before the damage is kept, marked `.partial` / `(incomplete)`, and never replaces an existing file.
- Names the restoring computer cannot store (for example `a:b.txt` on Windows) are renamed instead of failing the restore.
- Originals are only removed after the encrypted copy was read back, decrypted in full and compared.

## Command line

Same engine and same files, no window (does not need PySide6). On Windows use `cryptid_cli.bat` instead of `python cryptid_cli.py`.

```
python cryptid_cli.py encrypt Documents photo.jpg -o /mnt/cloud --hide-names
python cryptid_cli.py verify  /mnt/cloud
python cryptid_cli.py decrypt /mnt/cloud -o restored
python cryptid_cli.py genpass
python cryptid_cli.py keyfile /media/usb/Cryptid.encvkey
```

The password is asked for, or read from `CRYPTID_PASSWORD` or `--password-file`. `--help` lists every option.

## What is and is not protected

- Protected: the contents, and the names of everything inside an encrypted folder. Any change to an encrypted file is detected (wrong byte, missing end, swapped or removed blocks).
- Visible to anyone who has the file: its size, the size of the original, whether it was compressed, whether a key file is needed, and its name unless names are hidden.
- The password is the weak point. Every guess costs about 128 MB of memory and a fraction of a second, which stops nothing if the password is short or common.
- Deleting or overwriting an original does not guarantee it is gone from an SSD, a synced folder or a backup.

The file format is described in [FORMAT.md](FORMAT.md), so files can be read without this app.

## Tests

`pip install pytest`, then `python -m pytest tests`.
