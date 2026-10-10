"""
Cryptid from the command line: the same engine and the same files as the app, without a window.
For scripts, scheduled backups and machines without a desktop. Needs no PySide6.

    python cryptid_cli.py encrypt  Documents photo.jpg -o /mnt/cloud --hide-names
    python cryptid_cli.py verify   /mnt/cloud
    python cryptid_cli.py decrypt  /mnt/cloud/3f9c1a7be2d04c55.enc -o restored
    python cryptid_cli.py genpass
    python cryptid_cli.py keyfile  /media/usb/Cryptid.encvkey

The password is asked for (twice when encrypting). For unattended use, put it in the
CRYPTID_PASSWORD environment variable or in a file given with --password-file. There is
deliberately no --password option: command lines show up in process lists and shell history.

Exit code: 0 nothing failed (files skipped because they exist count as fine), 1 something failed
or was only recovered in part, 2 wrong usage, 130 interrupted.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from cryptography.exceptions import InvalidTag

import cryptid_core as core


def _err(msg: str):
    print(msg, file=sys.stderr)


class _Usage(Exception):
    pass


def _read_password(args, confirm: bool) -> str:
    if args.password_file:
        try:
            # utf-8-sig: Notepad and PowerShell put an invisible mark at the start of a "UTF-8" file,
            # which must not become part of the password.
            with open(args.password_file, "r", encoding="utf-8-sig") as f:
                pw = f.readline().rstrip("\r\n")
        except OSError as e:
            raise _Usage(f"Cannot read the password file: {e.strerror or e}")
        except UnicodeError:
            raise _Usage("The password file is not UTF-8 text. Save it as UTF-8 and try again.")
    elif os.environ.get("CRYPTID_PASSWORD"):
        pw = os.environ["CRYPTID_PASSWORD"]
    else:
        if not sys.stdin.isatty():
            raise _Usage("No password: set CRYPTID_PASSWORD or use --password-file when not at a terminal.")
        pw = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Repeat password: ") != pw:
            raise _Usage("The two passwords don't match.")
    if not pw:
        raise _Usage("The password is empty.")
    return pw


def _progress_printer(name: str):
    if not sys.stderr.isatty():
        return None
    last = [""]

    def show(frac: float, stage: str):
        text = f"  {stage} {int(frac * 100):3d}%  {name}"[:79]
        if text != last[0]:
            last[0] = text
            sys.stderr.write("\r" + text.ljust(79))
            sys.stderr.flush()
    return show


def _clear_progress():
    if sys.stderr.isatty():
        sys.stderr.write("\r" + " " * 79 + "\r")
        sys.stderr.flush()


def _encrypted_files(paths) -> list:
    """Encrypted files among `paths`; a folder stands for every encrypted file inside it."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                out += [os.path.join(root, f) for f in sorted(files) if core.is_encv_file(os.path.join(root, f))]
        else:
            out.append(p)
    return out


def _run(args) -> int:
    cmd = args.command
    if cmd == "genpass":
        print(core.generate_password(args.groups))
        return 0
    if cmd == "keyfile":
        path = args.path if os.path.splitext(args.path)[1] else args.path + "." + core.KEYFILE_EXTENSION
        key_id = core.create_keyfile(path)
        print(f"Created {path}\nKey ID: {key_id}")
        _err("Keep it apart from your encrypted files and make a backup copy now: "
             "without it AND the password nothing can be opened.")
        return 0

    paths = args.paths if cmd == "encrypt" else _encrypted_files(args.paths)
    if not paths:
        raise _Usage("No encrypted files found there.")
    password = _read_password(args, confirm=cmd == "encrypt")
    opts = None
    if cmd == "encrypt":
        bits, ok, hint = core.password_feedback(password)
        if not ok and not args.allow_weak:
            raise _Usage(f"{hint.rstrip('.')} (about {bits:.0f} bits). Run the 'genpass' command for a strong one, "
                         "or pass --allow-weak to use this one anyway.")
        try:
            ext = core.clean_extension(args.ext)
        except ValueError as e:
            raise _Usage(f"--ext: {e}")
        opts = core.EncryptOptions(
            kdf_profile=args.kdf, compression=args.compression, verify=not args.no_verify,
            keyfile=args.keyfile, after=args.after, overwrite=args.if_exists, extension=ext,
            hide_name=args.hide_names)
    known_ext = (core.DEFAULT_EXTENSION, *(getattr(args, "strip_ext", None) or ()))

    failed = partial = 0
    for path in paths:
        name = os.path.basename(path.rstrip("\\/")) or path
        hooks = core.Hooks(progress=_progress_printer(name), log=None)
        try:
            if cmd == "encrypt":
                r = core.encrypt_path(path, args.output, password, opts, hooks)
                line = f"encrypted  {name} -> {r.output}  ({core.size_str(r.in_size)} -> {core.size_str(r.out_size)})"
                if r.original != "kept":
                    line += f"  [original {r.original}]"
            elif cmd == "verify":
                r = core.verify_path(path, password, hooks, keyfile=args.keyfile)
                inside = f"contains {', '.join(repr(n) for n in r.names[:3])}, " if r.names else ""
                line = f"intact     {name}  ({inside}{core.size_str(r.out_size)})"
            else:
                r = core.decrypt_path(path, args.output, password, args.if_exists, hooks, known_ext,
                                      keyfile=args.keyfile, salvage=args.salvage)
                line = f"{'RECOVERED IN PART' if r.partial else 'decrypted'}  {name} -> {r.output}"
                partial += r.partial
            _clear_progress()
            print(line)
            for w in r.warnings:
                _err(f"  warning: {w}")
        except KeyboardInterrupt:
            _clear_progress()
            _err("Interrupted. Nothing unfinished was left behind.")
            return 130
        except core.Skipped as e:
            _clear_progress()
            print(f"skipped    {name}  ({e})")
        except InvalidTag:
            _clear_progress()
            both = args.keyfile or (cmd != "encrypt" and core.file_needs_keyfile(path))
            _err(f"FAILED     {name}: wrong password{' or wrong key file' if both else ''}, "
                 "or the file is damaged or was modified.")
            failed += 1
        except Exception as e:  # noqa: BLE001
            _clear_progress()
            _err(f"FAILED     {name}: {e}")
            failed += 1
    return 1 if failed or partial else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cryptid_cli.py", description="Encrypt, decrypt and verify Cryptid files without the window.",
        epilog="Password: asked for at the terminal, or read from CRYPTID_PASSWORD or --password-file. "
               "There is no recovery: without the password (and the key file, if one was used) the data is gone.")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp, keyfile_help):
        sp.add_argument("--keyfile", metavar="FILE", help=keyfile_help)
        sp.add_argument("--password-file", metavar="FILE", help="read the password from the first line of FILE")

    e = sub.add_parser("encrypt", help="encrypt files and folders (each becomes one file)")
    e.add_argument("paths", nargs="+", metavar="PATH")
    e.add_argument("-o", "--output", metavar="DIR", help="where to write (default: next to each original)")
    common(e, "also require this key file to open the result")
    e.add_argument("--hide-names", action="store_true",
                   help="give the encrypted file a random name; the real name is kept inside and restored")
    e.add_argument("--kdf", choices=("strong", "light", "auto"), default="strong",
                   help="key strength: strong = 128 MiB of memory (default), light = 32 MiB, auto = tuned")
    e.add_argument("--compression", choices=("auto", "fast", "lzma", "none"), default="auto")
    e.add_argument("--after", choices=("keep", "trash", "delete", "wipe"), default="keep",
                   help="what to do with the original once the encrypted copy was checked (default: keep)")
    e.add_argument("--if-exists", choices=("rename", "overwrite", "skip"), default="rename")
    e.add_argument("--ext", default=core.DEFAULT_EXTENSION, help="extension of the encrypted file (default: enc)")
    e.add_argument("--no-verify", action="store_true", help="skip reading the result back (not with --after)")
    e.add_argument("--allow-weak", action="store_true", help="accept a password the strength check rejects")

    d = sub.add_parser("decrypt", help="restore encrypted files (a folder means every encrypted file in it)")
    d.add_argument("paths", nargs="+", metavar="PATH")
    d.add_argument("-o", "--output", metavar="DIR", help="where to restore to (default: next to each file)")
    common(d, "the key file the files were protected with")
    d.add_argument("--if-exists", choices=("rename", "overwrite", "skip"), default="rename")
    d.add_argument("--strip-ext", action="append", metavar="EXT",
                   help="a custom extension used when encrypting, removed from restored names (repeatable)")
    d.add_argument("--salvage", action="store_true",
                   help="for a damaged file: keep the part that is still readable instead of nothing")

    v = sub.add_parser("verify", help="check that files are complete and the password opens them; writes nothing")
    v.add_argument("paths", nargs="+", metavar="PATH")
    common(v, "the key file the files were protected with")

    k = sub.add_parser("keyfile", help="create a new random key file (never overwrites)")
    k.add_argument("path", metavar="NEW_FILE")

    g = sub.add_parser("genpass", help="print a random password (about 25 bits per group)")
    g.add_argument("--groups", type=int, default=5, help="groups of 5 characters (default 5 = 124 bits)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except _Usage as e:
        _err(f"cryptid: {e}")
        return 2
    except KeyboardInterrupt:
        _err("Interrupted.")
        return 130
    except (OSError, ValueError) as e:
        _err(f"cryptid: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
