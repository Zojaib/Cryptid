"""
cryptid_core.py - ENCV v8 engine (no UI, no prompts, no sys.exit)

Pipeline: file/folder -> tar (folders only) -> zstd/lzma -> chunked AES-256-GCM -> .enc (or any extension)
Key derivation: Argon2id.

File format is IDENTICAL to the original Encrypt.py / Decrypt.py scripts (v8) this project grew out of, so every
.enc you already have keeps working. Differences are in behaviour only:

  * Decryption no longer loses data (the original Decrypt.py dropped up to one
    chunk of output while sniffing the first 512 bytes for a tar header).
  * The terminal chunk is always read and verified, also for folders.
  * Trailing bytes after the terminal chunk are rejected.
  * Single files that are themselves .tar archives are wrapped, so they are
    restored as files instead of being unpacked as folders.
  * Folder archives keep empty folders and file modification times.

Security model (what is trusted, and when):

  * Everything in the file header is UNTRUSTED until the first chunk authenticates,
    and the key derivation runs before that. So the Argon2 settings are checked
    against fixed ceilings (KDF_MAX_*) before any key is derived.
  * Everything after the header is authenticated chunk by chunk before it reaches
    the decompressor or the archive reader. A hostile archive therefore needs the
    password. Limits (see Limits) still bound what such an archive can do: bytes
    written, free disk space, entry count, name length/depth, header size and
    decoder memory.
  * Restoring uses an own extractor, not tarfile.extract: only regular files and
    folders, exclusive creation, no links, private permissions, safe names.
  * Temporary files are created exclusively with random names inside the target
    folder; finished files are published atomically and never replace anything
    unless "replace" was chosen.
  * Originals are only removed after the written file was decrypted again in full
    and its SHA-256 matched the data that was read.

Since the first public version (the file format did not change):

  * The limits the restore step enforces (nesting depth, path length, entry count, total size)
    are now checked before encrypting, and the read-back check walks an archive with the same
    code that restores it. Before, a folder nested deeper than the restore limit, or one whose
    name looks like a drive letter ("C: backup"), encrypted and verified fine and then could
    not be decrypted.
  * Names the restoring system cannot store (a:b.txt, aux.txt or "name." on Windows, names that
    are too long) are renamed when restoring instead of making the whole restore fail.
  * Optional: hide the original name (random output name, real name stored inside), and
    recover the readable part of a damaged file (see decrypt_path(salvage=True)).

  Still true: restoring needs a destination whose path is short enough. A tree whose paths are
  already at the system's limit restores only into a folder with a shorter path than it came from.

Key file (optional second factor, like KeePass): the header's KDF id is 2 instead of 1.
The encryption key is HMAC-SHA256(key = digest of the key file, message = label + Argon2id output),
so opening a file needs the password AND the key file. Files without a key file stay
byte-for-byte compatible with the original scripts; files with one are refused by them
(unknown KDF id) rather than failing with a misleading "wrong password".
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import lzma
import math
import os
import shutil
import struct
import tarfile
import threading
import time
import secrets
import stat
import tempfile
import errno
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:  # falls back to the built-in lzma
    ZSTD_AVAILABLE = False

try:
    from send2trash import send2trash as _send2trash
    TRASH_AVAILABLE = True
except Exception:  # not installed, or no trash support on this system
    _send2trash = None
    TRASH_AVAILABLE = False


# -- Format constants (must match the original scripts) ------------------------
KDF_ARGON2ID = 1
KDF_ARGON2ID_KEYFILE = 2   # same Argon2id, then mixed with a key file (Cryptid only; the old scripts refuse it)
CIPHER_AES_GCM = 1

COMPRESS_NONE = 0
COMPRESS_ZSTD = 1
COMPRESS_LZMA = 2
COMPRESS_NAMES = {0: "none", 1: "zstd", 2: "lzma"}

FORMAT_MAGIC = b"ENCV"
FORMAT_VERSION = 8
CHUNK_SIZE = 512 * 1024
CHUNK_SIZE_SMALL = 64 * 1024
TAG_SIZE = 16
CHUNK_LEN_SIZE = 4
NONCE_PREFIX_LEN = 4
TERMINAL_COUNTER = 0xFFFF_FFFF_FFFF_FFFF
HEADER_SIZE = 4 + 1 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + 16 + 4 + 8  # 52 bytes

MAX_ORIG_SIZE = 1024 ** 4      # 1 TiB: the largest original this format version restores

KDF_MIN_TIME_COST = 2
KDF_MIN_MEMORY_COST = 19456

# Ceilings for the Argon2id settings read from a file header. The header is not
# authenticated yet when the key is derived, so anyone able to edit the file could
# otherwise ask for 4 GiB x 999 passes. These are the largest values any version of
# this app (or the original scripts) ever wrote: 3 passes, 512 MiB (the autotune cap),
# at most 4 lanes. Raise them here if you ever tune beyond that.
KDF_MAX_TIME_COST = 6
KDF_MAX_MEMORY_COST = 512 * 1024    # KiB = 512 MiB
KDF_MAX_PARALLELISM = 8

AUTOTUNE_CACHE = Path.home() / ".config" / "encv" / "argon2.json"

_CORES = os.cpu_count() or 1
KDF_PROFILES = {
    "strong": {"time_cost": 3, "memory_cost": 131072, "parallelism": min(4, _CORES)},
    "light":  {"time_cost": 2, "memory_cost": 32768,  "parallelism": min(2, _CORES)},
}

# Extensions that are already compressed: zstd would burn CPU for nothing.
INCOMPRESSIBLE_EXT = {
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".tgz", ".lz4",
    ".jpg", ".jpeg", ".png", ".webp", ".heic", ".avif", ".gif",
    ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v",
    ".mp3", ".aac", ".m4a", ".ogg", ".opus", ".flac",
    ".docx", ".xlsx", ".pptx", ".odt", ".jar", ".apk",
}


# -- Output file extension -----------------------------------------------------
DEFAULT_EXTENSION = "enc"
MAX_EXTENSION_LEN = 16
# Names that would make an encrypted blob look like a program or script.
BLOCKED_EXTENSIONS = {
    "exe", "com", "bat", "cmd", "scr", "msi", "dll", "lnk", "pif", "ps1", "vbs", "vbe",
    "js", "jse", "wsf", "hta", "reg", "jar", "sh", "app", "apk",
}


def clean_extension(raw: str) -> str:
    """Normalise what the user typed ('.Vault ' -> 'vault'). Empty means the default, 'enc'.

    Raises ValueError with a message that can be shown as-is.
    """
    ext = (raw or "").strip().lstrip(".").strip().lower()
    if not ext:
        return DEFAULT_EXTENSION
    if len(ext) > MAX_EXTENSION_LEN:
        raise ValueError(f"Use at most {MAX_EXTENSION_LEN} characters.")
    if not all(c.isascii() and (c.isalnum() or c in "-_") for c in ext):
        raise ValueError("Use only letters, numbers, - and _ (no dots or spaces).")
    if ext in BLOCKED_EXTENSIONS:
        raise ValueError(f".{ext} could be mistaken for a program. Pick another extension.")
    return ext


# -- Exceptions / hooks --------------------------------------------------------

class Cancelled(Exception):
    pass


class Skipped(Exception):
    pass


class AlreadyEncrypted(Skipped):
    pass


class FormatError(ValueError):
    pass


class LimitExceeded(ValueError):
    """An archive went beyond one of the safety limits (size, entries, disk space...)."""


class SourceReadError(ValueError):
    """The encrypted file itself could not be read (a bad sector, a network drive that dropped)."""


class Hooks:
    """Cancel flag + throttled progress + log, shared by one job."""

    def __init__(self, cancel: Optional[threading.Event] = None,
                 progress: Optional[Callable[[float, str], None]] = None,
                 log: Optional[Callable[[str], None]] = None):
        self.cancel = cancel or threading.Event()
        self._progress = progress
        self._log = log
        self._last = 0.0

    def check(self):
        if self.cancel.is_set():
            raise Cancelled()

    def progress(self, frac: float, stage: str, force: bool = False):
        if not self._progress:
            return
        now = time.monotonic()
        if force or now - self._last >= 0.05:
            self._last = now
            self._progress(min(max(frac, 0.0), 1.0), stage)

    def log(self, msg: str):
        if self._log:
            self._log(msg)


@dataclass
class EncryptOptions:
    kdf_profile: str = "strong"     # strong | light | auto
    compression: str = "auto"       # auto | fast | lzma | none
    verify: bool = True
    keyfile: Optional[str] = None   # path of a key file: required together with the password to open the result
    after: str = "keep"             # keep | trash | delete | wipe
    overwrite: str = "rename"       # rename | overwrite | skip
    extension: str = DEFAULT_EXTENSION   # file extension of the encrypted file, without the dot
    hide_name: bool = False         # random output name; the real name is stored inside and restored on decrypt


@dataclass
class Result:
    output: str = ""
    in_size: int = 0
    out_size: int = 0
    files: int = 0          # verify: regular files found inside a folder archive
    folders: int = 0        # verify: folders found inside a folder archive
    is_folder: bool = False  # verify: the archive holds a folder, not a single file
    original: str = ""       # encrypt: what happened to the original: kept | trashed | deleted | wiped
    names: List[str] = field(default_factory=list)   # verify/decrypt: top-level names stored inside an archive
    partial: bool = False    # decrypt(salvage=True): the file is damaged, only the readable part was restored
    warnings: List[str] = field(default_factory=list)


# -- Small helpers -------------------------------------------------------------

def size_str(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def read_magic(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read(4)


def is_encv_file(path: str) -> bool:
    try:
        return os.path.isfile(path) and read_magic(path) == FORMAT_MAGIC
    except OSError:
        return False


def _looks_like_tar(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(512)
        return len(head) >= 262 and head[257:262] == b"ustar"
    except OSError:
        return False


MIN_PASSWORD_LEN = 16
MIN_PASSWORD_BITS = 50

# What people actually type. Each of these counts as one guess-list entry, not as random letters.
_COMMON_WORDS = sorted((
    "password", "passwort", "contrasena", "contraseña", "qwerty", "qwertz", "azerty", "letmein", "welcome",
    "admin", "administrator", "login", "master", "dragon", "monkey", "iloveyou", "teamo", "secret", "secreto",
    "football", "baseball", "princess", "sunshine", "shadow", "superman", "batman", "trustno", "hello",
    "hola", "freedom", "whatever", "starwars", "pokemon", "computer", "internet", "michael", "jordan",
    "summer", "winter", "spring", "autumn", "love", "god", "test", "guest", "root", "user", "default",
    "changeme", "cryptid", "encrypt", "abc", "asdf", "zxcv", "pass", "key", "enc",
), key=len, reverse=True)
_KEY_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwertzuiop", "azertyuiop",
             "1qaz2wsx3edc4rfv5tgb6yhn7ujm", "zaq1xsw2cde3vfr4bgt5nhy6mju7")     # rows, then columns
_PW_ANALYSED = 128      # characters looked at: more cannot change the verdict, and the search is not linear
_LEET = str.maketrans("013457@$!", "oleastasi")


def _run_bits(length: int) -> float:
    """What a repeat, a sequence or a keyboard walk is worth: where it starts and how long it is."""
    return 6.0 + 2.0 * math.log2(length)


def _pattern_at(low: str, plain: str, i: int):
    """(length, bits) of the longest predictable stretch starting at i, or (0, 0)."""
    best = [0, 0.0]

    def consider(length: int, bits: float):
        if length > best[0] or (length == best[0] and bits < best[1]):
            best[0], best[1] = length, bits

    for w in _COMMON_WORDS:                          # a word from every cracking list (also with l33t letters)
        if low.startswith(w, i) or plain.startswith(w, i):
            consider(len(w), 10.0)
            break                                    # sorted longest first
    n = len(low)
    j = i + 1                                        # the same character again, or abc / 321
    if j < n:
        step = ord(low[j]) - ord(low[i])
        if step in (0, 1, -1):
            while j < n and ord(low[j]) - ord(low[j - 1]) == step:
                j += 1
            if j - i >= 3:
                consider(j - i, _run_bits(j - i))
    for row in _KEY_ROWS:                            # a walk along the keyboard, either direction
        for r in (row, row[::-1]):
            k = r.find(low[i])
            if k < 0:
                continue
            m = 1
            while i + m < n and k + m < len(r) and low[i + m] == r[k + m]:
                m += 1
            if m >= 3:
                consider(m, _run_bits(m))
    m = min(n - i, i, 32)                            # something already typed earlier in the password
    while m >= 3:
        if low[i:i + m] in low[:i]:
            consider(m, 4.0)
            break
        m -= 1
    return best[0], best[1]


def password_feedback(password: str):
    """(estimated_bits, acceptable, hint). The hint says what is wrong, or "" if nothing is.

    An estimate, not a proof: it counts character variety like the original script did, but no longer
    gives full credit to repeats (aaaa), sequences (1234, abcd), keyboard walks (qwerty), repeated
    blocks (hunterhunter) or the words every cracking list starts with. A passphrase of ordinary words
    is still credited per character, so prefer random words or the generator.
    """
    if not password:
        return 0.0, False, ""
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    charset = (26 * has_lower) + (26 * has_upper) + (10 * has_digit) + (32 * has_symbol)
    per_char = math.log2(charset or 26)       # 0: letters of a script without upper and lower case
    low = password[:_PW_ANALYSED].lower()
    plain = low.translate(_LEET)
    bits, i, predictable = 0.0, 0, 0
    while i < len(low):
        length, cost = _pattern_at(low, plain, i)
        if length and cost < length * per_char:
            bits += cost
            predictable += length
            i += length
        else:
            bits += per_char
            i += 1
    hint = ""
    if len(password) < MIN_PASSWORD_LEN:
        hint = f"Too short: use at least {MIN_PASSWORD_LEN} characters."
    elif bits < MIN_PASSWORD_BITS:
        hint = ("Too predictable: it is mostly repeats, sequences or common words."
                if predictable * 2 >= len(low) else "Too weak: mix in more different characters.")
    return bits, not hint, hint


def password_strength(password: str):
    """(entropy_bits, acceptable). Same rule as the original script (16+ characters and 50+ bits),
    with a less gullible estimate: see password_feedback."""
    bits, ok, _hint = password_feedback(password)
    return bits, ok


# Lower-case letters and digits without the look-alikes (i l o 0 1): easy to read, type and dictate.
_PW_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def generate_password(groups: int = 5, group_len: int = 5) -> str:
    """A random password such as 'k7fqm-2xwhp-9rtbn-c3hnv-u8dze' from the operating system's
    random generator: about 4.95 bits per character, 124 bits with the defaults."""
    if groups < 1 or group_len < 1:
        raise ValueError("groups and group_len must be at least 1")
    return "-".join("".join(secrets.choice(_PW_ALPHABET) for _ in range(group_len)) for _ in range(groups))


def _resolve_output(path: str, policy: str, is_dir: bool = False) -> str:
    if not os.path.lexists(path):
        return path
    if policy == "overwrite":
        return path
    if policy == "skip":
        raise Skipped(f"'{os.path.basename(path)}' already exists")
    root, ext = (path, "") if is_dir else os.path.splitext(path)
    i = 1
    while True:
        cand = f"{root} ({i}){ext}"
        if not os.path.lexists(cand):
            return cand
        i += 1


def _atomic_replace(tmp_path: str, final_path: str):
    os.replace(tmp_path, final_path)
    parent = os.path.dirname(os.path.abspath(final_path))
    try:
        dir_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except (OSError, AttributeError):
        pass  # Windows cannot open directories this way


def _remove_any(path: str):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.lexists(path):
        os.remove(path)


# -- Key derivation ------------------------------------------------------------

def _check_kdf_params(time_cost: int, memory_cost: int, parallelism: int):
    """Refuse key settings outside the ceilings. Called before every key derivation."""
    if not (1 <= time_cost <= KDF_MAX_TIME_COST):
        raise FormatError(f"This file asks for {time_cost} key-derivation passes; the most this app "
                          f"accepts is {KDF_MAX_TIME_COST}. It may be damaged or tampered with.")
    if not (8192 <= memory_cost <= KDF_MAX_MEMORY_COST):
        raise FormatError(f"This file asks for {memory_cost // 1024} MB of memory for key derivation; "
                          f"this app accepts {8192 // 1024} to {KDF_MAX_MEMORY_COST // 1024} MB. "
                          "It may be damaged or tampered with.")
    if not (1 <= parallelism <= KDF_MAX_PARALLELISM):
        raise FormatError(f"This file asks for {parallelism} key-derivation threads; the most this app "
                          f"accepts is {KDF_MAX_PARALLELISM}. It may be damaged or tampered with.")


def derive_key(password: str, salt: bytes, time_cost: int, memory_cost: int,
               parallelism: int, keyfile_key: Optional[bytes] = None) -> bytearray:
    _check_kdf_params(time_cost, memory_cost, parallelism)
    try:
        raw = hash_secret_raw(
            secret=password.encode("utf-8"), salt=salt,
            time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism,
            hash_len=32, type=Type.ID,
        )
    except (MemoryError, HashingError):
        raise RuntimeError(
            "Not enough free RAM for this key setting. "
            "Choose 'Light' key strength, or close other programs."
        )
    if keyfile_key is not None:
        # Second factor: without the key file the Argon2id output alone opens nothing.
        raw = hmac.new(bytes(keyfile_key), _KEYFILE_MIX_LABEL + raw, hashlib.sha256).digest()
    return bytearray(raw)


def autotune_argon2(hooks: Hooks, target_ms: int = 300) -> dict:
    if AUTOTUNE_CACHE.exists():
        try:
            c = json.loads(AUTOTUNE_CACHE.read_text())
            if (1 <= int(c["time_cost"]) <= KDF_MAX_TIME_COST
                    and 8192 <= int(c["memory_cost"]) <= KDF_MAX_MEMORY_COST
                    and 1 <= int(c["parallelism"]) <= KDF_MAX_PARALLELISM):
                hooks.log(f"Using cached key settings ({int(c['memory_cost']) // 1024} MB)")
                return {k: int(c[k]) for k in ("time_cost", "memory_cost", "parallelism")}
        except Exception:
            pass
    parallelism, time_cost, memory_cost = min(4, _CORES), 3, 65536
    salt = os.urandom(16)
    elapsed_ms = 0.0
    while memory_cost <= KDF_MAX_MEMORY_COST:
        hooks.check()
        t0 = time.monotonic()
        hash_secret_raw(secret=b"benchmark", salt=salt, time_cost=time_cost,
                        memory_cost=memory_cost, parallelism=parallelism,
                        hash_len=32, type=Type.ID)
        elapsed_ms = (time.monotonic() - t0) * 1000
        if elapsed_ms >= target_ms:
            break
        memory_cost = min(memory_cost * 2, KDF_MAX_MEMORY_COST)
    result = {"time_cost": time_cost, "memory_cost": memory_cost, "parallelism": parallelism}
    hooks.log(f"Tuned key settings: {memory_cost // 1024} MB ({elapsed_ms:.0f} ms)")
    try:
        AUTOTUNE_CACHE.parent.mkdir(parents=True, exist_ok=True)
        AUTOTUNE_CACHE.write_text(json.dumps(result))
    except Exception:
        pass
    return result


# -- Key file (second factor) --------------------------------------------------

_KEYFILE_MIX_LABEL = b"ENCV-v8-keyfile\x01"
KEYFILE_EXTENSION = "encvkey"
KEYFILE_MAGIC = "ENCVKEY1"
KEYFILE_RANDOM_BYTES = 64
KEYFILE_MAX_SIZE = 64 << 20     # any file may serve as a key file, up to this size

_KEYFILE_HEADER_TEXT = (
    "# Cryptid key file. Keep it safe, and apart from your encrypted files.\n"
    "# Files protected with it can only be opened with this file AND the password.\n"
    "# If it is lost, that data is lost for good: keep a backup copy somewhere else.\n"
    "# You may copy it freely, but do not change the line below.\n")


def _parse_encvkey(data: bytes) -> Optional[bytes]:
    """The 64 random bytes of an Cryptid key file, or None if this is some other kind of file."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if not lines or lines[0] != KEYFILE_MAGIC:
        return None
    try:
        raw = bytes.fromhex("".join(lines[1:]))
    except ValueError:
        raw = b""
    if len(raw) != KEYFILE_RANDOM_BYTES:
        raise FormatError("This key file is damaged or incomplete. Use the original or a backup copy.")
    return raw


def load_keyfile(path: str) -> bytearray:
    """Digest (32 bytes) that stands for a key file.

    Cryptid key files are read in a form that survives copying through e-mail or editors
    (line endings, comments, spaces). Any other file also works, as in KeePass, but then every
    single byte counts: re-saving a photo or document changes the key.
    """
    shown = os.path.basename(path) or path
    try:
        st = os.stat(path)
    except OSError:
        raise FormatError(f"The key file '{shown}' cannot be found. Is the USB stick or folder connected?")
    if not stat.S_ISREG(st.st_mode):
        raise FormatError(f"'{shown}' is not a file.")
    if st.st_size == 0:
        raise FormatError(f"The key file '{shown}' is empty.")
    if st.st_size > KEYFILE_MAX_SIZE:
        raise FormatError(f"'{shown}' is too big to be a key file (limit {KEYFILE_MAX_SIZE >> 20} MB).")
    try:
        with open(path, "rb") as f:
            data = f.read(KEYFILE_MAX_SIZE + 1)
    except OSError as e:
        raise FormatError(f"The key file '{shown}' cannot be read: {e.strerror or e}")
    parsed = _parse_encvkey(data)
    material = (b"ENCV-keyfile-v1" + parsed) if parsed is not None else (b"ENCV-rawfile-v1" + data)
    return bytearray(hashlib.sha256(material).digest())


def keyfile_id(digest: bytes) -> str:
    """Short fingerprint to tell key files apart (shown to the user, reveals nothing useful)."""
    h = hashlib.sha256(b"ENCV-keyid\x01" + bytes(digest)).hexdigest()[:8].upper()
    return f"{h[:4]}-{h[4:]}"


def create_keyfile(path: str, extra_entropy: bytes = b"") -> str:
    """Write a new random key file and return its ID. Never overwrites anything.

    The 64 key bytes always come from the operating system's random generator. Whatever the user
    adds (mouse movements, typing) is mixed in on top, as in KeePass; it can only add to the
    randomness, never replace it, so a poor or predictable input cannot make the key weaker.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"The folder '{directory}' does not exist.")
    pool = hashlib.sha512(b"ENCV-user-entropy\x01" + bytes(extra_entropy)).digest()
    raw = hmac.new(os.urandom(64), pool + struct.pack(">Q", time.time_ns()) + secrets.token_bytes(32),
                   hashlib.sha512).digest()
    assert len(raw) == KEYFILE_RANDOM_BYTES
    body = _KEYFILE_HEADER_TEXT + KEYFILE_MAGIC + "\n" + "\n".join(
        raw[i:i + 16].hex() for i in range(0, len(raw), 16)) + "\n"
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise FileExistsError(f"'{os.path.basename(path)}' already exists. A key file is never overwritten.")
    ok = False
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(body.encode("ascii"))
            f.flush()
            os.fsync(f.fileno())
        written = load_keyfile(path)           # read it back: what is on disk must be what we mean
        expected = hashlib.sha256(b"ENCV-keyfile-v1" + raw).digest()
        if bytes(written) != expected:
            raise OSError("The key file could not be read back correctly.")
        ok = True
    finally:
        if not ok:
            try:
                os.remove(path)
            except OSError:
                pass
    _fsync_dir(directory)
    return keyfile_id(written)


def file_needs_keyfile(path: str) -> bool:
    """True if this .enc file was protected with a key file (reads only the first 8 bytes)."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return False
    return len(head) == 8 and head[:4] == FORMAT_MAGIC and head[5] == KDF_ARGON2ID_KEYFILE


def _zero(buf):
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def _keyfile_for(header: dict, keyfile_path: Optional[str], res: "Result") -> Optional[bytearray]:
    """The key file digest to use for this .enc file (None if it needs none). Runs before any key derivation."""
    if header["keyfile"]:
        if not keyfile_path:
            raise FormatError("This file is protected with a key file as well as a password. "
                              "Choose the key file that was used to encrypt it.")
        return load_keyfile(keyfile_path)
    if keyfile_path:
        res.warnings.append("A key file was chosen, but this file is protected by a password only, "
                            "so the key file was not used.")
    return None


# -- Nonce / AAD / header ------------------------------------------------------

def _chunk_nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">Q", counter)


def _aad_base(header: bytes) -> bytes:
    return hashlib.sha256(header).digest()


def _chunk_aad(base: bytes, counter: int) -> bytes:
    return base + struct.pack(">Q", counter)


def _build_header(codec, chunk_size, salt, nonce_prefix, orig_size,
                  time_cost, memory_cost, parallelism, kdf_id=KDF_ARGON2ID) -> bytes:
    hdr = (FORMAT_MAGIC + struct.pack("<BBBB", FORMAT_VERSION, kdf_id, CIPHER_AES_GCM, codec)
           + struct.pack("<IIII", chunk_size, time_cost, memory_cost, parallelism)
           + salt + nonce_prefix + struct.pack("<Q", orig_size))
    assert len(hdr) == HEADER_SIZE
    return hdr


def _parse_header(raw: bytes) -> dict:
    if len(raw) < HEADER_SIZE:
        raise FormatError("File too small - damaged or not made by this app.")
    magic = raw[0:4]
    version, kdf_id, cipher_id, codec = struct.unpack("<BBBB", raw[4:8])
    chunk_size, time_cost, memory_cost, parallelism = struct.unpack("<IIII", raw[8:24])
    salt, nonce_prefix = raw[24:40], raw[40:44]
    orig_size = struct.unpack("<Q", raw[44:52])[0]

    if magic != FORMAT_MAGIC:
        raise FormatError("Not an encrypted file from this app (missing ENCV marker).")
    if version != FORMAT_VERSION:
        raise FormatError(f"Unsupported format version {version}.")
    if kdf_id not in (KDF_ARGON2ID, KDF_ARGON2ID_KEYFILE) or cipher_id != CIPHER_AES_GCM:
        raise FormatError("Unknown key-derivation or cipher id.")
    if codec not in COMPRESS_NAMES:
        raise FormatError(f"Unknown compression codec {codec}.")
    if not (16 * 1024 <= chunk_size <= 16 * 1024 * 1024):
        raise FormatError(f"Suspicious chunk size {chunk_size}.")
    _check_kdf_params(time_cost, memory_cost, parallelism)   # before any key derivation
    if orig_size > MAX_ORIG_SIZE:
        raise FormatError(f"Suspicious original size {orig_size}.")
    return {"codec": codec, "keyfile": kdf_id == KDF_ARGON2ID_KEYFILE, "chunk_size": chunk_size,
            "time_cost": time_cost,
            "memory_cost": memory_cost, "parallelism": parallelism,
            "salt": salt, "nonce_prefix": nonce_prefix, "orig_size": orig_size}


# -- Limits for what an archive may do while it is read -------------------------

@dataclass
class Limits:
    """Upper bounds applied while decoding and restoring. The defaults are far above
    anything a real backup reaches; they exist so that a damaged or hostile file
    stops with a clear message instead of filling the disk or the memory."""
    max_total_bytes: int = MAX_ORIG_SIZE    # decoded stream, 1 TiB (same ceiling as the header check)
    max_file_bytes: int = MAX_ORIG_SIZE     # one file inside an archive
    max_entries: int = 2_000_000            # files + folders in one archive
    max_path_len: int = 4096                # characters in an archive path
    max_component_len: int = 255            # one name inside that path, in bytes
    max_depth: int = 128                    # folders deep
    max_header_bytes: int = 1 << 20         # one PAX / GNU long-name record (read into RAM)
    lzma_memlimit: int = 256 << 20          # decoder RAM; real files need about 9 MiB
    zstd_window: int = 1 << 27              # decoder window, 128 MiB (zstd's own default cap)
    free_space_margin: int = 16 << 20       # keep this much free after restoring
    max_seconds: Optional[float] = None     # wall-clock cap; off by default (restores can be long)


_STREAM_SLACK = 1 << 20                     # end-of-archive blocks and read-ahead
_READ_STEP = 1 << 20                        # how much is pulled through the decoder per read
_SALVAGE_STEP = 16 << 10                    # salvage reads in small steps: a read that hits the damage
                                            # returns nothing, so everything before it must be out already
_ENTRY_SLACK = 16 << 10                     # tar header + padding + PAX record per entry
_LINK_TYPES = (tarfile.SYMTYPE, tarfile.LNKTYPE)
_META_TYPES = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
               tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK)


def _show(name: str, n: int = 120) -> str:
    """A name from an untrusted archive, made safe to print."""
    s = name.encode("unicode_escape", "backslashreplace").decode("ascii", "replace")
    return s if len(s) <= n else s[:n] + "..."


def _add_warning(res: Result, msg: str, cap: int = 12):
    n = len(res.warnings)
    if n < cap:
        res.warnings.append(msg)
    elif n == cap:
        res.warnings.append("More warnings were left out.")


# -- Streaming helpers ---------------------------------------------------------

class _CountingReader:
    """Wraps a source: counts bytes, optionally hashes them, honours cancel, can cap the length."""

    def __init__(self, src, hooks: Hooks, on_bytes: Callable[[int], None],
                 limit: Optional[int] = None, digest=None):
        self._src, self._hooks, self._on_bytes = src, hooks, on_bytes
        self._limit, self._digest, self.count = limit, digest, 0

    def read(self, n=-1):
        self._hooks.check()
        if self._limit is not None:
            room = self._limit - self.count
            if room <= 0:
                return b""
            n = room if (n is None or n < 0) else min(n, room)
        data = self._src.read(n)
        self.count += len(data)
        if self._digest is not None:
            self._digest.update(data)
        self._on_bytes(self.count)
        return data


class _ChunkDecryptReader(io.RawIOBase):
    """Authenticates + decrypts one chunk at a time; stops at the verified terminal chunk."""

    def __init__(self, fin, aesgcm: AESGCM, aad_base: bytes, nonce_prefix: bytes,
                 chunk_size: int, hooks: Optional[Hooks] = None,
                 on_consumed: Optional[Callable[[int], None]] = None):
        self._fin, self._aesgcm, self._aad_base = fin, aesgcm, aad_base
        self._nonce_prefix, self._chunk_size = nonce_prefix, chunk_size
        self._hooks, self._on_consumed = hooks, on_consumed
        self._counter = 0
        self._consumed = 0
        self._buf = b""
        self.done = False

    def readable(self):
        return True

    def readinto(self, b):
        while not self._buf and not self.done:
            self._buf = self._next_chunk()
        if not self._buf:
            return 0
        n = min(len(b), len(self._buf))
        b[:n] = self._buf[:n]
        self._buf = self._buf[n:]
        return n

    def finish(self):
        """Read and authenticate everything up to the terminal chunk.

        Called after the decoder reached its end, so any plaintext still pending is unexpected.
        """
        extra = self._buf
        self._buf = b""
        while not self.done:
            extra += self._next_chunk()
        if extra:
            raise ValueError("Unexpected extra data after the end of the compressed stream.")

    def _read(self, n: int) -> bytes:
        try:
            return self._fin.read(n)
        except OSError as e:
            raise SourceReadError(f"The encrypted file could not be read at this point "
                                  f"({e.strerror or e}).") from e

    def _next_chunk(self) -> bytes:
        if self._hooks:
            self._hooks.check()
        raw_len = self._read(CHUNK_LEN_SIZE)
        if len(raw_len) < CHUNK_LEN_SIZE:
            raise ValueError("Unexpected end of file - the file is truncated.")
        chunk_len = struct.unpack("<I", raw_len)[0]
        if chunk_len < TAG_SIZE or chunk_len > self._chunk_size + TAG_SIZE:
            raise ValueError(f"Corrupt chunk length at chunk {self._counter}.")
        ct_and_tag = self._read(chunk_len)
        if len(ct_and_tag) < chunk_len:
            raise ValueError(f"Truncated chunk at chunk {self._counter}.")
        self._consumed += CHUNK_LEN_SIZE + chunk_len
        if self._on_consumed:
            self._on_consumed(self._consumed)

        if chunk_len == 8 + TAG_SIZE:  # possible terminal chunk
            try:
                plaintext = self._aesgcm.decrypt(
                    _chunk_nonce(self._nonce_prefix, TERMINAL_COUNTER), ct_and_tag,
                    _chunk_aad(self._aad_base, TERMINAL_COUNTER))
                if len(plaintext) == 8:
                    stored = struct.unpack("<Q", plaintext)[0]
                    if stored != self._counter:
                        raise ValueError(f"Chunk count mismatch ({stored} vs {self._counter}) - "
                                         "file truncated or spliced.")
                    if self._read(1):
                        raise ValueError("Unexpected data after the end of the file.")
                    self.done = True
                    return b""
            except InvalidTag:
                pass  # ordinary 8-byte data chunk

        plaintext = self._aesgcm.decrypt(
            _chunk_nonce(self._nonce_prefix, self._counter), ct_and_tag,
            _chunk_aad(self._aad_base, self._counter))
        self._counter += 1
        return plaintext


class _Guarded:
    """The decoded stream, with a hard cap on how much may come out of it.

    Also replays the bytes that were read to recognise a tar header, so nothing is lost
    (the original Decrypt.py dropped them), and applies cancel and the optional time limit.
    """

    def __init__(self, stream, hooks: Hooks, limit: int, deadline: Optional[float] = None):
        self._s, self._hooks, self.limit, self._deadline = stream, hooks, limit, deadline
        self.count = 0
        self._replay = b""

    def allow(self, n: int):
        self.limit += n

    def unread(self, data: bytes):
        self._replay = data + self._replay

    def read(self, n=-1):
        if n is None or n < 0:
            n = 1 << 20
        self._hooks.check()
        if self._deadline is not None and time.monotonic() > self._deadline:
            raise LimitExceeded("Decoding took longer than the time limit allows.")
        if self._replay:
            out, self._replay = self._replay[:n], self._replay[n:]
            return out
        data = self._s.read(n)
        self.count += len(data)
        if self.count > self.limit:
            raise LimitExceeded(
                "The data inside expands to more than the file's header says "
                f"({size_str(self.limit)} allowed). Stopped before it could fill the disk.")
        return data

    def close(self):
        pass


def _read_exact(stream, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


# -- Bounded decoders ----------------------------------------------------------

class _ZstdReader:
    def __init__(self, source, limits: Limits):
        if not ZSTD_AVAILABLE:
            raise RuntimeError("This file uses zstd but the 'zstandard' package is missing.")
        dctx = zstd.ZstdDecompressor(max_window_size=limits.zstd_window)
        self._r = dctx.stream_reader(source, closefd=False)

    def read(self, n=-1):
        try:
            return self._r.read(n)
        except zstd.ZstdError as e:
            raise ValueError(f"The compressed data is damaged or exceeds the decoder limits ({e}).")

    def close(self):
        try:
            self._r.close()
        except Exception:
            pass


class _LzmaReader:
    """Pull-based xz/lzma decoder: output per call is bounded, RAM is capped, truncation is an error."""

    def __init__(self, source, chunk_size: int, limits: Limits):
        self._src, self._chunk = source, chunk_size
        self._dec = lzma.LZMADecompressor(memlimit=limits.lzma_memlimit)

    def read(self, n=-1):
        if n is None or n < 0:
            n = 1 << 20
        out = b""
        try:
            while not out:
                if self._dec.eof:
                    if self._dec.unused_data:
                        raise ValueError("Unexpected data after the end of the compressed stream.")
                    return b""
                data = b""
                if self._dec.needs_input:
                    data = self._src.read(self._chunk)
                    if not data:
                        raise ValueError("The compressed data ends unexpectedly (truncated).")
                out = self._dec.decompress(data, max_length=n)
        except lzma.LZMAError as e:
            raise ValueError(f"The compressed data is damaged or needs too much memory ({e}).")
        return out

    def close(self):
        pass


class _LzmaCompressReader:
    def __init__(self, source, chunk_size: int):
        self._src, self._chunk = source, chunk_size
        self._c = lzma.LZMACompressor(preset=6)
        self._buf = b""
        self._done = False

    def read(self, n=-1):
        if n is None or n < 0:
            n = self._chunk
        while len(self._buf) < n and not self._done:
            chunk = self._src.read(self._chunk)
            if chunk:
                self._buf += self._c.compress(chunk)
            else:
                self._buf += self._c.flush()
                self._done = True
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        pass


def _make_compress_stream(source, codec: int, chunk_size: int, level: int):
    if codec == COMPRESS_ZSTD:
        cctx = zstd.ZstdCompressor(level=level, threads=-1)  # multi-core, same format
        return cctx.stream_reader(source, closefd=False)
    if codec == COMPRESS_LZMA:
        return _LzmaCompressReader(source, chunk_size)
    return source


def _make_decompress_stream(source, codec: int, chunk_size: int, limits: Limits):
    if codec == COMPRESS_ZSTD:
        return _ZstdReader(source, limits)
    if codec == COMPRESS_LZMA:
        return _LzmaReader(source, chunk_size, limits)
    return source


def _pick_codec(mode: str, is_dir: bool, src: str) -> int:
    if mode == "none":
        return COMPRESS_NONE
    if mode == "lzma":
        return COMPRESS_LZMA
    if mode == "auto" and not is_dir and Path(src).suffix.lower() in INCOMPRESSIBLE_EXT:
        return COMPRESS_NONE
    return COMPRESS_ZSTD if ZSTD_AVAILABLE else COMPRESS_LZMA


# -- Safe files: temp files, publishing, opening sources -------------------------

def _make_temp(directory: str):
    """Exclusive (O_EXCL), unpredictable name, mode 0600, never follows a planted link."""
    fd, path = tempfile.mkstemp(prefix=".encv-", suffix=".tmp", dir=directory)
    return fd, path


def _make_temp_dir(directory: str) -> str:
    # Mode 0700. The name is kept short: while restoring, every path inside is this much longer.
    return tempfile.mkdtemp(prefix=".encv-", dir=directory)


def _fsync_dir(directory: str):
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except (OSError, AttributeError):
        pass  # Windows cannot open directories this way


def _create_exclusive(path: str, mode: int = 0o600) -> int:
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    return os.open(path, flags, mode)


def _open_regular(path: str):
    """Open a file for reading without following a link, and only if it is a regular file."""
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file any more", path)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb"), st


def _link_noclobber(src: str, dst: str) -> bool:
    """Give `src` the extra name `dst`, failing with FileExistsError if anything is there.

    Returns True if `src` was renamed instead (file systems without hard links), in which
    case the old name is already gone.
    """
    try:
        os.link(src, dst)
        return False
    except FileExistsError:
        raise
    except OSError:
        pass  # FAT/exFAT, some network shares: no hard links
    if os.path.lexists(dst):
        raise FileExistsError(dst)
    os.rename(src, dst)  # Windows refuses to replace; elsewhere the check above is all we have
    return True


def _publish_file(tmp: str, directory: str, name: str, policy: str) -> str:
    """Move a finished temp file to its final name. Never replaces anything unless policy is 'overwrite'."""
    final = os.path.join(directory, name)
    if policy == "overwrite":
        if os.path.isdir(final) and not os.path.islink(final):
            shutil.rmtree(final)
        os.replace(tmp, final)          # replaces a link itself, never writes through it
        _fsync_dir(directory)
        return final
    root, ext = os.path.splitext(name)
    i = 0
    while True:
        cand = final if i == 0 else os.path.join(directory, f"{root} ({i}){ext}")
        try:
            moved = _link_noclobber(tmp, cand)
        except FileExistsError:
            if policy == "skip":
                raise Skipped(f"'{name}' already exists")
            i += 1
            continue
        if not moved:
            os.unlink(tmp)
        _fsync_dir(directory)
        return cand


def _publish_dir(item: str, directory: str, name: str, policy: str) -> str:
    final = os.path.join(directory, name)
    if os.path.lexists(final):
        if policy == "skip":
            raise Skipped(f"'{name}' already exists")
        if policy == "overwrite":
            _remove_any(final)
        else:
            final = _resolve_output(final, "rename", is_dir=True)
    os.rename(item, final)
    _fsync_dir(directory)
    return final


def _publish_tree(tmp_dir: str, out_dir: str, policy: str, res: Result) -> List[str]:
    kept = []
    for entry in sorted(os.listdir(tmp_dir)):
        item = os.path.join(tmp_dir, entry)
        try:
            if os.path.isdir(item) and not os.path.islink(item):
                kept.append(_publish_dir(item, out_dir, entry, policy))
            else:
                kept.append(_publish_file(item, out_dir, entry, policy))
        except Skipped:
            res.warnings.append(f"Skipped '{entry}' (already exists)")
    return kept


def _is_inside(child: str, parent: str) -> bool:
    try:
        c, p = os.path.realpath(child), os.path.realpath(parent)
        return os.path.commonpath([c, p]) == p
    except ValueError:  # different drives
        return False


def _check_free_space(directory: str, need: int, limits: Limits):
    probe = directory
    while probe and not os.path.isdir(probe) and os.path.dirname(probe) != probe:
        probe = os.path.dirname(probe)        # the folder may not exist yet: ask the nearest one that does
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return
    if need + limits.free_space_margin > free:
        raise LimitExceeded(f"Not enough free space in '{directory}': about {size_str(need)} needed, "
                            f"{size_str(free)} free. Nothing was written.")


def _translate_oserror(e: OSError) -> Optional[Exception]:
    if e.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", -1)):
        return LimitExceeded("The disk is full (or a quota was reached). Free some space or pick another "
                             "destination and try again. Nothing was left behind.")
    if e.errno == errno.ENAMETOOLONG or getattr(e, "winerror", None) == 206:
        return LimitExceeded("A file name or path is too long for this location. Choose a folder with a "
                             "shorter path (or a shorter name) and try again. Nothing was left behind.")
    return None


# -- Folder -> tar -------------------------------------------------------------

def _normalize_tarinfo(ti: tarfile.TarInfo) -> tarfile.TarInfo:
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti


def _scan_dir(target: str, skipped: List[str]):
    """Sorted list of (full_path, arcname, size, kind, mtime_ns). Raises on unreadable folders."""
    def _raise(err):
        raise err

    top = os.path.basename(os.path.abspath(target)) or "folder"
    entries = []
    for root, dirs, files in os.walk(target, onerror=_raise):
        keep = []
        for d in sorted(dirs):
            if os.path.islink(os.path.join(root, d)):
                skipped.append(os.path.join(root, d))
            else:
                keep.append(d)
        dirs[:] = keep
        rel = os.path.relpath(root, target)
        arc_root = top if rel == "." else top + "/" + rel.replace(os.sep, "/")
        n_files = 0
        for f in sorted(files):
            full = os.path.join(root, f)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):  # links, sockets, devices, pipes
                skipped.append(full)
                continue
            entries.append((full, arc_root + "/" + f, st.st_size, "file", st.st_mtime_ns))
            n_files += 1
        if n_files == 0 and not dirs:
            entries.append((root, arc_root, 0, "dir", 0))
    return entries


def _tar_stream(entries, hooks: Hooks, changed: List[str]):
    """Stream `entries` as a tar through a pipe. Files are opened without following links
    and the tar header is built from the open handle, so a swapped-in link is never read."""
    errors: list = []
    read_fd, write_fd = os.pipe()
    reader = os.fdopen(read_fd, "rb")
    writer = os.fdopen(write_fd, "wb")

    def _run():
        try:
            with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                for full, arc, size, kind, mtime_ns in entries:
                    if hooks.cancel.is_set():
                        break
                    try:
                        if kind == "dir":
                            ti = tar.gettarinfo(full, arcname=arc)
                            if ti is None or not ti.isdir():
                                raise OSError("is no longer a folder")
                            tar.addfile(_normalize_tarinfo(ti))
                        else:
                            f, st = _open_regular(full)
                            with f:
                                ti = tar.gettarinfo(arcname=arc, fileobj=f)
                                if ti.size < size:
                                    raise OSError("became smaller while being read")
                                if ti.size > size or st.st_mtime_ns != mtime_ns:
                                    changed.append(full)
                                ti.size = size          # the header size we promised
                                tar.addfile(_normalize_tarinfo(ti), f)
                    except OSError as e:
                        raise OSError(f"Cannot read '{full}': {e}") from e
                    finally:
                        tar.inodes.clear()   # never store hard links; every file carries its data
        except Exception as e:  # noqa: BLE001
            errors.append(e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return reader, t, errors


# -- Deleting originals --------------------------------------------------------

WIPE_CAVEAT = ("Overwriting is best-effort: on SSDs, USB sticks, copy-on-write or journaling file systems, "
               "synced folders and snapshots, older copies of the data can remain. "
               "Full-disk encryption is the reliable protection.")


def _write_pass(fd: int, size: int, pattern: Optional[bytes]):
    os.lseek(fd, 0, os.SEEK_SET)
    written = 0
    while written < size:
        n = min(1 << 20, size - written)
        buf = os.urandom(n) if pattern is None else pattern * n
        view = memoryview(buf)
        while view:
            view = view[os.write(fd, view):]
        written += n
    os.fsync(fd)


def _wipe_file(path: str):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
        # A link, or data that other names share: overwriting would damage those. Just remove the name.
        os.remove(path)
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        fst = os.fstat(fd)
        if (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise OSError(errno.EBUSY, "file was replaced while wiping", path)
        for pattern in (b"\x00", b"\xff", None):
            _write_pass(fd, fst.st_size, pattern)
        os.ftruncate(fd, 0)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.remove(path)


def _wipe_path(path: str):
    if os.path.islink(path) or not os.path.isdir(path):
        _wipe_file(path)
        return
    for root, dirs, files in os.walk(path, topdown=False):   # never follows links
        for f in files:
            _wipe_file(os.path.join(root, f))
        for d in dirs:
            p = os.path.join(root, d)
            os.remove(p) if os.path.islink(p) else os.rmdir(p)
    os.rmdir(path)


def _source_unchanged(src: str, is_dir: bool, snapshot) -> bool:
    try:
        if is_dir:
            now = [(e[0], e[2], e[4], e[3]) for e in _scan_dir(src, [])]
            return now == snapshot
        st = os.stat(src)
        return (st.st_size, st.st_mtime_ns) == snapshot
    except OSError:
        return False


def _dispose_original(src: str, is_dir: bool, mode: str, snapshot, changed: bool,
                      skipped: List[str], res: Result, hooks: Hooks):
    """Remove the original only when every precondition holds; otherwise keep it and say why."""
    res.original = "kept"
    if mode == "keep":
        return
    reason = None
    if skipped:
        reason = "some items (links or special files) were not included in the encrypted file"
    elif changed or not _source_unchanged(src, is_dir, snapshot):
        reason = "it changed while it was being encrypted"
    elif os.path.islink(src):
        reason = "it is a link"
    elif not os.path.isfile(res.output) or os.path.getsize(res.output) != res.out_size:
        reason = "the encrypted file is not as expected on disk"
    if reason:
        res.warnings.append(f"Original kept: {reason}.")
        return

    hooks.progress(1.0, "Removing original", force=True)
    try:
        if mode == "trash":
            _send2trash(src)
            res.original = "trashed"
        elif mode == "wipe":
            _wipe_path(src)
            res.original = "wiped"
            res.warnings.append(WIPE_CAVEAT)
        else:
            _remove_any(src)
            res.original = "deleted"
    except Exception as e:  # noqa: BLE001
        res.original = "kept" if mode == "trash" and os.path.exists(src) else "partly removed"
        res.warnings.append(
            f"The original could not be removed completely: {e}. "
            "The encrypted file was fully checked, so nothing is lost.")


# -- Verification of a freshly written file --------------------------------------

def _drop_cache(fd: int):
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)   # read it back from the disk, not from RAM
    except (AttributeError, OSError):
        pass


# -- Decoding an .enc file -------------------------------------------------------

class _Payload:
    """One .enc file opened for reading: key, chunk authentication, decoder, size guard."""

    def __init__(self, fin, raw_header: bytes, header: dict, hooks: Hooks, limits: Limits,
                 total: int, stage: str, password: Optional[str] = None,
                 aesgcm: Optional[AESGCM] = None, exact_len: Optional[int] = None,
                 span=(0.0, 0.99), keyfile_key: Optional[bytes] = None):
        self.hooks, self.header = hooks, header
        if aesgcm is None:
            hooks.progress(span[0], "Deriving key", force=True)
            key = derive_key(password, header["salt"], header["time_cost"],
                             header["memory_cost"], header["parallelism"], keyfile_key)
            aesgcm = AESGCM(bytes(key))
            for i in range(len(key)):
                key[i] = 0
            del key
        lo, hi = span
        self.reader = _ChunkDecryptReader(
            fin, aesgcm, _aad_base(raw_header), header["nonce_prefix"], header["chunk_size"], hooks,
            on_consumed=lambda n: hooks.progress(lo + (hi - lo) * min((HEADER_SIZE + n) / total, 1.0), stage))
        self.stream = _make_decompress_stream(self.reader, header["codec"], header["chunk_size"], limits)
        deadline = time.monotonic() + limits.max_seconds if limits.max_seconds else None
        if exact_len is not None:
            cap = exact_len
        else:
            cap = min(limits.max_total_bytes, header["orig_size"] + _STREAM_SLACK)
        self.guard = _Guarded(self.stream, hooks, cap, deadline)
        self.is_tar = False

    def sniff(self) -> bool:
        """Read the first 512 bytes (this also proves the password) and put them back."""
        prefix = _read_exact(self.guard, 512)
        self.is_tar = len(prefix) >= 262 and prefix[257:262] == b"ustar"
        self.guard.unread(prefix)
        return self.is_tar

    def drain(self):
        while True:
            self.hooks.check()
            if not self.guard.read(1 << 20):
                break

    def finish(self):
        """Run the stream to its end and authenticate the terminal chunk (completeness)."""
        self.drain()
        self.reader.finish()

    def close(self):
        try:
            self.stream.close()
        except Exception:
            pass


class _HashTap:
    """Hashes and counts everything read through it (used to check a freshly written file)."""

    def __init__(self, guard: _Guarded):
        self._g, self.digest, self.count = guard, hashlib.sha256(), 0

    def read(self, n=-1):
        data = self._g.read(n)
        self.digest.update(data)
        self.count += len(data)
        return data

    def allow(self, n: int):
        pass    # the exact length is known here, no allowance is needed

    def close(self):
        pass


def _roundtrip_check(path: str, raw_header: bytes, aesgcm: AESGCM, expected_len: int,
                     expected_sha: bytes, hooks: Hooks, lo: float, hi: float, tarred: bool = False):
    """Decrypt + decode the finished file completely and compare it with what was read.

    An archive is also walked with the very code that restores it, under the same limits, so a
    file that passes here is one decrypt_path will accept (names, depth, entry count, sizes).
    """
    total = max(os.path.getsize(path), 1)
    header = _parse_header(raw_header)
    try:
        with open(path, "rb") as f:
            _drop_cache(f.fileno())
            f.seek(HEADER_SIZE)
            pl = _Payload(f, raw_header, header, hooks, Limits(), total, "Verifying",
                          aesgcm=aesgcm, exact_len=expected_len, span=(lo, hi))
            tap = _HashTap(pl.guard)
            try:
                if tarred:
                    ex = _Extractor(None, tap, hooks, Limits(), Result(),
                                    written_cap=header["orig_size"] + _STREAM_SLACK)
                    ex.run()
                    if ex.ignored:
                        raise ValueError(f"{ex.ignored} item(s) inside would not be restored")
                    _check_size_match(header, ex.content, ex.links, True)
                while True:
                    hooks.check()
                    if not tap.read(1 << 20):
                        break
                pl.reader.finish()
            finally:
                pl.close()
        if tap.count != expected_len or tap.digest.digest() != expected_sha:
            raise ValueError("the decrypted data does not match what was read")
    except Cancelled:
        raise
    except (InvalidTag, ValueError, OSError) as e:
        why = str(e) or ("a block failed its integrity check" if isinstance(e, InvalidTag) else type(e).__name__)
        raise RuntimeError(f"Verification of the encrypted file failed ({why.rstrip('.')}). "
                           "The original was not touched.")


# -- Archive reading + safe extraction -----------------------------------------

def _tarinfo_class(max_header_bytes: int):
    class _SafeTarInfo(tarfile.TarInfo):
        def _proc_member(self, tarfile_):
            # tarfile reads PAX / long-name records completely into memory, whatever their size.
            if self.type in _META_TYPES and self.size > max_header_bytes:
                raise LimitExceeded(f"The archive has an oversized header record ({size_str(self.size)}).")
            return super()._proc_member(tarfile_)
    return _SafeTarInfo


_WINDOWS = os.name == "nt"
# A name inside an archive is split at '/' only (that is all this app ever writes). On Windows a
# backslash in it is therefore part of a Linux file name, and is replaced like any other character
# Windows cannot store: no component that reaches the file system contains a separator.
_WIN_BAD_CHARS = set('<>:"|?*\\/') | {chr(i) for i in range(32)}
_WIN_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$",
                 *(f"com{i}" for i in "123456789\u00b9\u00b2\u00b3"),
                 *(f"lpt{i}" for i in "123456789\u00b9\u00b2\u00b3")}


def _win_safe_name(part: str) -> str:
    """One path component made acceptable to Windows (which refuses a:b, 'aux', 'name.' ...)."""
    q = "".join("_" if c in _WIN_BAD_CHARS else c for c in part).rstrip(" .")
    if not q:
        q = "_"
    if q.split(".")[0].rstrip(" ").lower() in _WIN_RESERVED:    # "aux", "AUX.txt", "aux .txt"
        q = "_" + q
    return q


def _name_units(name: str, windows: bool) -> int:
    """Length of a name the way the file system counts it: UTF-16 units on Windows, bytes elsewhere."""
    if windows:
        return len(name.encode("utf-16-le", "surrogatepass")) // 2
    try:
        return len(name.encode("utf-8", "surrogateescape"))
    except UnicodeEncodeError:
        return len(name.encode("utf-8", "surrogatepass"))


def _fit_name(name: str, marker: str = "", windows: Optional[bool] = None, limit: int = 255) -> str:
    """name + marker, with the name shortened (its extension kept if possible) until the file
    system can store the result."""
    if windows is None:
        windows = _WINDOWS
    if _name_units(name + marker, windows) <= limit:
        return name + marker
    root, ext = os.path.splitext(name)
    if _name_units(ext + marker, windows) >= limit // 2:      # no real extension, just a long name with a dot
        root, ext = name, ""
    while root and _name_units(root + ext + marker, windows) > limit:
        root = root[:-1]
    return (root or "_") + ext + marker


def _safe_parts(name: str, limits: Limits, windows: Optional[bool] = None,
                fit: bool = False) -> Optional[List[str]]:
    """Split an archive path into safe components, or None if it must not be restored.

    Rejects absolute paths, '..' and NUL; limits path length and depth (LimitExceeded beyond them).
    With windows=True (the default on Windows) components Windows cannot store are renamed rather
    than dropped: an archive made on Linux must still restore completely. No component keeps a
    ':' or a backslash, so none can name a drive, a stream or another folder.
    A component longer than the file system allows raises LimitExceeded, or with fit=True (used
    when restoring) is shortened.
    """
    if windows is None:
        windows = _WINDOWS
    if "\x00" in name:
        return None
    if name.startswith("/"):
        return None
    if len(name) > limits.max_path_len:
        raise LimitExceeded(f"An entry has a path longer than {limits.max_path_len} characters.")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    if len(parts) > limits.max_depth:
        raise LimitExceeded(f"An entry is nested deeper than {limits.max_depth} folders.")
    if windows:
        parts = [_win_safe_name(p) for p in parts]
    for i, p in enumerate(parts):
        if _name_units(p, windows) > limits.max_component_len:
            if not fit:
                raise LimitExceeded(f"An entry has a name longer than the {limits.max_component_len} "
                                    f"{'characters' if windows else 'bytes'} a file system stores.")
            parts[i] = _fit_name(p, "", windows, limits.max_component_len)
    return parts


def _show_path(path: str, n: int = 160) -> str:
    """One of the user's own paths for a message: readable (accents stay), but nothing unprintable."""
    s = "".join(c if c.isprintable() else "?" for c in path)
    return s if len(s) <= n else s[:60] + " ... " + s[-(n - 65):]


def _preflight(entries, orig_size: int, limits: Limits):
    """Refuse, before any work, a source the restore step would not accept.

    The restore limits are deliberately strict (they also face damaged or hostile files), so the
    same limits are applied here: nothing may be written that this app would later refuse to open.
    """
    if orig_size > MAX_ORIG_SIZE:
        raise LimitExceeded(f"This is {size_str(orig_size)}; one encrypted file holds at most "
                            f"{size_str(MAX_ORIG_SIZE)}. Split it into smaller parts first.")
    if not entries:
        return
    if len(entries) > limits.max_entries:
        raise LimitExceeded(f"This folder holds {len(entries):,} items; one encrypted file holds at most "
                            f"{limits.max_entries:,}. Encrypt its subfolders separately.")
    for full, arc, size, _kind, _mtime in entries:
        try:
            # Names come from this file system, so they fit it (a system with a shorter limit shortens
            # them when restoring). Path length and depth are refused by the restore step: check those.
            parts = _safe_parts(arc, limits, windows=False, fit=True)
        except LimitExceeded as e:
            raise LimitExceeded(f"Cannot encrypt '{_show_path(full)}': {str(e)[0].lower()}{str(e)[1:]} "
                                "Shorten or flatten it and try again.") from None
        if parts is None:
            raise LimitExceeded(f"Cannot encrypt '{_show_path(full)}': its name cannot be stored safely.")
        if size > limits.max_file_bytes:
            raise LimitExceeded(f"Cannot encrypt '{_show_path(full)}': it is larger than "
                                f"{size_str(limits.max_file_bytes)}.")


class _Extractor:
    """Walks a tar stream and (optionally) restores it below `dest`.

    Restores regular files and folders only, created exclusively with private permissions.
    Links, devices and anything else are not restored. With dest=None nothing is written
    (verify mode) but every limit and check still applies.
    """

    def __init__(self, dest: Optional[str], guard: _Guarded, hooks: Hooks, limits: Limits,
                 res: Result, written_cap: int, keep_partial: bool = False,
                 windows: Optional[bool] = None):
        self.dest, self.guard, self.hooks, self.limits, self.res = dest, guard, hooks, limits, res
        self.written_cap = written_cap
        self.keep_partial = keep_partial   # salvage: keep the readable start of a file cut short by damage
        self.windows = _WINDOWS if windows is None else windows
        self.names: List[str] = []         # top-level names, in archive order
        self.partial_files: List[str] = []
        self.done_files = 0                # files written completely
        self.renamed = 0                   # entries renamed because this system cannot store their name
        self._dir_alias: dict = {}         # (parent, name) -> the name a folder got when a file had it
        self.files = self.folders = 0
        self.content = 0        # sum of the sizes of regular files listed in the archive
        self.written = 0        # bytes actually written (hard-link copies included)
        self.links = False      # the archive holds links (old archives from the original script)
        self.nested = False
        self.ignored = 0
        self._dirs: List = []
        self._parent = None

    # -- helpers
    def _ignore(self, name: str, why: str):
        self.ignored += 1
        _add_warning(self.res, f"Ignored {why}: {_show(name)}")

    def _ensure_dirs(self, parts: List[str]) -> str:
        path = self.dest
        for p in parts:
            cand = os.path.join(path, self._dir_alias.get((path, p), p))
            try:
                os.mkdir(cand, 0o700)
            except FileExistsError:
                if os.path.islink(cand) or not os.path.isdir(cand):
                    # A file already has this name: two names that differ only in case, or that
                    # became equal when they were adapted to this system. Keep both.
                    cand = self._unique(cand)
                    os.mkdir(cand, 0o700)
                    self._dir_alias[(path, p)] = os.path.basename(cand)
                    _add_warning(self.res, f"A file and a folder share the name '{_show(p)}'; the folder "
                                           f"was saved as '{_show(os.path.basename(cand))}'.")
            path = cand
        return path

    def _parent_dir(self, parts: List[str]) -> str:
        key = tuple(parts[:-1])
        if self._parent is None or self._parent[0] != key:
            self._parent = (key, self._ensure_dirs(parts[:-1]))
        return self._parent[1]

    @staticmethod
    def _unique(path: str) -> str:
        root, ext = os.path.splitext(path)
        i = 1
        while os.path.lexists(f"{root} ({i}){ext}"):
            i += 1
        return f"{root} ({i}){ext}"

    def _new_file(self, path: str):
        try:
            return path, _create_exclusive(path)
        except FileExistsError:
            alt = self._unique(path)
            _add_warning(self.res, f"Two entries share one name; the second was saved as '{os.path.basename(alt)}'.")
            return alt, _create_exclusive(alt)

    def _account(self, n: int):
        self.written += n
        if self.written > self.written_cap:
            raise LimitExceeded("The archive writes more data than the file's header says. "
                                "Stopped before it could fill the disk.")

    # -- entry kinds
    def _make_dir(self, parts, m):
        parent = self._ensure_dirs(parts)
        self._dirs.append((parent, m.mtime))

    def _write_file(self, tar, m, parts):
        path, fd = self._new_file(os.path.join(self._parent_dir(parts), parts[-1]))
        ok = False
        remaining = m.size
        try:
            with os.fdopen(fd, "wb") as out:
                src = tar.extractfile(m)
                step = _SALVAGE_STEP if self.keep_partial else _READ_STEP
                while remaining > 0:
                    self.hooks.check()
                    chunk = src.read(min(step, remaining))
                    if not chunk:
                        raise FormatError("The archive ends in the middle of a file.")
                    self._account(len(chunk))
                    out.write(chunk)
                    remaining -= len(chunk)
            ok = True
        finally:
            if not ok:
                self._drop_or_keep_partial(path, m.size - remaining)
        self._finish_file(path, m.mode, m.mtime)

    def _drop_or_keep_partial(self, path: str, got: int):
        """A file that could not be written completely: remove it, or (salvage) keep what was read.

        What is kept always ends in .partial. If it cannot be given that name it is removed, and if
        even that fails the error is raised: no restore is better than an unmarked piece of a file.
        """
        if self.keep_partial and got > 0:
            alt = os.path.join(os.path.dirname(path), _fit_name(os.path.basename(path), ".partial", self.windows))
            if os.path.lexists(alt):
                alt = self._unique(alt)
            try:
                os.rename(path, alt)
                self.partial_files.append(alt)
                return
            except OSError:
                pass
        try:
            os.remove(path)
        except OSError:
            if self.keep_partial:
                raise

    def _copy_link(self, m, parts):
        """Old archives store a second name for the same file as a hard link: restore it as a copy."""
        tparts = _safe_parts(m.linkname, self.limits, self.windows, fit=True)
        target = os.path.join(self.dest, *tparts) if tparts else None
        try:
            st = os.lstat(target) if target else None
        except OSError:
            st = None
        if st is None or not stat.S_ISREG(st.st_mode):
            self._ignore(m.name, "link to a file that is not in the archive")
            return
        path, fd = self._new_file(os.path.join(self._parent_dir(parts), parts[-1]))
        ok = False
        try:
            with os.fdopen(fd, "wb") as out, open(target, "rb") as src:
                while True:
                    self.hooks.check()
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    self._account(len(chunk))
                    out.write(chunk)
            ok = True
        finally:
            if not ok:
                try:
                    os.remove(path)
                except OSError:
                    pass
        self._finish_file(path, m.mode, m.mtime)

    @staticmethod
    def _set_mtime(path: str, mtime):
        try:
            t = max(0.0, min(float(mtime), 4102444800.0))
            os.utime(path, (t, t))
        except (OSError, OverflowError, ValueError):
            pass

    def _finish_file(self, path: str, mode: int, mtime):
        self.done_files += 1
        try:
            os.chmod(path, 0o600 | (mode & 0o100))   # private; keeps "runnable" for the owner
        except OSError:
            pass
        self._set_mtime(path, mtime)

    # -- main loop
    def run(self):
        tar_cls = _tarinfo_class(self.limits.max_header_bytes)
        try:
            with tarfile.open(fileobj=self.guard, mode="r|", tarinfo=tar_cls) as tar:
                for m in tar:
                    self.hooks.check()
                    if self.files + self.folders + self.ignored >= self.limits.max_entries:
                        raise LimitExceeded(f"The archive has more than {self.limits.max_entries:,} entries.")
                    self.guard.allow(_ENTRY_SLACK)
                    parts = _safe_parts(m.name, self.limits, self.windows, fit=True)
                    if parts is None:
                        if m.name not in ("", ".", "./"):
                            self._ignore(m.name, "unsafe entry")
                        continue
                    if parts != [p for p in m.name.split("/") if p not in ("", ".")]:
                        self.renamed += 1
                    if len(parts) > 1:
                        self.nested = True
                    if parts[0] not in self.names and len(self.names) < 50:
                        self.names.append(parts[0])
                    if m.isdir():
                        self.folders += 1
                        if self.dest:
                            self._make_dir(parts, m)
                    elif m.isreg() and not m.issparse():
                        if m.size > self.limits.max_file_bytes or self.content + m.size > self.written_cap:
                            raise LimitExceeded(f"'{_show(m.name)}' is larger than the file's header allows.")
                        self.files += 1
                        self.content += m.size
                        if self.dest:
                            self._write_file(tar, m, parts)
                    elif m.islnk():
                        self.links = True
                        if self.dest:
                            self._copy_link(m, parts)
                            self.files += 1
                        else:
                            self.files += 1
                    else:
                        self.links = self.links or m.issym()
                        self._ignore(m.name, "link or special entry (not restored)")
        except (tarfile.TarError, RecursionError, UnicodeError) as e:
            raise FormatError(f"The archive inside is damaged ({e}).") from e
        # folder timestamps last, deepest first, so writing files did not change them
        for path, mtime in reversed(self._dirs):
            self._set_mtime(path, mtime)
        if self.ignored > 12:
            self.res.warnings.append(f"{self.ignored} entries were not restored in total.")
        if self.renamed:
            self.res.warnings.append(
                f"{self.renamed} item{'s have names' if self.renamed != 1 else ' has a name'} this system "
                "cannot store (too long, or on Windows characters like : ? * and reserved names such as "
                "AUX); they were renamed or shortened.")


def _check_size_match(header: dict, content: int, links: bool, is_tar: bool):
    """The authenticated header records the original size; the decoded data must agree."""
    expected = header["orig_size"]
    ok = content <= expected if (is_tar and links) else content == expected
    if not ok:
        raise ValueError(f"Size mismatch: the file records {size_str(expected)} "
                         f"but {size_str(content)} came out. It may be damaged.")


# -- Encrypt -------------------------------------------------------------------

def encrypt_path(src: str, out_dir: Optional[str], password: str,
                 opts: EncryptOptions, hooks: Optional[Hooks] = None) -> Result:
    try:
        return _encrypt_path(src, out_dir, password, opts, hooks)
    except OSError as e:
        t = _translate_oserror(e)
        if t:
            raise t from e
        raise


def _encrypt_path(src: str, out_dir: Optional[str], password: str,
                  opts: EncryptOptions, hooks: Optional[Hooks]) -> Result:
    hooks = hooks or Hooks()
    res = Result()
    src = os.path.abspath(src)
    if not os.path.exists(src):
        raise FileNotFoundError(src)
    is_dir = os.path.isdir(src)
    if not is_dir and not os.path.isfile(src):
        raise ValueError("Only regular files and folders can be encrypted.")
    if not is_dir and read_magic(src) == FORMAT_MAGIC:
        raise AlreadyEncrypted("Already encrypted")
    if opts.after not in ("keep", "trash", "delete", "wipe"):
        raise ValueError(f"Unknown option for the original: {opts.after}")
    if opts.after == "trash" and not TRASH_AVAILABLE:
        raise ValueError("Moving to the Recycle Bin / Trash is not available here (send2trash is missing).")

    kf = load_keyfile(opts.keyfile) if opts.keyfile else None    # fail early, before any work
    out_dir = os.path.abspath(out_dir or os.path.dirname(src))
    os.makedirs(out_dir, exist_ok=True)
    if opts.after != "keep" and is_dir and _is_inside(out_dir, src):
        raise ValueError("The destination is inside the folder being encrypted. Removing the original "
                         "would remove the encrypted file too. Choose another destination.")
    ext = clean_extension(opts.extension)
    out_name = os.path.basename(src) + "." + ext
    if opts.hide_name:
        # Nothing about the original shows in the name; the real name travels inside (see below).
        out_name = secrets.token_hex(8) + "." + ext
    if opts.overwrite == "skip" and os.path.lexists(os.path.join(out_dir, out_name)):
        raise Skipped(f"'{out_name}' already exists")

    hooks.progress(0.0, "Reading", force=True)
    skipped: List[str] = []
    entries = None
    if is_dir:
        entries = _scan_dir(src, skipped)
        orig_size = sum(e[2] for e in entries)
        snapshot = [(e[0], e[2], e[4], e[3]) for e in entries]
    else:
        st0 = os.stat(src)
        orig_size = st0.st_size
        snapshot = (st0.st_size, st0.st_mtime_ns)
        if opts.hide_name or _looks_like_tar(src):
            # Wrapped in a one-entry archive: that is where the name (and date) of a file with a
            # hidden name is kept, and what keeps a real .tar restorable as a file.
            real = os.path.realpath(src)
            entries = [(real, os.path.basename(src), orig_size, "file", st0.st_mtime_ns)]
    tarred = entries is not None
    _preflight(entries, orig_size, Limits())
    for s in skipped[:10]:
        res.warnings.append(f"Not included (link or special file): {s}")
    if len(skipped) > 10:
        res.warnings.append(f"...and {len(skipped) - 10} more links or special files not included.")

    codec = _pick_codec(opts.compression, is_dir, src)
    level = 3 if opts.compression == "fast" else 10

    if opts.kdf_profile == "auto":
        hooks.progress(0.0, "Tuning key settings", force=True)
        params, chunk_size = autotune_argon2(hooks), CHUNK_SIZE
    elif opts.kdf_profile == "light":
        params, chunk_size = dict(KDF_PROFILES["light"]), CHUNK_SIZE_SMALL
    else:
        params, chunk_size = dict(KDF_PROFILES["strong"]), CHUNK_SIZE

    verify = opts.verify or opts.after != "keep"
    enc_hi = 0.85 if verify else 1.0

    hooks.check()
    hooks.progress(0.0, "Deriving key", force=True)
    salt, nonce_prefix = os.urandom(16), os.urandom(NONCE_PREFIX_LEN)
    key = derive_key(password, salt, keyfile_key=kf, **params)
    if kf is not None:
        _zero(kf)
    header = _build_header(codec, chunk_size, salt, nonce_prefix, orig_size, **params,
                           kdf_id=KDF_ARGON2ID_KEYFILE if opts.keyfile else KDF_ARGON2ID)
    aad_base = _aad_base(header)
    aesgcm = AESGCM(bytes(key))
    for i in range(len(key)):
        key[i] = 0
    del key

    tmp_path = None
    raw_src = comp_src = None
    tar_thread = None
    tar_errors: list = []
    changed_files: List[str] = []
    counter = 0
    try:
        if tarred:
            raw_src, tar_thread, tar_errors = _tar_stream(entries, hooks, changed_files)
            limit = None
        else:
            raw_src = open(src, "rb")
            limit = orig_size
        digest = hashlib.sha256()
        counting = _CountingReader(
            raw_src, hooks,
            lambda n: hooks.progress(enc_hi * min(n / max(orig_size, 1), 1.0), "Encrypting"),
            limit=limit, digest=digest)
        comp_src = _make_compress_stream(counting, codec, chunk_size, level)

        fd, tmp_path = _make_temp(out_dir)
        with os.fdopen(fd, "wb") as fout:
            fout.write(header)
            while True:
                plaintext = comp_src.read(chunk_size)
                if not plaintext or tar_errors:
                    break
                ct = aesgcm.encrypt(_chunk_nonce(nonce_prefix, counter), plaintext,
                                    _chunk_aad(aad_base, counter))
                fout.write(struct.pack("<I", len(ct)))
                fout.write(ct)
                counter += 1
            hooks.check()
            if tar_errors:
                raise RuntimeError(str(tar_errors[0]))
            if not tarred and counting.count != orig_size:
                raise RuntimeError("The file became smaller while it was being read. Try again.")
            term = aesgcm.encrypt(_chunk_nonce(nonce_prefix, TERMINAL_COUNTER),
                                  struct.pack("<Q", counter),
                                  _chunk_aad(aad_base, TERMINAL_COUNTER))
            fout.write(struct.pack("<I", len(term)))
            fout.write(term)
            fout.flush()
            os.fsync(fout.fileno())

        if verify:
            _roundtrip_check(tmp_path, header, aesgcm, counting.count, digest.digest(),
                             hooks, enc_hi, 1.0, tarred=tarred)
        hooks.check()
        out_path = _publish_file(tmp_path, out_dir, out_name, opts.overwrite)
        tmp_path = None
    finally:
        for s in (comp_src, raw_src):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        if tar_thread is not None:
            tar_thread.join(timeout=5)
        if tmp_path is not None:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    res.output = out_path
    res.in_size = orig_size
    res.out_size = os.path.getsize(out_path)
    if changed_files:
        res.warnings.append(f"{len(changed_files)} file(s) changed while being read; the encrypted copy "
                            "may be inconsistent. Run it again once nothing is writing to them.")
    _dispose_original(src, is_dir, opts.after, snapshot, bool(changed_files), skipped, res, hooks)
    hooks.progress(1.0, "Done", force=True)
    return res


# -- Decrypt -------------------------------------------------------------------

def _plain_name(name: str, known_ext) -> str:
    """Name of a decrypted single file: drop the extension if it is one we know, else add .dec."""
    low = name.lower()
    for ext in known_ext:
        suffix = "." + ext.lower().lstrip(".")
        if len(name) > len(suffix) and low.endswith(suffix):
            return name[:-len(suffix)]
    return name + ".dec"


def _weak_kdf_warning(header: dict, res: Result):
    if header["time_cost"] < KDF_MIN_TIME_COST or header["memory_cost"] < KDF_MIN_MEMORY_COST:
        res.warnings.append("This file was protected with weak key settings. Consider re-encrypting it.")


def decrypt_path(src: str, out_dir: Optional[str], password: str,
                 overwrite: str = "rename", hooks: Optional[Hooks] = None,
                 known_ext=(DEFAULT_EXTENSION,), limits: Optional[Limits] = None,
                 keyfile: Optional[str] = None, salvage: bool = False) -> Result:
    """Restore an encrypted file. Nothing is published unless every block and the end marker check out.

    salvage=True is for a file that is damaged (a bad sector, an interrupted download): instead of
    restoring nothing, it keeps what could be read and authenticated before the damage, clearly
    marked: a folder gets " (incomplete)" added to its name, and a file that is not known to be
    whole ends in ".partial". Result.partial is then True, and the result is saved under a new
    name whatever `overwrite` says. Every byte kept still passed its integrity check and the
    password must be right; what cannot be vouched for is only that nothing is missing.
    Nothing is recovered if the damage is in the first block (that is indistinguishable from a
    wrong password), and a file of less than 512 bytes is all or nothing.
    """
    try:
        return _decrypt_path(src, out_dir, password, overwrite, hooks, known_ext, limits or Limits(),
                             keyfile, salvage)
    except OSError as e:
        t = _translate_oserror(e)
        if t:
            raise t from e
        raise


def _mark_incomplete(tmp_dir: str):
    """Rename what a salvage produced so that every top-level item says it is not the whole thing:
    folders get " (incomplete)", files end in ".partial"."""
    for entry in sorted(os.listdir(tmp_dir)):
        item = os.path.join(tmp_dir, entry)
        if os.path.isdir(item) and not os.path.islink(item):
            marked = _fit_name(entry, " (incomplete)")
        elif entry.endswith(".partial"):
            continue
        else:
            marked = _fit_name(entry, ".partial")
        target = os.path.join(tmp_dir, marked)
        if os.path.lexists(target):
            target = _Extractor._unique(target)
        os.rename(item, target)


def _damage_text(e: Exception, pl: "_Payload", total: int) -> str:
    why = "a block failed its integrity check" if isinstance(e, InvalidTag) else str(e).rstrip(".")
    where = min(100, int(100 * (HEADER_SIZE + pl.reader._consumed) / max(total, 1)))
    return f"{why} (about {where}% into the file)"


def _decrypt_path(src, out_dir, password, overwrite, hooks, known_ext, limits, keyfile=None,
                  salvage=False) -> Result:
    hooks = hooks or Hooks()
    res = Result()
    src = os.path.abspath(src)
    if not os.path.isfile(src):
        raise FileNotFoundError(src)
    out_dir = os.path.abspath(out_dir or os.path.dirname(src))   # created only once there is something to write
    total = max(os.path.getsize(src), 1)
    res.in_size = total

    hooks.progress(0.0, "Reading", force=True)
    tmp_file = tmp_dir = None
    kept: List[str] = []
    damage: Optional[Exception] = None
    try:
        with open(src, "rb") as fin:
            raw_header = fin.read(HEADER_SIZE)
            header = _parse_header(raw_header)
            _weak_kdf_warning(header, res)
            kf = _keyfile_for(header, keyfile, res)
            _check_free_space(out_dir, header["orig_size"], limits)

            plain = _plain_name(os.path.basename(src), known_ext)

            try:
                pl = _Payload(fin, raw_header, header, hooks, limits, total, "Decrypting",
                              password=password, keyfile_key=kf)
            finally:
                if kf is not None:
                    _zero(kf)
            try:
                is_tar = pl.sniff()      # first read also proves the password
                if is_tar:
                    os.makedirs(out_dir, exist_ok=True)
                    tmp_dir = _make_temp_dir(out_dir)
                    ex = _Extractor(tmp_dir, pl.guard, hooks, limits, res,
                                    written_cap=header["orig_size"] + _STREAM_SLACK, keep_partial=salvage)
                    try:
                        ex.run()
                        pl.finish()
                        _check_size_match(header, ex.content, ex.links, True)
                    except LimitExceeded:
                        raise
                    except (InvalidTag, ValueError) as e:
                        if not salvage or not (ex.done_files or ex.partial_files):
                            raise
                        damage = e
                        note = f"{ex.done_files} complete file{'s' if ex.done_files != 1 else ''}"
                        if ex.partial_files:
                            note += f" and the start of {len(ex.partial_files)} more (.partial)"
                        res.warnings.append(f"Damaged: {_damage_text(e, pl, total)}. Recovered {note}; "
                                            "anything stored after the damage is missing.")
                    res.out_size = ex.written
                    res.names = list(ex.names)
                    res.files = ex.done_files
                else:
                    if overwrite == "skip" and os.path.lexists(os.path.join(out_dir, plain)):
                        raise Skipped(f"'{plain}' already exists")
                    os.makedirs(out_dir, exist_ok=True)
                    fd, tmp_file = _make_temp(out_dir)
                    written = 0
                    step = _SALVAGE_STEP if salvage else _READ_STEP
                    with os.fdopen(fd, "wb") as fout:
                        try:
                            while True:
                                hooks.check()
                                chunk = pl.guard.read(step)
                                if not chunk:
                                    break
                                fout.write(chunk)
                                written += len(chunk)
                            pl.finish()
                            _check_size_match(header, pl.guard.count, False, False)
                        except LimitExceeded:
                            raise
                        except (InvalidTag, ValueError) as e:
                            if not salvage or not written:
                                raise
                            damage = e
                            res.warnings.append(
                                f"Damaged: {_damage_text(e, pl, total)}. Recovered the first {size_str(written)} "
                                f"of {size_str(header['orig_size'])}; the rest is missing.")
                        fout.flush()
                        os.fsync(fout.fileno())
                    res.out_size = written
            finally:
                pl.close()

        hooks.check()
        res.partial = damage is not None
        if res.partial:
            overwrite = "rename"     # a partial result never replaces anything, and is never skipped
        if is_tar:
            if res.partial:          # make it impossible to mistake for a complete restore
                _mark_incomplete(tmp_dir)
            kept = _publish_tree(tmp_dir, out_dir, overwrite, res)
            shutil.rmtree(tmp_dir, ignore_errors=True)
            tmp_dir = None
            res.output = kept[0] if len(kept) == 1 else out_dir
        else:
            res.output = _publish_file(tmp_file, out_dir,
                                       _fit_name(plain, ".partial") if res.partial else plain, overwrite)
            tmp_file = None
    finally:
        if tmp_file and os.path.lexists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)

    hooks.progress(1.0, "Done", force=True)
    return res


# -- Verify (nothing is written) -----------------------------------------------

def verify_path(src: str, password: str, hooks: Optional[Hooks] = None,
                limits: Optional[Limits] = None, keyfile: Optional[str] = None) -> Result:
    """Fully check an .enc file without writing anything to disk.

    Checks, in order: header sanity, password, authentication of every chunk,
    the authenticated chunk count (truncation / splicing), that the compressed
    stream decodes completely within the limits, that the archive inside parses,
    and that the decoded size matches the size recorded in the (authenticated) header.
    """
    hooks = hooks or Hooks()
    limits = limits or Limits()
    res = Result()
    src = os.path.abspath(src)
    if not os.path.isfile(src):
        raise FileNotFoundError(src)
    total = max(os.path.getsize(src), 1)
    res.in_size = total

    hooks.progress(0.0, "Reading", force=True)
    with open(src, "rb") as fin:
        raw_header = fin.read(HEADER_SIZE)
        header = _parse_header(raw_header)
        _weak_kdf_warning(header, res)
        kf = _keyfile_for(header, keyfile, res)
        try:
            pl = _Payload(fin, raw_header, header, hooks, limits, total, "Verifying",
                          password=password, keyfile_key=kf)
        finally:
            if kf is not None:
                _zero(kf)
        try:
            if pl.sniff():
                ex = _Extractor(None, pl.guard, hooks, limits, res,
                                written_cap=header["orig_size"] + _STREAM_SLACK)
                ex.run()
                pl.finish()
                _check_size_match(header, ex.content, ex.links, True)
                res.files, res.folders = ex.files, ex.folders
                res.names = list(ex.names)
                res.is_folder = ex.nested or ex.folders > 0
                res.out_size = ex.content
                if ex.ignored:
                    res.warnings.append(f"{ex.ignored} entr{'y' if ex.ignored == 1 else 'ies'} "
                                        "would be ignored when decrypting.")
            else:
                pl.finish()
                _check_size_match(header, pl.guard.count, False, False)
                res.out_size = pl.guard.count
        finally:
            pl.close()
    hooks.progress(1.0, "Done", force=True)
    return res
