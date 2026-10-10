"""
Tests for the Cryptid engine.   Run:  python -m pytest tests

They check the promises the app makes: what was encrypted comes back byte for byte, nothing opens
without the right password (and key file), any change to an encrypted file is noticed, originals
are only removed after the copy was proven good, and a file the app wrote is a file it can restore.
"""

import hashlib
import hmac
import io
import os
import struct
import sys
import tarfile

import pytest
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cryptid_cli as cli      # noqa: E402
import cryptid_core as core    # noqa: E402

PW = "correct horse battery staple 42!"
WINDOWS = os.name == "nt"
# Windows refuses paths beyond 260 characters unless long paths are switched on.
needs_long_paths = pytest.mark.skipif(WINDOWS, reason="needs paths longer than Windows allows by default")


def opts(**kw):
    kw.setdefault("kdf_profile", "light")     # fast key derivation; the code path is the same
    return core.EncryptOptions(**kw)


def write(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return str(path)


def read(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def chunks_of(blob: bytes):
    out, i = [], core.HEADER_SIZE
    while i < len(blob):
        n = struct.unpack("<I", blob[i:i + 4])[0]
        out.append(blob[i:i + 4 + n])
        i += 4 + n
    return out


@pytest.fixture
def sample(tmp_path):
    data = os.urandom(700_000) + b"compressible " * 60_000
    return write(tmp_path / "src" / "report.bin", data), data


# -- an independent reader, written from FORMAT.md and sharing no code with the engine ---------

def reference_decrypt(blob: bytes, password: str, keyfile_digest: bytes = None) -> bytes:
    """Returns the decoded payload (still compressed if a codec was used). Raises on any mismatch."""
    assert blob[:4] == b"ENCV" and blob[4] == 8 and blob[6] == 1
    kdf_id = blob[5]
    chunk_size, t, m, p = struct.unpack("<IIII", blob[8:24])
    salt, prefix = blob[24:40], blob[40:44]
    key = hash_secret_raw(password.encode(), salt, time_cost=t, memory_cost=m, parallelism=p,
                          hash_len=32, type=Type.ID)
    if kdf_id == 2:
        key = hmac.new(keyfile_digest, b"ENCV-v8-keyfile\x01" + key, hashlib.sha256).digest()
    aad = hashlib.sha256(blob[:52]).digest()
    gcm, out, pos, counter = AESGCM(key), b"", 52, 0
    while True:
        n = struct.unpack("<I", blob[pos:pos + 4])[0]
        body = blob[pos + 4:pos + 4 + n]
        pos += 4 + n
        if pos == len(blob):       # last record: the end marker carries the number of chunks
            last = gcm.decrypt(prefix + b"\xff" * 8, body, aad + b"\xff" * 8)
            assert struct.unpack("<Q", last)[0] == counter
            return out
        out += gcm.decrypt(prefix + struct.pack(">Q", counter), body, aad + struct.pack(">Q", counter))
        counter += 1


def test_format_is_plain_aes_gcm_and_argon2id(tmp_path):
    data = os.urandom(1_200_000)
    src = write(tmp_path / "a.bin", data)
    r = core.encrypt_path(src, str(tmp_path / "o"), PW, opts(compression="none"))
    assert reference_decrypt(read(r.output), PW) == data
    with pytest.raises(InvalidTag):
        reference_decrypt(read(r.output), PW + "x")


def test_format_with_key_file(tmp_path):
    data = os.urandom(50_000)
    src = write(tmp_path / "a.bin", data)
    kf = str(tmp_path / "k.encvkey")
    core.create_keyfile(kf)
    raw = bytes.fromhex("".join(ln for ln in open(kf).read().split("\n")
                                if ln and not ln.startswith("#") and ln != "ENCVKEY1"))
    digest = hashlib.sha256(b"ENCV-keyfile-v1" + raw).digest()
    r = core.encrypt_path(src, str(tmp_path / "o"), PW, opts(compression="none", keyfile=kf))
    assert reference_decrypt(read(r.output), PW, digest) == data


# -- round trips ------------------------------------------------------------------------------

@pytest.mark.parametrize("compression", ["auto", "fast", "lzma", "none"])
def test_roundtrip_sizes_around_every_boundary(tmp_path, compression):
    for size in (0, 1, 7, 8, 9, 511, 512, 513, 65535, 65536, 65537, 200_000):
        data = os.urandom(size // 2) + b"A" * (size - size // 2)
        src = write(tmp_path / "in" / f"f{size}.bin", data)
        r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(compression=compression))
        assert core.verify_path(r.output, PW).out_size == size
        out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
        assert read(out.output) == data
        assert os.path.basename(out.output) == f"f{size}.bin"


def test_strong_profile_and_large_chunks(tmp_path):
    data = os.urandom(1_200_000)
    src = write(tmp_path / "a.bin", data)
    r = core.encrypt_path(src, str(tmp_path / "o"), PW, core.EncryptOptions())
    assert read(core.decrypt_path(r.output, str(tmp_path / "d"), PW).output) == data


def test_folder_roundtrip(tmp_path):
    root = tmp_path / "Proj"
    files = {"a/one.txt": b"1" * 10, "a/b/two.bin": os.urandom(300_000), "üñí – 文件.txt": b"unicode",
             "a/zero": b"", "a/b/" + "L" * (40 if WINDOWS else 200) + ".txt": b"long name"}
    for rel, data in files.items():
        write(root / rel, data)
    os.makedirs(root / "empty")
    os.utime(root / "a" / "one.txt", (1_500_000_000, 1_500_000_000))
    if hasattr(os, "symlink"):
        try:
            os.symlink("/etc/passwd", root / "link")
        except OSError:
            pass
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts())
    blob = read(r.output)
    assert b"a/b/two.bin" not in blob and b"Proj/a" not in blob  # names inside are encrypted
    v = core.verify_path(r.output, PW)
    assert v.is_folder and v.files == len(files) and v.names == ["Proj"]
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
    for rel, data in files.items():
        assert read(os.path.join(out.output, *rel.split("/"))) == data
    assert os.path.isdir(os.path.join(out.output, "empty"))
    assert int(os.stat(os.path.join(out.output, "a", "one.txt")).st_mtime) == 1_500_000_000
    assert not os.path.lexists(os.path.join(out.output, "link"))   # links are never stored or restored


def test_tar_file_comes_back_as_a_file(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("evil/../../escape.txt")
        ti.size = 3
        tf.addfile(ti, io.BytesIO(b"abc"))
    src = write(tmp_path / "in" / "backup.tar", buf.getvalue())
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts())
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
    assert os.path.isfile(out.output) and read(out.output) == buf.getvalue()
    assert not os.path.exists(tmp_path / "escape.txt")


# -- it really is encrypted --------------------------------------------------------------------

def test_ciphertext_shows_nothing_and_never_repeats(tmp_path):
    data = b"TOP-SECRET-MARKER " * 20_000
    src = write(tmp_path / "s.txt", data)
    a = read(core.encrypt_path(src, str(tmp_path / "1"), PW, opts(compression="none")).output)
    b = read(core.encrypt_path(src, str(tmp_path / "2"), PW, opts(compression="none")).output)
    assert b"SECRET" not in a
    assert len(set(a[52:])) == 256                      # every byte value occurs: no visible structure
    assert a[24:40] != b[24:40]                         # fresh salt -> fresh key for every file
    assert sum(x == y for x, y in zip(a[52:], b[52:])) < len(a) // 50


@pytest.mark.parametrize("bad", ["", "x", PW[:-1], PW + " ", PW.upper(), PW.replace("c", "C", 1)])
def test_wrong_password_opens_nothing(tmp_path, sample, bad):
    src, _ = sample
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts())
    with pytest.raises(InvalidTag):
        core.decrypt_path(r.output, str(tmp_path / "out"), bad, salvage=True)
    assert not os.path.exists(tmp_path / "out") or not os.listdir(tmp_path / "out")


def test_any_flipped_bit_is_noticed(tmp_path):
    src = write(tmp_path / "a.bin", os.urandom(150_000))
    blob = read(core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(compression="none")).output)
    positions = list(range(core.HEADER_SIZE + 4)) + [60, 100, len(blob) // 2, len(blob) - 29,
                                                    len(blob) - 28, len(blob) - 20, len(blob) - 1]
    t = str(tmp_path / "t.enc")
    for pos in positions:
        bad = bytearray(blob)
        bad[pos] ^= 1
        write(t, bytes(bad))
        with pytest.raises((InvalidTag, ValueError)):
            core.verify_path(t, PW)


def test_truncation_reordering_and_splicing_are_noticed(tmp_path):
    src = write(tmp_path / "a.bin", os.urandom(400_000))
    o = opts(compression="none")
    blob = read(core.encrypt_path(src, str(tmp_path / "1"), PW, o).output)
    other = chunks_of(read(core.encrypt_path(src, str(tmp_path / "2"), PW, o).output))
    head, ch = blob[:52], chunks_of(blob)
    assert len(ch) >= 5
    cases = {
        "end marker removed": head + b"".join(ch[:-1]),
        "last data chunk removed": head + b"".join(ch[:-2] + ch[-1:]),
        "cut in the middle": blob[:len(blob) // 2],
        "header only": head,
        "empty": b"",
        "junk appended": blob + b"\0",
        "two chunks swapped": head + b"".join([ch[0], ch[2], ch[1]] + ch[3:]),
        "chunk dropped": head + b"".join(ch[:1] + ch[2:]),
        "chunk repeated": head + b"".join(ch[:2] + [ch[1]] + ch[2:]),
        "chunk from another file, same password": head + b"".join([ch[0], other[1]] + ch[2:]),
    }
    t = str(tmp_path / "t.enc")
    for name, data in cases.items():
        write(t, data)
        with pytest.raises((InvalidTag, ValueError)):
            core.verify_path(t, PW)
            pytest.fail(f"not noticed: {name}")


def test_header_cannot_demand_absurd_key_settings(tmp_path):
    src = write(tmp_path / "a.bin", b"x" * 1000)
    blob = read(core.encrypt_path(src, str(tmp_path / "enc"), PW, opts()).output)
    t = str(tmp_path / "t.enc")
    for offset, value in ((16, 4 * 1024 * 1024), (12, 999), (20, 255), (16, 8)):
        bad = bytearray(blob)
        bad[offset:offset + 4] = struct.pack("<I", value)
        write(t, bytes(bad))
        with pytest.raises(core.FormatError):
            core.verify_path(t, PW)
    bad = bytearray(blob)                               # weaker but allowed settings: a different key, so no entry
    bad[16:20] = struct.pack("<I", 8192)
    write(t, bytes(bad))
    with pytest.raises(InvalidTag):
        core.verify_path(t, PW)


# -- key file ------------------------------------------------------------------------------------

def test_key_file_is_a_real_second_factor(tmp_path, sample):
    src, data = sample
    kf, kf2 = str(tmp_path / "k.encvkey"), str(tmp_path / "k2.encvkey")
    core.create_keyfile(kf, b"mouse")
    core.create_keyfile(kf2, b"mouse")
    assert read(kf) != read(kf2)
    with pytest.raises(FileExistsError):
        core.create_keyfile(kf)
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(keyfile=kf))
    assert core.file_needs_keyfile(r.output)
    assert core.verify_path(r.output, PW, keyfile=kf).out_size == len(data)
    with pytest.raises(core.FormatError):
        core.verify_path(r.output, PW)
    with pytest.raises(InvalidTag):
        core.verify_path(r.output, PW, keyfile=kf2)
    with pytest.raises(InvalidTag):
        core.verify_path(r.output, "wrong password, right file", keyfile=kf)
    blob = bytearray(read(r.output))
    blob[5] = core.KDF_ARGON2ID                          # claim that no key file is needed
    t = write(tmp_path / "t.enc", bytes(blob))
    with pytest.raises(InvalidTag):
        core.verify_path(t, PW)
    crlf = write(tmp_path / "mailed.encvkey", read(kf).replace(b"\n", b"\r\n") + b"  \r\n")
    assert core.verify_path(r.output, PW, keyfile=crlf).out_size == len(data)


# -- originals -----------------------------------------------------------------------------------

@pytest.mark.parametrize("after", ["delete", "wipe"])
def test_original_removed_only_after_the_copy_was_proven(tmp_path, monkeypatch, after):
    data = os.urandom(90_000)
    src = write(tmp_path / "in" / "a.bin", data)

    def broken(*a, **k):
        raise RuntimeError("Verification of the encrypted file failed")
    real = core._roundtrip_check
    monkeypatch.setattr(core, "_roundtrip_check", broken)
    with pytest.raises(RuntimeError):
        core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(after=after, verify=False))
    assert read(src) == data and os.listdir(tmp_path / "enc") == []     # original kept, no half result

    monkeypatch.setattr(core, "_roundtrip_check", real)
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(after=after))
    assert not os.path.exists(src)
    assert read(core.decrypt_path(r.output, str(tmp_path / "dec"), PW).output) == data


@pytest.mark.parametrize("compression", ["none", "fast", "lzma"])
@pytest.mark.parametrize("how", ["flip a byte", "cut the end marker", "append junk", "other content"])
def test_read_back_check_catches_a_bad_copy_and_keeps_the_original(tmp_path, monkeypatch, how, compression):
    """The real check runs here (only the file it reads is spoiled first). With compression the
    decoder is finished before the end marker is reached, so the marker has to be checked on its own."""
    data = os.urandom(300_000)
    src = write(tmp_path / "in" / "a.bin", data)
    real = core._roundtrip_check

    def spoil_then_check(path, raw_header, aesgcm, expected_len, expected_sha, *a, **k):
        blob = bytearray(read(path))
        if how == "flip a byte":
            blob[len(blob) // 2] ^= 1
        elif how == "cut the end marker":
            del blob[-28:]
        elif how == "append junk":
            blob += b"\0"
        else:                                   # every block authentic, but not the data that was read
            expected_sha = hashlib.sha256(b"something else").digest()
        write(path, bytes(blob))
        return real(path, raw_header, aesgcm, expected_len, expected_sha, *a, **k)
    monkeypatch.setattr(core, "_roundtrip_check", spoil_then_check)
    with pytest.raises(RuntimeError, match="Verification"):
        core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(after="delete", compression=compression))
    assert read(src) == data and os.listdir(tmp_path / "enc") == []


def test_read_back_check_refuses_an_archive_with_an_entry_it_would_not_restore(tmp_path, monkeypatch):
    root = tmp_path / "in" / "Proj"
    write(root / "keep.txt", b"1")
    write(root / "lost.txt", b"2")
    real = core._safe_parts
    monkeypatch.setattr(core, "_preflight", lambda *a, **k: None)
    monkeypatch.setattr(core, "_safe_parts",
                        lambda name, *a, **k: None if name.endswith("lost.txt") else real(name, *a, **k))
    with pytest.raises(RuntimeError, match="would not be restored"):
        core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(after="delete"))
    assert os.path.exists(root / "lost.txt") and os.listdir(tmp_path / "enc") == []


def test_preflight_limits():
    lim = core.Limits(max_entries=3, max_file_bytes=1000)
    entry = ("/src/Top/f", "Top/f", 10, "file", 0)
    core._preflight([entry] * 3, 30, lim)
    core._preflight(None, core.MAX_ORIG_SIZE, lim)
    with pytest.raises(core.LimitExceeded, match="at most"):
        core._preflight(None, core.MAX_ORIG_SIZE + 1, lim)
    with pytest.raises(core.LimitExceeded, match="4 items"):
        core._preflight([entry] * 4, 40, lim)
    with pytest.raises(core.LimitExceeded, match="larger than"):
        core._preflight([("/src/Top/big", "Top/big", 1001, "file", 0)], 1001, lim)
    with pytest.raises(core.LimitExceeded, match="nested deeper"):
        core._preflight([("/src/deep", "/".join(["d"] * 129), 1, "file", 0)], 1, core.Limits())


def test_existing_files_are_never_replaced_by_default(tmp_path, sample):
    src, data = sample
    a = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts())
    b = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts())
    assert a.output != b.output
    with pytest.raises(core.Skipped):
        core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(overwrite="skip"))
    assert not [f for f in os.listdir(tmp_path / "enc") if f.startswith(".encv-")]
    core.decrypt_path(a.output, str(tmp_path / "dec"), PW)
    second = core.decrypt_path(a.output, str(tmp_path / "dec"), PW)
    assert os.path.basename(second.output) == "report (1).bin" and read(second.output) == data


# -- a file this app writes is a file this app restores --------------------------------------------

@pytest.mark.parametrize("name", ["C: backup", "a:b", "x:"])
def test_folder_named_like_a_drive_letter(tmp_path, name):
    if os.name == "nt":
        pytest.skip("Windows cannot create such a folder")
    root = tmp_path / name
    write(root / "f.txt", b"hello")
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts())
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
    assert read(os.path.join(out.output, "f.txt")) == b"hello"


@needs_long_paths
def test_too_deep_folder_is_refused_before_encrypting_not_after(tmp_path):
    root = tmp_path / "Deep"
    p = root
    for _ in range(core.Limits().max_depth + 2):
        p = p / "d"
    write(p / "f.txt", b"x")
    with pytest.raises(core.LimitExceeded):
        core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(after="delete"))
    assert os.path.exists(p / "f.txt")
    assert not os.path.exists(tmp_path / "enc") or os.listdir(tmp_path / "enc") == []


@needs_long_paths
def test_check_after_encrypting_uses_the_restore_rules(tmp_path, monkeypatch):
    """Even if the early check missed something, the read-back must refuse what decrypt would refuse."""
    root = tmp_path / "Deep"
    p = root
    for _ in range(core.Limits().max_depth + 2):
        p = p / "d"
    write(p / "f.txt", b"x")
    monkeypatch.setattr(core, "_preflight", lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="Verification"):
        core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(after="delete"))
    assert os.path.exists(p / "f.txt") and os.listdir(tmp_path / "enc") == []


def test_names_windows_refuses_are_renamed_not_lost(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("Windows cannot create these names")
    root = tmp_path / "Notes"
    files = {"ok.txt": b"1", "meeting 10:30.txt": b"22", "aux.txt": b"333", "what?.md": b"4444", "dot.": b"55555"}
    for n, d in files.items():
        write(root / n, d)
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts())
    monkeypatch.setattr(core, "_WINDOWS", True)          # restore as Windows would
    assert core.verify_path(r.output, PW).files == len(files)
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
    got = {n: read(os.path.join(out.output, n)) for n in os.listdir(out.output)}
    assert got == {"ok.txt": b"1", "meeting 10_30.txt": b"22", "_aux.txt": b"333", "what_.md": b"4444", "dot": b"55555"}
    assert any("renamed" in w for w in out.warnings)


def test_safe_parts():
    lim = core.Limits()
    for bad in ("/etc/passwd", "a/../b", "..", "", ".", "a\0b"):
        assert core._safe_parts(bad, lim, windows=False) is None
    assert core._safe_parts("a/./b//c", lim, windows=False) == ["a", "b", "c"]
    assert core._safe_parts("C:/x", lim, windows=False) == ["C:", "x"]
    # On Windows only '/' separates: a backslash is part of a Linux file name and is replaced, so
    # nothing in a name can reach another folder, a drive, a share or a stream.
    assert core._safe_parts("C:\\Windows\\x", lim, windows=True) == ["C__Windows_x"]
    assert core._safe_parts("\\\\server\\share\\x", lim, windows=True) == ["__server_share_x"]
    assert core._safe_parts("a\\..\\b", lim, windows=True) == ["a_.._b"]
    assert core._safe_parts("top/..\\x", lim, windows=True) == ["top", ".._x"]
    assert core._safe_parts("a/..\\/b", lim, windows=True) == ["a", ".._", "b"]
    assert core._safe_parts("f.txt:stream", lim, windows=True) == ["f.txt_stream"]
    assert core._safe_parts("NUL/com1.txt/ok ", lim, windows=True) == ["_NUL", "_com1.txt", "ok"]
    assert core._safe_parts("aux .txt/.. /x?.", lim, windows=True) == ["_aux .txt", "_", "x_"]
    assert core._safe_parts("CONIN$/COM\u00b9.log/...", lim, windows=True) == ["_CONIN$", "_COM\u00b9.log", "_"]
    for name in ("..", "a/..", "../x", "a/../../x"):
        assert core._safe_parts(name, lim, windows=True) is None
    for parts in (core._safe_parts(n, lim, windows=True) for n in ("x/. ./y", "x/.. ./y", "x/ /y", "\\", ":")):
        assert parts and all(p not in (".", "..") and p == p.rstrip(" .") and p for p in parts)


def test_names_too_long_for_this_system_are_shortened_not_refused():
    lim = core.Limits()
    cjk = "\u5831" * 90 + ".txt"                       # 94 characters: fine on Windows, 274 bytes elsewhere
    assert core._safe_parts(cjk, lim, windows=True, fit=True) == [cjk]
    with pytest.raises(core.LimitExceeded):
        core._safe_parts(cjk, lim, windows=False)
    (short,) = core._safe_parts(cjk, lim, windows=False, fit=True)
    assert short.endswith(".txt") and len(short.encode()) <= 255 and cjk.startswith(short[:-4])
    (res,) = core._safe_parts("aux." + "a" * 251, lim, windows=True, fit=True)     # grows by the '_' prefix
    assert res.startswith("_aux.") and len(res) == 255
    assert core._fit_name("a" * 250, ".partial", windows=False) == "a" * 247 + ".partial"
    assert core._fit_name("b" * 240 + ".jpeg", " (incomplete)", windows=False).endswith(".jpeg (incomplete)")


def test_restoring_on_windows_keeps_every_file_from_a_linux_folder(tmp_path, monkeypatch):
    """Names only Linux allows (backslashes, a file and a folder that become the same name) must not
    cost the restore: everything comes back, renamed where it has to be."""
    if WINDOWS:
        pytest.skip("Windows cannot create these names")
    root = tmp_path / "Top"
    files = {"..\\x": b"1", "a\\..\\b": b"22", "\\report.txt": b"333", "x:": b"4444",
             "x_/inside.txt": b"55555", "plain.txt": b"666666"}
    for n, d in files.items():
        write(root / n, d)
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(after="delete"))
    assert not os.path.exists(root)
    monkeypatch.setattr(core, "_WINDOWS", True)
    assert core.verify_path(r.output, PW).files == len(files)
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
    got = {}
    for base, _dirs, names in os.walk(out.output):
        for n in names:
            got[os.path.relpath(os.path.join(base, n), out.output)] = read(os.path.join(base, n))
    assert sorted(got.values(), key=len) == sorted(files.values(), key=len)          # nothing lost
    assert not out.partial and ".._x" in got and "_report.txt" in got and "plain.txt" in got
    assert not [n for n in got if "\\" in n or ":" in n]
    assert any("renamed" in w for w in out.warnings)
    assert not os.path.exists(tmp_path / "x") and not os.path.exists(tmp_path / "dec" / "x")



# -- hidden names ----------------------------------------------------------------------------------

def test_hidden_name_file(tmp_path):
    data = os.urandom(120_000)
    src = write(tmp_path / "in" / "Tax return 2025.pdf", data)
    os.utime(src, (1_600_000_000, 1_600_000_000))
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(hide_name=True))
    name = os.path.basename(r.output)
    assert name.endswith(".enc") and len(name) == 16 + 4 and set(name[:16]) <= set("0123456789abcdef")
    assert b"Tax return" not in read(r.output)
    v = core.verify_path(r.output, PW)
    assert v.names == ["Tax return 2025.pdf"] and not v.is_folder and v.out_size == len(data)
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
    assert os.path.basename(out.output) == "Tax return 2025.pdf" and read(out.output) == data
    assert int(os.stat(out.output).st_mtime) == 1_600_000_000


def test_hidden_name_folder_and_delete(tmp_path):
    root = tmp_path / "in" / "Client Acme"
    write(root / "contract.txt", b"secret terms")
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(hide_name=True, after="delete"))
    assert "Acme" not in os.path.basename(r.output) and not os.path.exists(root)
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW)
    assert os.path.basename(out.output) == "Client Acme"
    assert read(os.path.join(out.output, "contract.txt")) == b"secret terms"


def test_hidden_names_do_not_collide(tmp_path, sample):
    src, _ = sample
    names = {os.path.basename(core.encrypt_path(src, str(tmp_path / "enc"), PW,
                                                opts(hide_name=True, verify=False)).output) for _ in range(5)}
    assert len(names) == 5 and not [n for n in names if "report" in n or "(" in n or len(n) != 20]


# -- salvage -----------------------------------------------------------------------------------------

def damage(path, fraction: float, to=None) -> str:
    blob = bytearray(read(path))
    blob[int(len(blob) * fraction)] ^= 0xFF
    return write(to or path + ".damaged.enc", bytes(blob))


@pytest.mark.parametrize("compression", ["none", "fast", "lzma"])
def test_salvage_single_file(tmp_path, compression):
    data = os.urandom(2_000_000)
    src = write(tmp_path / "in" / "movie.bin", data)
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(compression=compression))
    bad = damage(r.output, 0.6)
    with pytest.raises((InvalidTag, ValueError)):                       # default: all or nothing
        core.decrypt_path(bad, str(tmp_path / "strict"), PW)
    assert os.listdir(tmp_path / "strict") == []
    out = core.decrypt_path(bad, str(tmp_path / "rescued"), PW, salvage=True)
    got = read(out.output)
    assert out.partial and out.output.endswith(".partial")
    assert 0 < len(got) < len(data) and data.startswith(got)            # a true prefix, nothing invented
    assert len(got) > len(data) // 3
    assert any("Damaged" in w for w in out.warnings)


def test_salvage_folder_keeps_complete_files(tmp_path):
    root = tmp_path / "in" / "Photos"
    files = {f"{i:02d}.raw": os.urandom(200_000) for i in range(10)}
    for n, d in files.items():
        write(root / n, d)
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(compression="none"))
    out = core.decrypt_path(damage(r.output, 0.55), str(tmp_path / "rescued"), PW, salvage=True)
    assert out.partial and os.path.basename(out.output) == "Photos (incomplete)"
    got = sorted(os.listdir(out.output))
    complete = [n for n in got if not n.endswith(".partial")]
    assert 3 <= len(complete) < 10 and complete == sorted(files)[:len(complete)]
    for n in complete:
        assert read(os.path.join(out.output, n)) == files[n]
    for n in got:
        if n.endswith(".partial"):
            part = read(os.path.join(out.output, n))
            assert part and files[n[:-len(".partial")]].startswith(part)


@pytest.mark.parametrize("compression", ["none", "fast", "lzma"])
def test_salvage_loses_little_before_the_damage(tmp_path, compression):
    """A small file with a hidden name is one entry in an archive: what precedes the damage must come out."""
    data = os.urandom(900_000)
    src = write(tmp_path / "in" / "data.bin", data)
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(compression=compression, hide_name=True))
    blob = read(r.output)
    out = core.decrypt_path(damage(r.output, 0.75), str(tmp_path / "rescued"), PW, salvage=True)
    got = read(out.output)
    assert out.partial and os.path.basename(out.output) == "data.bin.partial" and data.startswith(got)
    # everything up to the damaged 64 KiB block, minus at most one read step and the archive's own buffer
    assert len(got) > int(len(blob) * 0.75) - (64 << 10) - (48 << 10)
    assert os.listdir(tmp_path / "rescued") == ["data.bin.partial"]          # no temp files left


def photos(tmp_path, n=6, size=150_000, **kw):
    root = tmp_path / "in" / "Photos"
    files = {f"{i:02d}.raw": os.urandom(size) for i in range(n)}
    for name, d in files.items():
        write(root / name, d)
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(compression="none", **kw))
    return r.output, files


def test_salvage_marks_everything_it_publishes(tmp_path):
    enc, files = photos(tmp_path)
    blob = read(enc)
    cases = {"end marker cut": blob[:-28], "junk appended": blob + b"\0"}
    for i, (what, data) in enumerate(cases.items()):
        out = core.decrypt_path(write(tmp_path / f"c{i}.enc", data), str(tmp_path / f"d{i}"), PW, salvage=True)
        assert out.partial and os.listdir(tmp_path / f"d{i}") == ["Photos (incomplete)"], what
        assert sorted(os.listdir(out.output)) == sorted(files), what           # all there, yet not provably
    one = write(tmp_path / "in2" / "single.bin", os.urandom(200_000))
    r = core.encrypt_path(one, str(tmp_path / "enc2"), PW, opts(compression="none", hide_name=True))
    out = core.decrypt_path(write(tmp_path / "cut.enc", read(r.output)[:-28]), str(tmp_path / "d9"), PW, salvage=True)
    assert out.partial and os.listdir(tmp_path / "d9") == ["single.bin.partial"]


def test_salvage_never_replaces_or_skips(tmp_path):
    enc, files = photos(tmp_path)
    dec = tmp_path / "dec"
    good = core.decrypt_path(enc, str(dec), PW)
    earlier = write(dec / "Photos (incomplete)" / "note.txt", b"from an earlier attempt")
    bad = damage(enc, 0.5)
    for policy in ("overwrite", "skip"):
        out = core.decrypt_path(bad, str(dec), PW, overwrite=policy, salvage=True)
        assert out.partial and os.path.basename(out.output).startswith("Photos (incomplete) (")
        assert os.listdir(out.output)
    assert sorted(os.listdir(good.output)) == sorted(files) and read(earlier) == b"from an earlier attempt"


def test_salvage_does_not_get_past_the_limits(tmp_path):
    enc, _ = photos(tmp_path)
    with pytest.raises(core.LimitExceeded):
        core.decrypt_path(enc, str(tmp_path / "dec"), PW, limits=core.Limits(max_entries=2), salvage=True)
    assert os.listdir(tmp_path / "dec") == []


def test_salvage_with_nothing_recovered_restores_nothing(tmp_path):
    enc, _ = photos(tmp_path, n=2, size=400_000)
    blob = bytearray(read(enc))
    blob[core.HEADER_SIZE + 4 + 70_000] ^= 1              # second 64 KiB block: inside the first file
    with pytest.raises(InvalidTag):
        core.decrypt_path(write(tmp_path / "bad.enc", bytes(blob)), str(tmp_path / "dec"), PW)
    out = core.decrypt_path(str(tmp_path / "bad.enc"), str(tmp_path / "dec"), PW, salvage=True)
    assert out.partial and os.listdir(out.output) == ["00.raw.partial"]
    empty = tmp_path / "in3" / "Empty"                    # an archive without a single file in it
    os.makedirs(empty / "sub")
    r = core.encrypt_path(str(empty), str(tmp_path / "enc3"), PW, opts())
    with pytest.raises(ValueError):
        core.decrypt_path(write(tmp_path / "bad3.enc", read(r.output)[:-28]), str(tmp_path / "dec3"), PW, salvage=True)
    assert os.listdir(tmp_path / "dec3") == []
    blob = bytearray(read(enc))
    blob[core.HEADER_SIZE + 10] ^= 1                      # first block: nothing can be vouched for
    with pytest.raises(InvalidTag):
        core.decrypt_path(write(tmp_path / "bad2.enc", bytes(blob)), str(tmp_path / "dec2"), PW, salvage=True)
    assert not os.path.exists(tmp_path / "dec2") or os.listdir(tmp_path / "dec2") == []


@pytest.mark.parametrize("hide", [False, True])
def test_salvage_survives_a_read_error(tmp_path, monkeypatch, hide):
    """A bad sector: the disk refuses to return part of the encrypted file."""
    import builtins
    import errno
    data = os.urandom(900_000)
    src = write(tmp_path / "in" / "movie.bin", data)
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(compression="none", hide_name=hide))
    real_open = builtins.open

    class BadSector:
        def __init__(self, f):
            self._f = f

        def read(self, n=-1):
            if self._f.tell() > 500_000:
                raise OSError(errno.EIO, "Input/output error")
            return self._f.read(n)

        def __getattr__(self, name):
            return getattr(self._f, name)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self._f.close()

    def flaky_open(path, mode="r", *a, **k):
        f = real_open(path, mode, *a, **k)
        return BadSector(f) if str(path) == r.output and mode == "rb" else f
    monkeypatch.setattr(builtins, "open", flaky_open)
    with pytest.raises(core.SourceReadError):
        core.decrypt_path(r.output, str(tmp_path / "strict"), PW)
    out = core.decrypt_path(r.output, str(tmp_path / "rescued"), PW, salvage=True)
    monkeypatch.undo()
    got = read(out.output)
    assert out.partial and out.output.endswith("movie.bin.partial") and data.startswith(got) and len(got) > 380_000
    assert any("could not be read" in w for w in out.warnings)
    assert os.listdir(tmp_path / "strict") == [] and len(os.listdir(tmp_path / "rescued")) == 1


def test_salvage_with_names_at_the_length_limit(tmp_path):
    if WINDOWS:
        pytest.skip("needs paths longer than Windows allows by default")
    root = tmp_path / "in" / ("F" * 250)
    write(root / ("a" * 250), os.urandom(600_000))
    r = core.encrypt_path(str(root), str(tmp_path / "enc"), PW, opts(compression="none"))
    out = core.decrypt_path(damage(r.output, 0.5, tmp_path / "bad1.enc"), str(tmp_path / "dec"), PW, salvage=True)
    (top,) = os.listdir(tmp_path / "dec")
    assert out.partial and top.endswith(" (incomplete)") and len(top) == 255
    (name,) = os.listdir(out.output)
    assert name.endswith(".partial") and len(name) == 255             # never an unmarked piece
    single = write(tmp_path / "in2" / ("s" * 251), os.urandom(600_000))
    r = core.encrypt_path(single, str(tmp_path / "enc2"), PW, opts(compression="none"))
    bad = damage(r.output, 0.5, tmp_path / ("s" * 251))        # same name, so the restored name is as long
    out = core.decrypt_path(bad, str(tmp_path / "dec2"), PW, salvage=True)
    assert out.partial and os.path.basename(out.output) == "s" * 243 + ".dec.partial"


def test_salvage_changes_nothing_for_a_healthy_file(tmp_path, sample):
    src, data = sample
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts())
    out = core.decrypt_path(r.output, str(tmp_path / "dec"), PW, salvage=True)
    assert not out.partial and read(out.output) == data and not out.warnings


def test_salvage_flags_a_file_whose_end_marker_is_gone(tmp_path):
    data = os.urandom(300_000)
    src = write(tmp_path / "in" / "a.bin", data)
    r = core.encrypt_path(src, str(tmp_path / "enc"), PW, opts(compression="none"))
    cut = write(tmp_path / "cut.enc", read(r.output)[:-28])
    out = core.decrypt_path(cut, str(tmp_path / "dec"), PW, salvage=True)
    assert out.partial and read(out.output) == data          # all there, but that cannot be proven


# -- passwords -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("pw", ["aaaaaaaaaaaaaaaa", "passwordpassword", "1234567890123456", "qwertyuiopasdfgh",
                                "Password123456789", "P@ssw0rdP@ssw0rd!", "abcdefghijklmnopqrst",
                                "letmeinletmeinletmein", "short-Xk7!", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"])
def test_predictable_passwords_are_rejected(pw):
    bits, ok, hint = core.password_feedback(pw)
    assert not ok and hint, (pw, bits)
    assert core.password_strength(pw) == (bits, False)


@pytest.mark.parametrize("pw", ["correct horse battery staple", "k7fqm-2xwhp-9rtbn-c3hnv-u8dze",
                                "Tr0ub4dor&3 is not enough!", "vqBz7#Lm2pXw9!Rt", "mountain-river-lantern-42-copper"])
def test_reasonable_passwords_are_accepted(pw):
    bits, ok, hint = core.password_feedback(pw)
    assert ok and not hint and bits >= core.MIN_PASSWORD_BITS, (pw, bits)


def test_password_estimate_stays_fast_and_is_not_fooled_by_length():
    import time
    t0 = time.perf_counter()
    for pw in (os.urandom(8000).hex(), "ab" * 10_000, "\u00e9\U0001f600 " * 5000, "x" * 32_767):
        core.password_feedback(pw)
    assert time.perf_counter() - t0 < 2.0
    for pw in ("a" * 45, "a" * 70, "z" * 200, "ab" * 40, "1qaz2wsx3edc4rfv", "zaq1xsw2cde3vfr4", "qwerty" * 12):
        assert not core.password_feedback(pw)[1], pw


def test_generated_passwords():
    seen = {core.generate_password() for _ in range(200)}
    assert len(seen) == 200
    for pw in seen:
        groups = pw.split("-")
        assert len(groups) == 5 and all(len(g) == 5 for g in groups)
        assert not set(pw) & set("ilo01") and core.password_feedback(pw)[1]
    assert len(core.generate_password(8, 4)) == 8 * 4 + 7


# -- command line ----------------------------------------------------------------------------------------

def test_cli_roundtrip(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CRYPTID_PASSWORD", PW)
    data = os.urandom(50_000)
    src = write(tmp_path / "in" / "notes.txt", data)
    write(tmp_path / "in" / "Folder" / "x.txt", b"inside")
    enc, dec = str(tmp_path / "enc"), str(tmp_path / "dec")
    assert cli.main(["encrypt", src, str(tmp_path / "in" / "Folder"), "-o", enc, "--kdf", "light", "--hide-names"]) == 0
    assert len(os.listdir(enc)) == 2 and not [n for n in os.listdir(enc) if "notes" in n or "Folder" in n]
    assert cli.main(["verify", enc]) == 0
    assert "contains 'notes.txt'" in capsys.readouterr().out
    assert cli.main(["decrypt", enc, "-o", dec]) == 0
    assert read(os.path.join(dec, "notes.txt")) == data
    assert read(os.path.join(dec, "Folder", "x.txt")) == b"inside"

    monkeypatch.setenv("CRYPTID_PASSWORD", "the wrong password entirely")
    assert cli.main(["verify", enc]) == 1
    monkeypatch.setenv("CRYPTID_PASSWORD", "password1234")
    assert cli.main(["encrypt", src, "-o", enc, "--kdf", "light"]) == 2          # weak password refused
    assert len(os.listdir(enc)) == 2


def test_cli_password_file_keyfile_and_salvage(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("CRYPTID_PASSWORD", raising=False)
    pwfile = write(tmp_path / "pw.txt", b"\xef\xbb\xbf" + (PW + "\r\n").encode())    # as Notepad saves it
    kf = str(tmp_path / "usb" / "key")
    os.makedirs(tmp_path / "usb")
    assert cli.main(["keyfile", kf]) == 0 and os.path.isfile(kf + ".encvkey")
    data = os.urandom(900_000)
    src = write(tmp_path / "in" / "a.bin", data)
    enc = str(tmp_path / "enc")
    common = ["--password-file", pwfile, "--keyfile", kf + ".encvkey"]
    assert cli.main(["encrypt", src, "-o", enc, "--kdf", "light", "--compression", "none", *common]) == 0
    f = os.path.join(enc, "a.bin.enc")
    assert cli.main(["verify", f, "--password-file", pwfile]) == 1               # key file missing
    assert cli.main(["verify", f, *common]) == 0
    monkeypatch.setenv("CRYPTID_PASSWORD", PW)                                   # the file held exactly PW
    assert cli.main(["verify", f, "--keyfile", kf + ".encvkey"]) == 0
    monkeypatch.delenv("CRYPTID_PASSWORD")
    bad = damage(f, 0.7)
    assert cli.main(["decrypt", bad, "-o", str(tmp_path / "d1"), *common]) == 1
    assert cli.main(["decrypt", bad, "-o", str(tmp_path / "d2"), "--salvage", *common]) == 1
    assert "RECOVERED IN PART" in capsys.readouterr().out
    part = [n for n in os.listdir(tmp_path / "d2") if n.endswith(".partial")]
    assert len(part) == 1 and data.startswith(read(tmp_path / "d2" / part[0]))
    assert cli.main(["genpass"]) == 0 and len(capsys.readouterr().out.strip()) == 29
