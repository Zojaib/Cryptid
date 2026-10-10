# ENCV file format, version 8

Enough to read a Cryptid file without Cryptid. `tests/test_core.py` contains a 20-line reader written
from this page (`reference_decrypt`), and the test suite checks it against what the app writes.

## Layout

```
header (52 bytes) | chunk | chunk | ... | end marker
```

All header integers are little-endian.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0  | 4  | magic `ENCV` |
| 4  | 1  | format version = 8 |
| 5  | 1  | key derivation: 1 = Argon2id, 2 = Argon2id + key file |
| 6  | 1  | cipher: 1 = AES-256-GCM |
| 7  | 1  | compression: 0 = none, 1 = zstd, 2 = xz (lzma) |
| 8  | 4  | chunk size in bytes (plaintext per chunk; 524288, or 65536 with "Light") |
| 12 | 4  | Argon2id time cost (passes) |
| 16 | 4  | Argon2id memory cost in KiB |
| 20 | 4  | Argon2id parallelism (lanes) |
| 24 | 16 | salt, random per file |
| 40 | 4  | nonce prefix, random per file |
| 44 | 8  | size of the original data in bytes (for a folder: the sum of its files) |

The header is not encrypted. It is authenticated: its SHA-256 is part of the associated data of every chunk.

## Key

```
key = Argon2id(password as UTF-8, salt, time, memory, parallelism, 32 bytes)        version 0x13
```

With a key file (key derivation = 2):

```
key = HMAC-SHA256(key = D, message = "ENCV-v8-keyfile" 0x01 || key)
D   = SHA-256("ENCV-keyfile-v1" || the 64 key bytes)      for a Cryptid key file
D   = SHA-256("ENCV-rawfile-v1" || whole file)            for any other file used as key file
```

A Cryptid key file is text: comment lines starting with `#`, the line `ENCVKEY1`, then 64 bytes as hex.

Every file has its own salt, so its own key. Defaults: 3 passes, 128 MiB, up to 4 lanes ("Strong");
2 passes, 32 MiB ("Light"). Cryptid refuses a header asking for less than 8 MiB, or for more than
6 passes, 512 MiB or 8 lanes, before deriving anything.

## Chunks

Each record is a 4-byte little-endian length followed by that many bytes of AES-256-GCM output
(ciphertext, then the 16-byte tag). For chunk number `i`, counting from 0:

```
nonce = nonce prefix (4 bytes) || i as 8 bytes big-endian
aad   = SHA-256(header) || i as 8 bytes big-endian
```

The **end marker** is the last record. Its plaintext is the number of data chunks as 8 bytes
little-endian, encrypted with `i = 0xFFFFFFFFFFFFFFFF`. Nothing may follow it. A file without a valid
end marker is incomplete.

## Payload

The decrypted chunks, concatenated, form one stream, compressed as the header says (a standard zstd
frame or `.xz` stream). Decompressed, it is either:

- the original file, byte for byte; its name is the encrypted file's name without the extension, or
- a tar archive (POSIX pax), recognised by `ustar` at offset 257. This is used for folders, for files
  encrypted with "Hide the file names" (one entry carrying the real name) and for files that are
  themselves tar archives (one entry, so they come back as a file).

Archives written by Cryptid hold regular files and folders only, with paths relative to the top folder.
