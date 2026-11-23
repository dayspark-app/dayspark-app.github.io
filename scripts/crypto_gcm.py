#!/usr/bin/env python3
"""
Standard AES-256-GCM + PBKDF2-HMAC-SHA256 encryption compatible with Web Crypto API.

Uses `cryptography` if installed; otherwise uses system `openssl` (native AES-256-CTR)
combined with NIST SP 800-38D GHASH in Python — zero external pip dependencies required.
"""

import hashlib
import os
import struct
import subprocess

VAULT_MAGIC = b"PA01"
DEFAULT_ITERATIONS = 600_000
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16

_R_POLY = 0xE1000000000000000000000000000000


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    if not password:
        raise ValueError("Password must not be empty")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


def _gf128_mul_bit(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R_POLY
        else:
            v >>= 1
    return z


def _build_ghash_table(h_int: int):
    # Precompute 16 byte-position tables (16 x 256 ints) for fast GHASH (~20 ms/MB)
    tables = []
    for byte_idx in range(16):
        shift = (15 - byte_idx) * 8
        tbl = [0] * 256
        for b in range(1, 256):
            tbl[b] = _gf128_mul_bit(b << shift, h_int)
        tables.append(tbl)
    return tables


def _ghash(h_bytes: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h_int = int.from_bytes(h_bytes, "big")
    tables = _build_ghash_table(h_int)

    def pad16(data: bytes) -> bytes:
        rem = len(data) & 15
        return data if rem == 0 else data + b"\x00" * (16 - rem)

    padded_aad = pad16(aad)
    padded_ct = pad16(ciphertext)
    lengths = struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)
    stream = padded_aad + padded_ct + lengths

    y = 0
    for off in range(0, len(stream), 16):
        block = int.from_bytes(stream[off:off + 16], "big")
        x = y ^ block
        # Multiply x * H using byte lookup tables
        acc = 0
        for byte_idx in range(16):
            b = (x >> ((15 - byte_idx) * 8)) & 0xFF
            if b:
                acc ^= tables[byte_idx][b]
        y = acc

    return y.to_bytes(16, "big")


def _openssl_aes256_ctr(key: bytes, iv16: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    proc = subprocess.run(
        [
            "openssl", "enc", "-aes-256-ctr", "-nosalt",
            "-K", key.hex(),
            "-iv", iv16.hex(),
        ],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return proc.stdout


def aes_256_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return ciphertext || 16-byte auth tag (Web Crypto API format)."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    if len(iv) != 12:
        raise ValueError("GCM requires a 12-byte (96-bit) IV")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        return AESGCM(key).encrypt(iv, plaintext, aad)
    except ImportError:
        pass

    # NIST SP 800-38D Section 7.1 with 96-bit IV:
    # H = AES_K(0^128) via CTR with IV=0^128 on 16 zero bytes
    # J0 = IV || 0x00000001
    # S = AES_K(J0)
    # C = AES_K_CTR(inc32(J0), P)
    # Note: calling CTR with IV=J0 on (16 zero bytes || P) computes (S || C) in one openssl call!
    h_bytes = _openssl_aes256_ctr(key, b"\x00" * 16, b"\x00" * 16)
    j0 = iv + b"\x00\x00\x00\x01"
    s_and_ct = _openssl_aes256_ctr(key, j0, (b"\x00" * 16) + plaintext)
    s_bytes = s_and_ct[:16]
    ciphertext = s_and_ct[16:]

    gh = _ghash(h_bytes, aad, ciphertext)
    tag = bytes(a ^ b for a, b in zip(gh, s_bytes))
    return ciphertext + tag


def aes_256_gcm_decrypt(key: bytes, iv: bytes, ciphertext_and_tag: bytes, aad: bytes = b"") -> bytes:
    """Verify tag and decrypt ciphertext || 16-byte tag."""
    if len(ciphertext_and_tag) < TAG_LEN:
        raise ValueError("Ciphertext too short")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        return AESGCM(key).decrypt(iv, ciphertext_and_tag, aad)
    except ImportError:
        pass

    ciphertext = ciphertext_and_tag[:-TAG_LEN]
    tag = ciphertext_and_tag[-TAG_LEN:]

    h_bytes = _openssl_aes256_ctr(key, b"\x00" * 16, b"\x00" * 16)
    j0 = iv + b"\x00\x00\x00\x01"
    s_and_pt = _openssl_aes256_ctr(key, j0, (b"\x00" * 16) + ciphertext)
    s_bytes = s_and_pt[:16]
    plaintext = s_and_pt[16:]

    gh = _ghash(h_bytes, aad, ciphertext)
    expected_tag = bytes(a ^ b for a, b in zip(gh, s_bytes))

    # Constant-time tag compare
    diff = 0
    for a, b in zip(tag, expected_tag):
        diff |= a ^ b
    if diff != 0:
        raise ValueError("Authentication tag mismatch (wrong password or corrupted data)")
    return plaintext


def seal_vault(plaintext: bytes, password: str, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Pack and encrypt plaintext into vault.enc binary format."""
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    header = VAULT_MAGIC + struct.pack(">I", iterations) + salt + iv
    key = derive_key(password, salt, iterations)
    ct_and_tag = aes_256_gcm_encrypt(key, iv, plaintext, aad=header)
    return header + ct_and_tag


def open_vault(vault_bytes: bytes, password: str) -> bytes:
    """Decrypt and authenticate vault.enc binary format."""
    header_len = 4 + 4 + SALT_LEN + IV_LEN
    if len(vault_bytes) < header_len + TAG_LEN:
        raise ValueError("Vault file is too small or corrupted")
    header = vault_bytes[:header_len]
    magic = header[:4]
    if magic != VAULT_MAGIC:
        raise ValueError(f"Unsupported vault magic: {magic!r}")
    (iterations,) = struct.unpack(">I", header[4:8])
    salt = header[8:8 + SALT_LEN]
    iv = header[8 + SALT_LEN:header_len]
    key = derive_key(password, salt, iterations)
    return aes_256_gcm_decrypt(key, iv, vault_bytes[header_len:], aad=header)


def _self_test() -> None:
    # Official NIST SP 800-38D / GCM Test Cases 13, 14, 15, 16 (AES-256, 96-bit IV)
    vectors = [
        # Test Case 13: empty PT, empty AAD
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "530f8afbc74536b9a963b4f1c4cb738b",
        ),
        # Test Case 14: 16-byte zero PT, empty AAD
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "cea7403d4d606b6e074ec5d3baf39d18",
            "d0d1c8a799996bf0265b98b5d48ab919",
        ),
        # Test Case 15: 64-byte PT, empty AAD
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        ),
        # Test Case 16: 60-byte PT (non-block-aligned) + 20-byte AAD
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        ),
    ]
    for idx, (k_hex, iv_hex, pt_hex, aad_hex, ct_hex, tag_hex) in enumerate(vectors, 13):
        key = bytes.fromhex(k_hex)
        iv = bytes.fromhex(iv_hex)
        pt = bytes.fromhex(pt_hex)
        aad = bytes.fromhex(aad_hex)
        expected = bytes.fromhex(ct_hex + tag_hex)
        got = aes_256_gcm_encrypt(key, iv, pt, aad)
        assert got == expected, f"NIST TC{idx} encrypt mismatch"
        dec = aes_256_gcm_decrypt(key, iv, got, aad)
        assert dec == pt, f"NIST TC{idx} decrypt mismatch"

    # Vault round-trip test
    sample = b"Hello encrypted vault!" * 100
    sealed = seal_vault(sample, "secret-123", iterations=10_000)
    assert open_vault(sealed, "secret-123") == sample
    try:
        open_vault(sealed, "wrong-pass")
        raise AssertionError("Wrong password should fail")
    except ValueError:
        pass
    print("All NIST SP 800-38D AES-256-GCM test vectors & vault round-trip PASSED!")


if __name__ == "__main__":
    _self_test()
