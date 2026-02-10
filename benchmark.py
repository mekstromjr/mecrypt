#!/usr/bin/env python3
"""
Benchmark mecrypt encryption and decryption performance.

Tests both in-memory and file-based operations at various data sizes.
"""

import os
import tempfile
import time

import mecrypt

PASSWORD = "benchmark-password-123"

SIZES = [
    ("1 KB", 1024),
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("1 MB", 1024 * 1024),
    ("10 MB", 10 * 1024 * 1024),
    ("50 MB", 50 * 1024 * 1024),
]


def fmt_time(seconds):
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f} us"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    return f"{seconds:.2f} s"


def fmt_throughput(size_bytes, seconds):
    if seconds == 0:
        return "---"
    mb_per_sec = (size_bytes / (1024 * 1024)) / seconds
    return f"{mb_per_sec:.2f} MB/s"


def bench_in_memory(label, size):
    """Benchmark encrypt() and decrypt() with in-memory data."""
    data = os.urandom(size)

    # Encrypt
    start = time.perf_counter()
    ciphertext, salt, nonce, mac = mecrypt.encrypt(data, PASSWORD)
    enc_time = time.perf_counter() - start

    # Decrypt
    start = time.perf_counter()
    plaintext = mecrypt.decrypt(ciphertext, PASSWORD, salt, nonce, mac)
    dec_time = time.perf_counter() - start

    assert plaintext == data, "Round-trip failed!"

    return enc_time, dec_time


def bench_file(label, size):
    """Benchmark encrypt_file() and decrypt_file() with temp files."""
    data = os.urandom(size)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        input_path = f.name

    enc_path = input_path + ".enc"
    dec_path = input_path + ".dec"

    try:
        # Encrypt
        start = time.perf_counter()
        mecrypt.encrypt_file(input_path, enc_path, PASSWORD)
        enc_time = time.perf_counter() - start

        # Decrypt
        start = time.perf_counter()
        mecrypt.decrypt_file(enc_path, dec_path, PASSWORD)
        dec_time = time.perf_counter() - start

        with open(dec_path, "rb") as f:
            result = f.read()
        assert result == data, "File round-trip failed!"

        return enc_time, dec_time
    finally:
        for p in (input_path, enc_path, dec_path):
            if os.path.exists(p):
                os.remove(p)


def run_benchmarks():
    print()
    print("== mecrypt benchmark ==")
    print()

    # Key derivation (one-time cost per password)
    print("Key derivation (PBKDF2, 100k iterations):")
    start = time.perf_counter()
    mecrypt.derive_keys(PASSWORD)
    kdf_time = time.perf_counter() - start
    print(f"  {fmt_time(kdf_time)}")
    print()

    # In-memory benchmarks
    print("In-memory encrypt/decrypt:")
    print(f"  {'Size':<10} {'Encrypt':>10} {'Decrypt':>10} {'Enc MB/s':>10} {'Dec MB/s':>10}")
    print(f"  {'----':<10} {'-------':>10} {'-------':>10} {'--------':>10} {'--------':>10}")

    for label, size in SIZES:
        enc_time, dec_time = bench_in_memory(label, size)
        print(
            f"  {label:<10} {fmt_time(enc_time):>10} {fmt_time(dec_time):>10}"
            f" {fmt_throughput(size, enc_time):>10} {fmt_throughput(size, dec_time):>10}"
        )

    print()

    # File benchmarks
    print("File-based encrypt/decrypt (streaming):")
    print(f"  {'Size':<10} {'Encrypt':>10} {'Decrypt':>10} {'Enc MB/s':>10} {'Dec MB/s':>10}")
    print(f"  {'----':<10} {'-------':>10} {'-------':>10} {'--------':>10} {'--------':>10}")

    for label, size in SIZES:
        enc_time, dec_time = bench_file(label, size)
        print(
            f"  {label:<10} {fmt_time(enc_time):>10} {fmt_time(dec_time):>10}"
            f" {fmt_throughput(size, enc_time):>10} {fmt_throughput(size, dec_time):>10}"
        )

    print()


if __name__ == "__main__":
    run_benchmarks()
