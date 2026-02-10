#!/usr/bin/env python3
"""
mecrypt — Basic Quantum-resistant encryption and authentication.

Implements:
  - Lamport one-time signature scheme (SHA-256) for authentication
  - Hash-based stream cipher (SHA-256 CTR + PBKDF2) for encryption
 
All operations use only the Python standard library.
"""

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys


# ---------------------------------------------------------------------------
# Lamport one-time signature scheme
# ---------------------------------------------------------------------------

def generate_keypair(progress_callback=None):
    """Generate a Lamport OTS keypair.

    Returns (private_key, public_key) where each is a list of 256 pairs
    of 32-byte values (bytes).
    """
    private_key = []
    public_key = []
    for i in range(256):
        # If the bit is 0, use sk0; if 1, use sk1
        sk0 = secrets.token_bytes(32) 
        sk1 = secrets.token_bytes(32)
        pk0 = hashlib.sha256(sk0).digest()
        pk1 = hashlib.sha256(sk1).digest()
        private_key.append((sk0, sk1))
        public_key.append((pk0, pk1))
        if progress_callback:
            progress_callback(i + 1, 256)
    return private_key, public_key


def sign_message(private_key, message_bytes, progress_callback=None):
    """Sign a message using a Lamport private key.

    Returns a list of 256 bytes objects (the signature).
    """
    digest = hashlib.sha256(message_bytes).digest()
    signature = []
    for i in range(256):
        byte_index = i // 8
        bit_index = 7 - (i % 8)
        bit = (digest[byte_index] >> bit_index) & 1
        signature.append(private_key[i][bit])
        if progress_callback:
            progress_callback(i + 1, 256)
    return signature


def verify_signature(public_key, message_bytes, signature, progress_callback=None):
    """Verify a Lamport signature against a public key.

    Returns True if valid, False otherwise.
    """
    digest = hashlib.sha256(message_bytes).digest()
    for i in range(256):
        byte_index = i // 8
        bit_index = 7 - (i % 8)
        bit = (digest[byte_index] >> bit_index) & 1
        expected = public_key[i][bit]
        actual = hashlib.sha256(signature[i]).digest()
        if actual != expected:
            return False
        if progress_callback:
            progress_callback(i + 1, 256)
    return True


# ---------------------------------------------------------------------------
# Symmetric encryption (SHA-256 CTR mode + PBKDF2 + HMAC)
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 100_000
CHUNK_SIZE = 65536  # 64 KB


def derive_keys(password, salt=None):
    """Derive an encryption key and authentication key from a password.

    The salt is used once for PBKDF2 to produce a 512-bit master output,
    split into a 256-bit encryption key and a 256-bit HMAC auth key.

    Returns (enc_key, auth_key, salt). Generates a random salt if None.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    raw = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=64
    )
    return raw[:32], raw[32:], salt


def _xor_stream(data, key, nonce, start_counter=0):
    """XOR data with a keystream derived from key + nonce + counter.

    Each counter value produces 32 bytes of keystream via SHA-256.
    Processes in 32-byte blocks to keep memory usage constant.

    Returns (result_bytes, next_counter).
    """
    result = bytearray(len(data))
    counter = start_counter
    offset = 0
    while offset < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        remaining = len(data) - offset
        block_use = min(32, remaining)
        for i in range(block_use):
            result[offset + i] = data[offset + i] ^ block[i]
        offset += block_use
        counter += 1
    return bytes(result), counter


def encrypt(plaintext_bytes, password):
    """Encrypt plaintext with authenticated encryption (CTR + HMAC).

    - Derives enc_key + auth_key from password via PBKDF2 (one-time cost)
    - Generates a random nonce for CTR mode
    - Encrypts via SHA-256 CTR in chunks
    - Computes HMAC-SHA256 over the ciphertext for tamper detection

    Returns (ciphertext_bytes, salt, nonce, mac).
    """
    enc_key, auth_key, salt = derive_keys(password)
    nonce = secrets.token_bytes(16)

    # Encrypt in chunks to support large data
    ciphertext = bytearray()
    counter = 0
    offset = 0
    while offset < len(plaintext_bytes):
        chunk = plaintext_bytes[offset:offset + CHUNK_SIZE]
        encrypted_chunk, counter = _xor_stream(chunk, enc_key, nonce, counter)
        ciphertext.extend(encrypted_chunk)
        offset += CHUNK_SIZE

    ciphertext = bytes(ciphertext)
    mac = hmac.new(auth_key, ciphertext, hashlib.sha256).digest()
    return ciphertext, salt, nonce, mac


def decrypt(ciphertext_bytes, password, salt, nonce, expected_mac):
    """Decrypt ciphertext with HMAC verification.

    Verifies the HMAC first — raises ValueError if tampered.
    Then decrypts via SHA-256 CTR in chunks.

    Returns plaintext_bytes.
    """
    enc_key, auth_key, _ = derive_keys(password, salt)

    # Verify HMAC before decrypting
    actual_mac = hmac.new(auth_key, ciphertext_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise ValueError("HMAC verification failed: ciphertext may have been tampered with")

    # Decrypt in chunks
    plaintext = bytearray()
    counter = 0
    offset = 0
    while offset < len(ciphertext_bytes):
        chunk = ciphertext_bytes[offset:offset + CHUNK_SIZE]
        decrypted_chunk, counter = _xor_stream(chunk, enc_key, nonce, counter)
        plaintext.extend(decrypted_chunk)
        offset += CHUNK_SIZE

    return bytes(plaintext)


def encrypt_file(input_path, output_path, password):
    """Encrypt a file using streaming — constant memory regardless of file size.

    Output is a binary format:
      [16 bytes salt][16 bytes nonce][ciphertext...][32 bytes HMAC]
    """
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Input and output paths must differ")

    enc_key, auth_key, salt = derive_keys(password)
    nonce = secrets.token_bytes(16)
    mac = hmac.new(auth_key, digestmod=hashlib.sha256)

    counter = 0
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(salt)
        fout.write(nonce)

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk, counter = _xor_stream(chunk, enc_key, nonce, counter)
            mac.update(encrypted_chunk)
            fout.write(encrypted_chunk)

        fout.write(mac.digest())


def decrypt_file(input_path, output_path, password):
    """Decrypt a binary-format encrypted file using streaming.

    Two-pass streaming: first pass verifies the HMAC, second pass decrypts.
    Memory usage stays constant regardless of file size.
    """
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Input and output paths must differ")

    file_size = os.path.getsize(input_path)
    if file_size < 64:  # 16 salt + 16 nonce + 32 hmac minimum
        raise ValueError("File too small to be a valid encrypted file")

    ciphertext_len = file_size - 64  # minus salt + nonce + hmac

    with open(input_path, "rb") as fin:
        salt = fin.read(16)
        nonce = fin.read(16)

        # Read HMAC from end of file
        fin.seek(-32, 2)
        expected_mac = fin.read(32)

        enc_key, auth_key, _ = derive_keys(password, salt)

        # Pass 1: Stream HMAC verification
        fin.seek(32)  # after salt + nonce
        mac = hmac.new(auth_key, digestmod=hashlib.sha256)
        remaining = ciphertext_len
        while remaining > 0:
            chunk = fin.read(min(CHUNK_SIZE, remaining))
            mac.update(chunk)
            remaining -= len(chunk)

        if not hmac.compare_digest(mac.digest(), expected_mac):
            raise ValueError("HMAC verification failed: file may have been tampered with")

        # Pass 2: Stream decryption
        fin.seek(32)
        counter = 0
        remaining = ciphertext_len
        with open(output_path, "wb") as fout:
            while remaining > 0:
                chunk = fin.read(min(CHUNK_SIZE, remaining))
                decrypted_chunk, counter = _xor_stream(chunk, enc_key, nonce, counter)
                fout.write(decrypted_chunk)
                remaining -= len(chunk)


# ---------------------------------------------------------------------------
# Serialization helpers (JSON with hex encoding)
# ---------------------------------------------------------------------------

def key_to_json(key, key_type, message_id=None):
    """Serialize a Lamport key (private or public) to a JSON-compatible dict."""
    data = {
        "scheme": "lamport-ots-sha256",
        "type": key_type,
        "key": [[v.hex() for v in pair] for pair in key],
    }
    if message_id:
        data["message_id"] = message_id
    return data


def key_from_json(data):
    """Deserialize a Lamport key from a JSON-compatible dict."""
    if "key" not in data:
        raise ValueError("Missing 'key' field in key JSON")
    pairs = data["key"]
    if len(pairs) != 256:
        raise ValueError(f"Expected 256 key pairs, got {len(pairs)}")
    result = []
    for i, pair in enumerate(pairs):
        if len(pair) != 2:
            raise ValueError(f"Key pair {i} must have exactly 2 values")
        v0, v1 = bytes.fromhex(pair[0]), bytes.fromhex(pair[1])
        if len(v0) != 32 or len(v1) != 32:
            raise ValueError(f"Key pair {i} values must be 32 bytes each")
        result.append((v0, v1))
    return result


def signature_to_json(signature, message_bytes, message_id=None):
    """Serialize a Lamport signature to a JSON-compatible dict."""
    data = {
        "scheme": "lamport-ots-sha256",
        "message_hash": hashlib.sha256(message_bytes).hexdigest(),
        "values": [v.hex() for v in signature],
    }
    if message_id:
        data["message_id"] = message_id
    return data


def signature_from_json(data):
    """Deserialize a Lamport signature from a JSON-compatible dict."""
    if "values" not in data:
        raise ValueError("Missing 'values' field in signature JSON")
    values = data["values"]
    if len(values) != 256:
        raise ValueError(f"Expected 256 signature values, got {len(values)}")
    result = []
    for i, v in enumerate(values):
        b = bytes.fromhex(v)
        if len(b) != 32:
            raise ValueError(f"Signature value {i} must be 32 bytes")
        result.append(b)
    return result


def ciphertext_to_json(ciphertext, salt, nonce, mac, message_id=None):
    """Serialize ciphertext, salt, nonce, and HMAC to a JSON-compatible dict."""
    data: dict = {
        "scheme": "sha256-ctr-hmac",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac": mac.hex(),
    }
    if message_id:
        data["message_id"] = message_id
    return data


def ciphertext_from_json(data):
    """Deserialize ciphertext, salt, nonce, and HMAC from a JSON-compatible dict."""
    for field in ("ciphertext", "salt", "nonce", "hmac"):
        if field not in data:
            raise ValueError(f"Missing '{field}' field in ciphertext JSON")
    salt = bytes.fromhex(data["salt"])
    nonce = bytes.fromhex(data["nonce"])
    mac = bytes.fromhex(data["hmac"])
    if len(salt) != 16:
        raise ValueError(f"Salt must be 16 bytes, got {len(salt)}")
    if len(nonce) != 16:
        raise ValueError(f"Nonce must be 16 bytes, got {len(nonce)}")
    if len(mac) != 32:
        raise ValueError(f"HMAC must be 32 bytes, got {len(mac)}")
    return (
        bytes.fromhex(data["ciphertext"]),
        salt,
        nonce,
        mac,
    )


def save_json(data, filepath):
    """Write a dict to a JSON file."""
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


def load_json(filepath):
    """Read a dict from a JSON file."""
    with open(filepath, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _resolve_input(value, literal=False):
    """Resolve input to bytes.

    If literal is False and value is an existing file path, read the file.
    Otherwise treat as a UTF-8 string.
    """
    if not literal and os.path.isfile(value):
        with open(value, "rb") as f:
            return f.read()
    return value.encode("utf-8")


def cmd_keygen(args):
    out_dir = args.out_dir or "."
    os.makedirs(out_dir, exist_ok=True)

    private_key, public_key = generate_keypair()

    priv_path = os.path.join(out_dir, "private.key.json")
    pub_path = os.path.join(out_dir, "public.key.json")

    save_json(key_to_json(private_key, "private"), priv_path)
    save_json(key_to_json(public_key, "public"), pub_path)

    priv_size = os.path.getsize(priv_path)
    pub_size = os.path.getsize(pub_path)
    print(f"Keypair generated:")
    print(f"  Private key: {priv_path} ({priv_size / 1024:.1f} KB)")
    print(f"  Public key:  {pub_path} ({pub_size / 1024:.1f} KB)")
    print()
    print("WARNING: Each key pair can only sign ONE message.")


def cmd_encrypt(args):
    password = args.password
    if not password:
        password = getpass.getpass("Password: ")

    if args.file and args.message:
        print("Error: Provide either a message or --file, not both.")
        sys.exit(1)

    if args.file:
        input_path = args.file
        if not os.path.isfile(input_path):
            print(f"Error: File not found: {input_path}")
            sys.exit(1)
        out_path = args.output or (input_path + ".enc")
        encrypt_file(input_path, out_path, password)
        print(f"File encrypted to: {out_path}")
    elif args.message:
        plaintext = args.message.encode("utf-8")
        ciphertext, salt, nonce, mac = encrypt(plaintext, password)
        out_path = args.output or "ciphertext.json"
        save_json(ciphertext_to_json(ciphertext, salt, nonce, mac), out_path)
        print(f"Message encrypted to: {out_path}")
        print(f"  Ciphertext: {ciphertext.hex()[:64]}...")
    else:
        print("Error: Provide a message or use --file.")
        sys.exit(1)


def cmd_decrypt(args):
    password = args.password
    if not password:
        password = getpass.getpass("Password: ")

    # Detect format: try JSON first, fall back to binary
    is_json = False
    data = None
    try:
        data = load_json(args.file)
        is_json = True
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    if is_json:
        try:
            ciphertext, salt, nonce, mac = ciphertext_from_json(data)
        except ValueError as e:
            print(f"Error: Invalid ciphertext JSON: {e}")
            sys.exit(1)
        try:
            plaintext = decrypt(ciphertext, password, salt, nonce, mac)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

        if args.output:
            with open(args.output, "wb") as f:
                f.write(plaintext)
            print(f"Decrypted to: {args.output}")
        else:
            print(f"Decrypted message: {plaintext.decode('utf-8', errors='replace')}")
    else:
        # Binary format (from encrypt --file)
        if not args.output:
            print("Error: Binary encrypted file requires --output/-o for decrypted output.")
            sys.exit(1)
        try:
            decrypt_file(args.file, args.output, password)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        print(f"File decrypted to: {args.output}")


def cmd_sign(args):
    private_key_data = load_json(args.key)
    private_key = key_from_json(private_key_data)

    message_bytes = _resolve_input(args.input, literal=args.literal)
    signature = sign_message(private_key, message_bytes)

    out_path = args.output or "signature.json"
    save_json(signature_to_json(signature, message_bytes), out_path)

    print(f"Message signed.")
    print(f"  Signature: {out_path}")
    print()
    print("WARNING: This key pair has been used. Do NOT sign another message with it.")


def cmd_verify(args):
    public_key_data = load_json(args.key)
    public_key = key_from_json(public_key_data)

    sig_data = load_json(args.sig)
    signature = signature_from_json(sig_data)

    message_bytes = _resolve_input(args.input, literal=args.literal)
    valid = verify_signature(public_key, message_bytes, signature)

    if valid:
        print("Signature: VALID")
    else:
        print("Signature: INVALID")
    sys.exit(0 if valid else 1)


def main():
    parser = argparse.ArgumentParser(
        prog="mecrypt",
        description="Quantum-resistant encryption and authentication.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate a Lamport keypair")
    p_keygen.add_argument("--out-dir", help="Output directory (default: current dir)")
    p_keygen.set_defaults(func=cmd_keygen)

    # encrypt
    p_encrypt = subparsers.add_parser("encrypt", help="Encrypt a message or file")
    p_encrypt.add_argument("message", nargs="?", help="The message to encrypt")
    p_encrypt.add_argument("--file", "-f", help="File to encrypt (binary format)")
    p_encrypt.add_argument("--password", help="Encryption password (visible in process list; omit to use secure prompt)")
    p_encrypt.add_argument("--output", "-o", help="Output file (default: ciphertext.json or <file>.enc)")
    p_encrypt.set_defaults(func=cmd_encrypt)

    # decrypt
    p_decrypt = subparsers.add_parser("decrypt", help="Decrypt a ciphertext file")
    p_decrypt.add_argument("file", help="Ciphertext JSON or binary .enc file")
    p_decrypt.add_argument("--password", help="Decryption password (visible in process list; omit to use secure prompt)")
    p_decrypt.add_argument("--output", "-o", help="Output file (required for binary .enc files)")
    p_decrypt.set_defaults(func=cmd_decrypt)

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign a message or file")
    p_sign.add_argument("input", help="Message string or file path to sign")
    p_sign.add_argument("--key", required=True, help="Private key JSON file")
    p_sign.add_argument("--output", "-o", help="Output file (default: signature.json)")
    p_sign.add_argument("--literal", action="store_true", help="Treat input as a literal string even if it matches a file path")
    p_sign.set_defaults(func=cmd_sign)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify a signature")
    p_verify.add_argument("input", help="Message string or file path to verify")
    p_verify.add_argument("--key", required=True, help="Public key JSON file")
    p_verify.add_argument("--sig", required=True, help="Signature JSON file")
    p_verify.add_argument("--literal", action="store_true", help="Treat input as a literal string even if it matches a file path")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
