# Mecrypt

A Hash-Based Exploration of Quantum-Resistant Encryption

## What It Does

**Mecrypt** implements two *hash-only* quantum-resistant cryptographic primitives:

- **Encryption** — A hash-based stream cipher (SHA-256 in counter mode) with password-derived keys (PBKDF2) for message confidentiality
- **Authentication** — A [Lamport one-time signature scheme](https://en.wikipedia.org/wiki/Lamport_signature) for message integrity and sender verification

Together these provide both confidentiality (only someone with the password can read the message) and authenticity (the recipient can verify who sent it and that it wasn't tampered with).

**Why is this quantum-resistant?** Traditional encryption (RSA, ECC) relies on mathematical problems that quantum computers can solve efficiently using Shor's algorithm. Mecrypt relies only on SHA-256 hash functions, which are not vulnerable to Shor's algorithm. Grover's algorithm provides only a quadratic speedup against hash functions, which is mitigated by using 256-bit keys.

Hash based encryption is the underlying mathematical structure for the [Sphincs+ encryption scheme](https://sphincs.org) recently chosen by NIST for standardization.

## Encryption Structure

| Step | Primitive | Purpose |
|------|-----------|---------|
| 1. Key Derivation | PBKDF2 (100k iterations) | Hardens your password into a 512-bit master key, split into an encryption key and an authentication key. Done once per password+salt. |
| 2. Encryption | SHA-256 CTR (key + nonce + counter) | Scrambles the message with a unique per-message nonce so no one can read it. |
| 3. Integrity | HMAC-SHA256 | Seals the ciphertext so any tampering is detected immediately on attempted decryption. |
| 4. Identity | Lamport OTS | Proves the sender's identity — only the holder of the private key could have signed it. |

## How to Run

### Prerequisites

- Python 3.8+
- No external dependencies (uses only the Python standard library)

### Interactive Mode (Recommended)

```bash
python3 main.py
```

This launches a guided menu:

```
== mecrypt -- Quantum-Resistant Encryption & Signing ==

What would you like to do?
  [1] Encrypt & Sign Message    (Encryption & Lamport Signature)
  [2] Encrypt Message Only      (Encryption Only)
  [3] Verify & Decrypt Message  
  [4] Encrypt File
  [5] Decrypt File
  [q] Quit
```

- **Encrypt & Sign Message** generates a fresh Lamport keypair automatically, encrypts the message, signs the ciphertext, and saves everything to `messages/<id>/`. The signature is bundled into `ciphertext.json` alongside a separate `public.key.json`. Send the folder to the recipient.
- **Encrypt Message Only** encrypts a message with just the password-based cipher — no signing, for when you don't need sender authentication. Saves a single `ciphertext.json`.
- **Verify & Decrypt Message** accepts a message ID (looks in `messages/<id>/`) or a direct file path. Verifies the signature if present, then decrypts.
- **Encrypt File** encrypts any file using the password-based cipher. Produces a compact binary `.enc` file (salt + nonce + ciphertext + HMAC).
- **Decrypt File** decrypts a `.enc` file back to its original form. Verifies HMAC integrity before decrypting.

### Direct CLI

You can also use `mecrypt.py` directly with subcommands:

```bash
# Generate a Lamport keypair
python3 mecrypt.py keygen

# Encrypt a message
python3 mecrypt.py encrypt --password "mypassword" "example message"

# Encrypt a file (produces <filename>.enc in binary format)
python3 mecrypt.py encrypt --file document.pdf --password "mypassword"

# Encrypt a file with a custom output path
python3 mecrypt.py encrypt --file document.pdf --password "mypassword" -o secret.enc

# Sign a file (e.g. the ciphertext)
python3 mecrypt.py sign --key private.key.json ciphertext.json

# Verify a signature
python3 mecrypt.py verify --key public.key.json --sig signature.json ciphertext.json

# Decrypt a message
python3 mecrypt.py decrypt --password "example password" ciphertext.json

# Decrypt an encrypted file
python3 mecrypt.py decrypt --password "mypassword" -o document.pdf document.pdf.enc
```

### Running Tests

```bash
python3 -m unittest test_mecrypt.py -v
```

## Limitations

- **One-time signatures.** Each Lamport key pair can sign exactly one message. Reusing a key pair to sign a second message compromises the private key and breaks the security of the scheme. A production system would need a Merkle tree structure (e.g., XMSS) to manage many one-time keys.
- **Large key and signature sizes.** A single Lamport key pair is ~40 KB on disk and each signature is ~20 KB, far larger than classical schemes like RSA or ECDSA.
- **Custom stream cipher.** The encryption uses a SHA-256 CTR construction with PBKDF2 key derivation, per-message nonces, and HMAC-SHA256 authentication. While it follows standard patterns (nonce-based CTR + encrypt-then-MAC), it has not been formally analyzed. Production systems should use vetted algorithms like AES-256-GCM.
- **No formal security audit.** This code has not been reviewed by cryptographers and may contain implementation errors.

## Ethical Considerations and Responsible Use

This tool is intended as an educational demonstration of post-quantum cryptographic concepts.

**Known risks:**

- This tool does not provide production-grade security. It has not been formally audited and likely contains vulnerabilities.
- **Reusing a Lamport key pair (signing more than one message) silently degrades security.** The interactive mode (`main.py`) mitigates this by keeping private keys in memory only and deleting public keys after verification, but the direct CLI (`mecrypt.py`) has no such enforcement.
- The tool does not address the full security context of a real system (key exchange, transport, storage, etc.).
- The custom stream cipher has not been formally verified.

**Potential for misuse:**

- **False sense of security.** The biggest risk is someone using mecrypt to protect real sensitive data, believing it to be secure. It is not. The encryption and signing implementations are educational and have not been audited. Anyone needing actual confidentiality or authentication should use established, peer-reviewed libraries.
- **Misrepresentation.** Someone could fork this project, strip these warnings, and present it as a production-ready cryptographic tool. If you encounter mecrypt (or a derivative) being marketed as secure software, it is not — treat it with skepticism.
- **Learning the wrong lessons.** A working demo can give the impression that building your own cryptography is straightforward. In practice, custom cryptographic implementations are almost always insecure. The lesson this project is meant to teach is *how* these schemes work conceptually, not that rolling your own crypto is advisable.
- **Criminal use.** Any encryption tool — including this one — could be used to conceal illegal activity (e.g., transmitting illicit content) or as a component in ransomware (encrypting a victim's files and demanding payment for the key). This project is published solely for educational purposes and is not intended to facilitate any unlawful activity.

**About this project:**

- This was written by a CS major, undergraduate, college student. It likely has many vulnerabilities and should not be considered truly *quantum safe*. The objective is to demonstrate principles of quantum-safe encryption. 
- If you are interested in production post-quantum cryptography, use vetted implementations of NIST-standardized algorithms (e.g., ML-KEM, ML-DSA, SLH-DSA) from established libraries.
