#!/usr/bin/env python3
"""Unit tests for mecrypt core functions."""

import os
import tempfile
import unittest

import mecrypt


class TestKeygen(unittest.TestCase):
    def test_keypair_structure(self):
        """Keypair should have 256 pairs of 32-byte values."""
        private_key, public_key = mecrypt.generate_keypair()
        self.assertEqual(len(private_key), 256)
        self.assertEqual(len(public_key), 256)
        for sk_pair, pk_pair in zip(private_key, public_key):
            self.assertEqual(len(sk_pair), 2)
            self.assertEqual(len(pk_pair), 2)
            self.assertEqual(len(sk_pair[0]), 32)
            self.assertEqual(len(sk_pair[1]), 32)
            self.assertEqual(len(pk_pair[0]), 32)
            self.assertEqual(len(pk_pair[1]), 32)

    def test_keypair_randomness(self):
        """Two generated keypairs should differ."""
        kp1 = mecrypt.generate_keypair()
        kp2 = mecrypt.generate_keypair()
        self.assertNotEqual(kp1[0], kp2[0])


class TestSignVerify(unittest.TestCase):
    def setUp(self):
        self.private_key, self.public_key = mecrypt.generate_keypair()
        self.message = b"hello world"

    def test_sign_verify_roundtrip(self):
        """A valid signature should verify successfully."""
        signature = mecrypt.sign_message(self.private_key, self.message)
        self.assertTrue(mecrypt.verify_signature(self.public_key, self.message, signature))

    def test_verify_rejects_wrong_message(self):
        """Signature should not verify against a different message."""
        signature = mecrypt.sign_message(self.private_key, self.message)
        self.assertFalse(mecrypt.verify_signature(self.public_key, b"wrong message", signature))

    def test_verify_rejects_tampered_signature(self):
        """A tampered signature should not verify."""
        signature = mecrypt.sign_message(self.private_key, self.message)
        tampered = list(signature)
        original = bytearray(tampered[0])
        original[0] ^= 0xFF
        tampered[0] = bytes(original)
        self.assertFalse(mecrypt.verify_signature(self.public_key, self.message, tampered))

    def test_signature_length(self):
        """Signature should contain exactly 256 values of 32 bytes each."""
        signature = mecrypt.sign_message(self.private_key, self.message)
        self.assertEqual(len(signature), 256)
        for value in signature:
            self.assertEqual(len(value), 32)


class TestEncryptDecrypt(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        """Encrypting then decrypting should recover the original plaintext."""
        plaintext = b"the quick brown fox jumps over the lazy dog"
        password = "testpassword123"
        ciphertext, salt, nonce, mac = mecrypt.encrypt(plaintext, password)
        recovered = mecrypt.decrypt(ciphertext, password, salt, nonce, mac)
        self.assertEqual(plaintext, recovered)

    def test_wrong_password_raises(self):
        """Decrypting with the wrong password should raise ValueError (HMAC fail)."""
        plaintext = b"secret message"
        ciphertext, salt, nonce, mac = mecrypt.encrypt(plaintext, "correct")
        with self.assertRaises(ValueError):
            mecrypt.decrypt(ciphertext, "wrong", salt, nonce, mac)

    def test_tampered_ciphertext_raises(self):
        """Tampered ciphertext should raise ValueError (HMAC fail)."""
        plaintext = b"important data"
        ciphertext, salt, nonce, mac = mecrypt.encrypt(plaintext, "password")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with self.assertRaises(ValueError):
            mecrypt.decrypt(bytes(tampered), "password", salt, nonce, mac)

    def test_different_nonces(self):
        """Same plaintext and password should produce different ciphertext (random nonce)."""
        plaintext = b"same message"
        ct1, salt1, nonce1, mac1 = mecrypt.encrypt(plaintext, "password")
        ct2, salt2, nonce2, mac2 = mecrypt.encrypt(plaintext, "password")
        self.assertNotEqual(nonce1, nonce2)
        self.assertNotEqual(ct1, ct2)

    def test_ciphertext_differs_from_plaintext(self):
        """Ciphertext should not equal plaintext."""
        plaintext = b"this should be encrypted"
        ciphertext, _, _, _ = mecrypt.encrypt(plaintext, "password")
        self.assertNotEqual(plaintext, ciphertext)

    def test_empty_message(self):
        """Encrypting an empty message should work."""
        ciphertext, salt, nonce, mac = mecrypt.encrypt(b"", "password")
        self.assertEqual(ciphertext, b"")
        recovered = mecrypt.decrypt(ciphertext, "password", salt, nonce, mac)
        self.assertEqual(recovered, b"")

    def test_large_message_chunked(self):
        """Messages larger than CHUNK_SIZE should encrypt/decrypt correctly."""
        plaintext = os.urandom(mecrypt.CHUNK_SIZE * 2 + 1000)  # ~131 KB
        password = "chunked"
        ciphertext, salt, nonce, mac = mecrypt.encrypt(plaintext, password)
        recovered = mecrypt.decrypt(ciphertext, password, salt, nonce, mac)
        self.assertEqual(plaintext, recovered)


class TestDeriveKeys(unittest.TestCase):
    def test_deterministic_with_same_salt(self):
        """Same password + salt should produce same keys."""
        enc1, auth1, salt = mecrypt.derive_keys("password")
        enc2, auth2, _ = mecrypt.derive_keys("password", salt)
        self.assertEqual(enc1, enc2)
        self.assertEqual(auth1, auth2)

    def test_different_keys_for_enc_and_auth(self):
        """Encryption key and auth key should differ."""
        enc_key, auth_key, _ = mecrypt.derive_keys("password")
        self.assertNotEqual(enc_key, auth_key)

    def test_key_lengths(self):
        """Both keys should be 32 bytes."""
        enc_key, auth_key, salt = mecrypt.derive_keys("password")
        self.assertEqual(len(enc_key), 32)
        self.assertEqual(len(auth_key), 32)
        self.assertEqual(len(salt), 16)


class TestFileEncryption(unittest.TestCase):
    def test_encrypt_decrypt_file_roundtrip(self):
        """File encryption and decryption should recover original content."""
        plaintext = b"file content for testing" * 100
        password = "filepassword"

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "plain.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            output_path = os.path.join(tmpdir, "decrypted.txt")

            with open(input_path, "wb") as f:
                f.write(plaintext)

            mecrypt.encrypt_file(input_path, encrypted_path, password)
            mecrypt.decrypt_file(encrypted_path, output_path, password)

            with open(output_path, "rb") as f:
                recovered = f.read()

            self.assertEqual(plaintext, recovered)

    def test_file_tampered_raises(self):
        """Tampered encrypted file should raise ValueError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "plain.txt")
            encrypted_path = os.path.join(tmpdir, "encrypted.bin")
            output_path = os.path.join(tmpdir, "decrypted.txt")

            with open(input_path, "wb") as f:
                f.write(b"sensitive data")

            mecrypt.encrypt_file(input_path, encrypted_path, "password")

            # Tamper with the ciphertext (byte 33, after salt+nonce header)
            with open(encrypted_path, "r+b") as f:
                f.seek(33)
                byte = f.read(1)
                f.seek(33)
                f.write(bytes([byte[0] ^ 0xFF]))

            with self.assertRaises(ValueError):
                mecrypt.decrypt_file(encrypted_path, output_path, "password")

    def test_large_file(self):
        """File larger than CHUNK_SIZE should work."""
        plaintext = os.urandom(mecrypt.CHUNK_SIZE * 3)

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "large.bin")
            encrypted_path = os.path.join(tmpdir, "large.enc")
            output_path = os.path.join(tmpdir, "large.dec")

            with open(input_path, "wb") as f:
                f.write(plaintext)

            mecrypt.encrypt_file(input_path, encrypted_path, "bigfile")
            mecrypt.decrypt_file(encrypted_path, output_path, "bigfile")

            with open(output_path, "rb") as f:
                recovered = f.read()

            self.assertEqual(plaintext, recovered)


class TestSerialization(unittest.TestCase):
    def test_key_roundtrip(self):
        """Keys should survive JSON serialization."""
        private_key, public_key = mecrypt.generate_keypair()
        priv_json = mecrypt.key_to_json(private_key, "private")
        pub_json = mecrypt.key_to_json(public_key, "public")
        priv_recovered = mecrypt.key_from_json(priv_json)
        pub_recovered = mecrypt.key_from_json(pub_json)
        self.assertEqual(private_key, priv_recovered)
        self.assertEqual(public_key, pub_recovered)

    def test_signature_roundtrip(self):
        """Signatures should survive JSON serialization."""
        private_key, _ = mecrypt.generate_keypair()
        message = b"test"
        signature = mecrypt.sign_message(private_key, message)
        sig_json = mecrypt.signature_to_json(signature, message)
        sig_recovered = mecrypt.signature_from_json(sig_json)
        self.assertEqual(signature, sig_recovered)

    def test_ciphertext_roundtrip(self):
        """Ciphertext should survive JSON serialization."""
        ciphertext, salt, nonce, mac = mecrypt.encrypt(b"test message", "pw")
        ct_json = mecrypt.ciphertext_to_json(ciphertext, salt, nonce, mac)
        ct_r, salt_r, nonce_r, mac_r = mecrypt.ciphertext_from_json(ct_json)
        self.assertEqual(ciphertext, ct_r)
        self.assertEqual(salt, salt_r)
        self.assertEqual(nonce, nonce_r)
        self.assertEqual(mac, mac_r)


class TestFullWorkflow(unittest.TestCase):
    def test_encrypt_sign_verify_decrypt(self):
        """Full workflow: keygen -> encrypt -> sign -> verify -> decrypt."""
        private_key, public_key = mecrypt.generate_keypair()

        plaintext = b"quantum-resistant hello world"
        password = "strongpassword"
        ciphertext, salt, nonce, mac = mecrypt.encrypt(plaintext, password)

        # Sign the ciphertext
        signature = mecrypt.sign_message(private_key, ciphertext)

        # Verify the signature
        self.assertTrue(mecrypt.verify_signature(public_key, ciphertext, signature))

        # Decrypt
        recovered = mecrypt.decrypt(ciphertext, password, salt, nonce, mac)
        self.assertEqual(plaintext, recovered)

    def test_tampered_ciphertext_fails_both(self):
        """Tampered ciphertext should fail both signature and HMAC verification."""
        private_key, public_key = mecrypt.generate_keypair()
        ciphertext, salt, nonce, mac = mecrypt.encrypt(b"original", "password")
        signature = mecrypt.sign_message(private_key, ciphertext)

        # Tamper
        tampered_ct = bytearray(ciphertext)
        tampered_ct[0] ^= 0xFF
        tampered_ct = bytes(tampered_ct)

        # Signature check fails
        self.assertFalse(mecrypt.verify_signature(public_key, tampered_ct, signature))

        # HMAC check fails
        with self.assertRaises(ValueError):
            mecrypt.decrypt(tampered_ct, "password", salt, nonce, mac)


if __name__ == "__main__":
    unittest.main()
