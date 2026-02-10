#!/usr/bin/env python3
"""
mecrypt interactive CLI — Quantum-resistant encryption and authentication.

Provides a guided, menu-driven interface to mecrypt's core functionality:
  [1] Encrypt & Sign (for sending to someone)
  [2] Encrypt Only (for personal use)
  [3] Verify & Decrypt
  [4] Encrypt File
  [5] Decrypt File
"""

import getpass
import os
import sys
import uuid

import mecrypt

MESSAGES_DIR = "messages"


# PROGRESS BAR
# ---

def progress_bar(current, total, width=32):
    """Print an in-place progress bar to stdout."""
    filled = int(width * current / total)
    bar = "\u2588" * filled + "\u2591" * (width - filled)
    sys.stdout.write(f"\r        {bar} {current}/{total}")
    sys.stdout.flush()
    if current == total:
        sys.stdout.write("\n")


# INPUT HELPERS
# ---

def prompt_with_default(message, default):
    """Prompt for input, returning a default if the user presses Enter."""
    value = input(f"{message} [{default}]: ").strip()
    return value if value else default


def prompt_password_confirmed():
    """Prompt for a password twice and verify they match."""
    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password == confirm:
            return password
        print("Passwords do not match. Try again.")


def prompt_multiline(message):
    """Prompt for multiline input. An empty line finishes."""
    print(f"{message} (press Enter twice to finish):")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


def generate_message_id():
    """Generate an 8-character hex message ID."""
    return uuid.uuid4().hex[:8]


# WORKFLOWS
# ---

def flow_encrypt_and_sign():
    """Encrypt a message, auto-generate a Lamport keypair, and sign."""
    print()

    # Gather inputs
    message = prompt_multiline("Enter your message")
    if not message:
        print("No message entered. Aborting.")
        return
    password = prompt_password_confirmed()

    msg_id = generate_message_id()
    msg_dir = os.path.join(MESSAGES_DIR, msg_id)
    os.makedirs(msg_dir, exist_ok=True)

    print()
    print(f"  Message ID: {msg_id}")
    print()
    plaintext = message.encode("utf-8")

    # Step 1: Generate Lamport keypair
    print("  [1/4] Generating Lamport keypair...")
    private_key, public_key = mecrypt.generate_keypair(progress_callback=progress_bar)

    # Step 2: Encrypt
    print("  [2/4] Encrypting message (PBKDF2 + SHA-256 CTR + HMAC)...")
    ciphertext, salt, nonce, mac = mecrypt.encrypt(plaintext, password)

    # Step 3: Sign the ciphertext
    print("  [3/4] Signing ciphertext with Lamport OTS...")
    signature = mecrypt.sign_message(private_key, ciphertext, progress_callback=progress_bar)

    # Step 4: Save files (private key never touches disk)
    print("  [4/4] Saving output files...")

    # Bundle signature into ciphertext JSON
    ct_json = mecrypt.ciphertext_to_json(ciphertext, salt, nonce, mac, msg_id)
    ct_json["signature"] = mecrypt.signature_to_json(signature, ciphertext, msg_id)

    ct_path = os.path.join(msg_dir, "ciphertext.json")
    pub_path = os.path.join(msg_dir, "public.key.json")

    mecrypt.save_json(ct_json, ct_path)
    mecrypt.save_json(mecrypt.key_to_json(public_key, "public", msg_id), pub_path)

    print()
    print("Message encrypted and signed:")
    print(f"  Ciphertext: ./{ct_path}")
    print(f"  Public key: ./{pub_path}")
    print()
    print(f"Send the {msg_dir}/ folder to the recipient.")


def flow_encrypt_only():
    """Encrypt a message without signing (no Lamport keys needed)."""
    print()

    # Gather inputs
    message = prompt_multiline("Enter your message")
    if not message:
        print("No message entered. Aborting.")
        return
    password = prompt_password_confirmed()

    print()
    plaintext = message.encode("utf-8")

    # Step 1: Encrypt
    print("  [1/2] Encrypting message (PBKDF2 + SHA-256 CTR + HMAC)...")
    ciphertext, salt, nonce, mac = mecrypt.encrypt(plaintext, password)

    # Step 2: Save
    ct_path = "ciphertext.json"
    print(f"  [2/2] Saving to ./{ct_path}...")
    mecrypt.save_json(mecrypt.ciphertext_to_json(ciphertext, salt, nonce, mac), ct_path)

    print()
    print("Message encrypted:")
    print(f"  Ciphertext: ./{ct_path}")


def flow_encrypt_file():
    """Encrypt a file with password-based encryption (binary format)."""
    print()

    file_path = input("File to encrypt: ").strip()
    if not file_path:
        print("No file path entered. Aborting.")
        return
    if not os.path.isfile(file_path):
        print(f"Error: File not found: {file_path}")
        return

    password = prompt_password_confirmed()

    default_out = file_path + ".enc"
    out_path = prompt_with_default("Output file", default_out)

    print()
    print(f"  [1/1] Encrypting {os.path.basename(file_path)} (PBKDF2 + SHA-256 CTR + HMAC)...")
    mecrypt.encrypt_file(file_path, out_path, password)

    in_size = os.path.getsize(file_path)
    out_size = os.path.getsize(out_path)
    print()
    print("File encrypted:")
    print(f"  Input:  {file_path} ({in_size:,} bytes)")
    print(f"  Output: {out_path} ({out_size:,} bytes)")


def flow_decrypt_file():
    """Decrypt a binary-format encrypted file."""
    print()

    file_path = input("Encrypted file (.enc): ").strip()
    if not file_path:
        print("No file path entered. Aborting.")
        return
    if not os.path.isfile(file_path):
        print(f"Error: File not found: {file_path}")
        return

    # Default output: strip .enc suffix if present
    if file_path.endswith(".enc"):
        default_out = file_path[:-4]
    else:
        default_out = file_path + ".dec"
    out_path = prompt_with_default("Output file", default_out)

    password = getpass.getpass("Password: ")

    print()
    print(f"  [1/1] Decrypting {os.path.basename(file_path)}...")
    try:
        mecrypt.decrypt_file(file_path, out_path, password)
    except ValueError as e:
        print(f"  Error: {e}")
        return

    out_size = os.path.getsize(out_path)
    print()
    print("File decrypted:")
    print(f"  Output: {out_path} ({out_size:,} bytes)")


def flow_verify_and_decrypt():
    """Verify a signature (if present) and decrypt the ciphertext."""
    print()

    # Determine input method: message ID or direct file path
    default = "ciphertext.json" if os.path.isfile("ciphertext.json") else None
    if default:
        identifier = prompt_with_default("Message ID or ciphertext file path", default)
    else:
        identifier = input("Message ID or ciphertext file path: ").strip()
    if not identifier:
        print("No input provided. Aborting.")
        return

    # Resolve file paths
    msg_id = None
    msg_dir = None
    if os.path.isfile(identifier):
        # User provided a direct file path
        ct_path = identifier
    else:
        # Treat as a message ID — check messages/ folder
        msg_id = identifier
        msg_dir = os.path.join(MESSAGES_DIR, msg_id)
        ct_path = os.path.join(msg_dir, "ciphertext.json")
        if not os.path.isfile(ct_path):
            print(f"Error: Ciphertext not found at {ct_path}")
            return

    password = getpass.getpass("Password: ")
    print()

    # Load ciphertext
    ct_data = mecrypt.load_json(ct_path)
    ciphertext, salt, nonce, mac = mecrypt.ciphertext_from_json(ct_data)

    # Check for signature — bundled in ciphertext JSON or separate file
    sig_valid = None
    has_signature = False
    signature = None
    public_key = None
    pub_key_path = None

    if "signature" in ct_data:
        # Signature bundled in ciphertext JSON
        has_signature = True
        signature = mecrypt.signature_from_json(ct_data["signature"])
        # Look for public key in same folder
        if msg_dir:
            pub_key_path = os.path.join(msg_dir, "public.key.json")
        else:
            pub_key_path = None
        if pub_key_path and os.path.isfile(pub_key_path):
            pub_key_data = mecrypt.load_json(pub_key_path)
            public_key = mecrypt.key_from_json(pub_key_data)
        else:
            has_signature = False

    # Calculate total steps
    has_cleanup = msg_dir is not None
    total_steps = 2  # decrypt + save (always)
    if has_signature:
        total_steps += 1  # verify signature
    if has_cleanup:
        total_steps += 1  # cleanup consumed files

    step = 1

    # Step: Verify Lamport signature (if present)
    if has_signature:
        print(f"  [{step}/{total_steps}] Verifying Lamport signature...")
        sig_valid = mecrypt.verify_signature(public_key, ciphertext, signature, progress_callback=progress_bar)

        if not sig_valid:
            print()
            print("WARNING: Signature INVALID -- the message may have been tampered with!")
            print()
        step += 1

    # Step: Decrypt (HMAC verification happens inside mecrypt.decrypt)
    print(f"  [{step}/{total_steps}] Decrypting message (verifying HMAC)...")
    try:
        plaintext = mecrypt.decrypt(ciphertext, password, salt, nonce, mac)
    except ValueError as e:
        print(f"\n  ERROR: {e}")
        print()
        print("Decryption failed. Check your password and try again.")
        return
    step += 1

    # Step: Save decrypted message
    if msg_dir:
        msg_path = os.path.join(msg_dir, "message.json")
    else:
        msg_path = "message.json"
    print(f"  [{step}/{total_steps}] Saving decrypted message to ./{msg_path}...")

    msg_data: dict = {
        "message": plaintext.decode("utf-8", errors="replace"),
    }
    if sig_valid is not None:
        msg_data["signature_valid"] = sig_valid
    mecrypt.save_json(msg_data, msg_path)
    step += 1

    # Step: Clean up consumed files (only in message-ID mode)
    if has_cleanup:
        print(f"  [{step}/{total_steps}] Cleaning up consumed files...")
        if os.path.isfile(ct_path):
            os.remove(ct_path)
            print(f"         Deleted ciphertext: {ct_path}")
        if has_signature and pub_key_path and os.path.isfile(pub_key_path):
            os.remove(pub_key_path)
            print(f"         Deleted public key: {pub_key_path}")

    print()
    if sig_valid is not None:
        print(f"Signature: {'VALID' if sig_valid else 'INVALID'}")
    print(f"HMAC:      VALID")
    print(f"Message:   {plaintext.decode('utf-8', errors='replace')}")
    print(f"Saved to:  ./{msg_path}")


# MENU
# ---

def main():
    print()
    print("== mecrypt -- Quantum-Resistant Encryption & Signing ==")

    try:
        while True:
            print()
            print("What would you like to do?")
            print("  [1] Encrypt & Sign Message     (Encryption & Lamport Signature)")
            print("  [2] Encrypt Message Only       (Encryption Only)")
            print("  [3] Verify & Decrypt Message")
            print("  [4] Encrypt File")
            print("  [5] Decrypt File")
            print("  [q] Quit")
            print()

            choice = input("> ").strip().lower()

            if choice == "1":
                flow_encrypt_and_sign()
            elif choice == "2":
                flow_encrypt_only()
            elif choice == "3":
                flow_verify_and_decrypt()
            elif choice == "4":
                flow_encrypt_file()
            elif choice == "5":
                flow_decrypt_file()
            elif choice in ("q", "quit", "exit"):
                print("Goodbye.")
                break
            else:
                print("Invalid choice. Please enter 1-5 or q.")
    except KeyboardInterrupt:
        print()
        print("Goodbye.")


if __name__ == "__main__":
    main()
