#!/usr/bin/env python3
"""Password strength checker and password hashing utility.

Uses scrypt for password storage hashes. SHA-256 is available only as a
non-storage fingerprint/demo because fast hashes are unsuitable for passwords.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import math
import os
import re
import secrets
import sys
from pathlib import Path
from getpass import getpass

FALLBACK_COMMON = {
    "123456", "password", "123456789", "12345678", "qwerty",
    "1234567", "111111", "123123", "admin", "letmein",
    "welcome", "iloveyou", "monkey", "abc123", "password1",
}
DEFAULT_WORDLIST = Path(__file__).parent / "data" / "common_passwords.txt"


def load_dictionary(filepath: str | Path = DEFAULT_WORDLIST) -> set[str]:
    """Load a local newline-separated password list, with a safe fallback."""
    path = Path(filepath)
    if not path.is_file():
        return FALLBACK_COMMON.copy()
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            return {line.strip().casefold() for line in handle if line.strip()}
    except OSError as exc:
        print(f"[!] Could not read wordlist ({exc}); using fallback list.", file=sys.stderr)
        return FALLBACK_COMMON.copy()


def calculate_entropy(password: str) -> float:
    """Return a rough character-pool entropy estimate in bits.

    This is a heuristic, not a true measure of guessability. It does not model
    dictionary words, keyboard patterns, reuse, or predictable substitutions.
    """
    if not password:
        return 0.0
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 33
    return round(len(password) * math.log2(pool_size), 2) if pool_size else 0.0


def evaluate_strength(password: str, dictionary_set: set[str]) -> tuple[str, list[str]]:
    """Return a strength label and actionable feedback."""
    reasons: list[str] = []
    if not password:
        return "Very weak", ["Enter a password."]
    if password.casefold() in dictionary_set:
        return "Critical risk", ["This password appears in the local common-password list. Do not use it."]

    entropy = calculate_entropy(password)
    if len(password) < 12:
        reasons.append("Use at least 12 characters;  passphrases can be easier to remember.")
    if len(password) < 16:
        reasons.append("For important accounts, aim for 16+ characters.")
    if re.search(r"(.)\1{2,}", password):
        reasons.append("Avoid repeated characters.")
    if re.search(r"1234|abcd|qwerty|password", password, re.IGNORECASE):
        reasons.append("Avoid predictable sequences and common words.")

    if entropy < 40:
        label = "Very weak"
    elif entropy < 60:
        label = "Weak"
    elif entropy < 80:
        label = "Moderate"
    else:
        label = "Strong (estimated)"
    if not reasons:
        reasons.append("No obvious issues detected by these basic checks.")
    reasons.append("Entropy is only a rough estimate; length and uniqueness matter more than forced character variety.")
    return label, reasons


def sha256_fingerprint(password: str) -> str:
    """Return a SHA-256 fingerprint for demonstrations, NOT password storage."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def hash_password(password: str, *, n: int = 2**14, r: int = 8, p: int = 1,
                  salt: bytes | None = None) -> str:
    """Create a salted scrypt hash string suitable for password verification."""
    if not password:
        raise ValueError("Password must not be empty.")
    if n < 2 or n & (n - 1):
        raise ValueError("scrypt n must be a power of two greater than 1.")
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    """Verify a password against a hash created by hash_password()."""
    try:
        algorithm, n_text, r_text, p_text, salt_hex, digest_hex = encoded_hash.split("$")
        if algorithm != "scrypt":
            return False
        n, r, p = int(n_text), int(r_text), int(p_text)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def interactive() -> int:
    print("\nPassword Security Tool")
    print("======================")
    print("1. Check password strength")
    print("2. Create secure password hash (scrypt)")
    print("3. Verify password against a scrypt hash")
    print("4. Show SHA-256 fingerprint (demo only)")
    choice = input("\nChoose an option [1-4]: ").strip()
    wordlist = load_dictionary()
    if choice == "1":
        password = getpass("Password (hidden): ")
        label, feedback = evaluate_strength(password, wordlist)
        print(f"\nStrength: {label}")
        print(f"Estimated entropy: {calculate_entropy(password)} bits")
        for item in feedback:
            print(f"- {item}")
    elif choice == "2":
        password = getpass("Password to hash (hidden): ")
        try:
            print("\nStore this hash, not the password:")
            print(hash_password(password))
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
    elif choice == "3":
        encoded = input("Paste stored scrypt hash: ").strip()
        password = getpass("Password to verify (hidden): ")
        print("MATCH: password verified." if verify_password(password, encoded)
              else "NO MATCH: password was not verified.")
    elif choice == "4":
        password = getpass("Password (hidden): ")
        print("\nSHA-256 fingerprint (not suitable for password storage):")
        print(sha256_fingerprint(password))
    else:
        print("Please choose 1, 2, 3, or 4.")
        return 2
    return 0


def main() -> int:
    global DEFAULT_WORDLIST
    parser = argparse.ArgumentParser(description="Password strength checker and secure hashing utility.")
    parser.add_argument("--wordlist", default=str(DEFAULT_WORDLIST), help="Optional newline-separated password list.")
    args = parser.parse_args()
    DEFAULT_WORDLIST = Path(args.wordlist)
    return interactive()


if __name__ == "__main__":
    raise SystemExit(main())
