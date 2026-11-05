import unittest
import hashlib
from app import hibp_match, generate_password
from password_tool import (
    calculate_entropy, evaluate_strength, hash_password,
    verify_password, sha256_fingerprint,
)

class PasswordToolTests(unittest.TestCase):
    def test_empty_entropy(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_dictionary_match(self):
        label, _ = evaluate_strength("Password", {"password"})
        self.assertEqual(label, "Critical risk")

    def test_hash_and_verify(self):
        encoded = hash_password("a-long-test-passphrase")
        self.assertTrue(verify_password("a-long-test-passphrase", encoded))
        self.assertFalse(verify_password("wrong-password", encoded))

    def test_hashes_are_salted(self):
        first = hash_password("same-password")
        second = hash_password("same-password")
        self.assertNotEqual(first, second)

    def test_hibp_suffix_match(self):
        password = "correct horse battery staple"
        digest = hashlib.sha1(password.encode()).hexdigest().upper()
        self.assertEqual(hibp_match(password, digest[5:] + ":42\n"), 42)
        self.assertEqual(hibp_match(password, "0" * 35 + ":1\n"), 0)

    def test_generator(self):
        generated = generate_password(24)
        self.assertEqual(len(generated), 24)
        self.assertTrue(any(c.islower() for c in generated))
        self.assertTrue(any(c.isupper() for c in generated))
        self.assertTrue(any(c.isdigit() for c in generated))
        self.assertTrue(any(not c.isalnum() for c in generated))

    def test_sha256_fingerprint(self):
        self.assertEqual(len(sha256_fingerprint("test")), 64)

if __name__ == "__main__":
    unittest.main()
