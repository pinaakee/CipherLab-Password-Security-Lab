import unittest
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

    def test_sha256_fingerprint(self):
        self.assertEqual(len(sha256_fingerprint("test")), 64)

if __name__ == "__main__":
    unittest.main()
