import unittest

from crypto_tool import decrypt_bytes, encrypt_bytes


class CryptoToolTests(unittest.TestCase):
    def test_round_trip_for_all_algorithms_and_binary_data(self) -> None:
        original = bytes(range(256)) * 3
        for algorithm in ("AES", "DES", "RC4"):
            with self.subTest(algorithm=algorithm):
                envelope = encrypt_bytes(original, "password-kuat", algorithm, "sample.bin")
                restored, name = decrypt_bytes(envelope, "password-kuat")
                self.assertEqual(restored, original)
                self.assertEqual(name, "sample.bin")

    def test_wrong_password_is_rejected(self) -> None:
        envelope = encrypt_bytes(b"rahasia", "benar", "AES")
        with self.assertRaises(ValueError):
            decrypt_bytes(envelope, "salah")


if __name__ == "__main__":
    unittest.main()
