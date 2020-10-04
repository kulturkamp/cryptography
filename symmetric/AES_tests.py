import unittest
import time
from AES import AES


class TestBlockEncryption(unittest.TestCase):
    def setUp(self):
        self.aes128 = AES(b'z' * 16)
        self.aes192 = AES(b'x' * 24)
        self.aes256 = AES(b'c' * 32)

    def test_encr_block_128(self):
        message = b'M' * 16
        ciphertext = self.aes128.encrypt_block(message)
        self.assertEqual(self.aes128.decrypt_block(ciphertext), message)

        message = b'message 123 1234'
        ciphertext = self.aes128.encrypt_block(message)
        self.assertEqual(self.aes128.decrypt_block(ciphertext), message)

    def test_encr_block_192(self):
        message = b'\x01' * 16
        ciphertext = self.aes192.encrypt_block(message)
        self.assertEqual(self.aes192.decrypt_block(ciphertext), message)

        message = b'message 123 1234'
        ciphertext = self.aes192.encrypt_block(message)
        self.assertEqual(self.aes192.decrypt_block(ciphertext), message)

    def test_encr_block_256(self):
        message = b'\x01' * 16
        ciphertext = self.aes256.encrypt_block(message)
        self.assertEqual(self.aes256.decrypt_block(ciphertext), message)

        message = b'message 123 1234'
        ciphertext = self.aes256.encrypt_block(message)
        self.assertEqual(self.aes256.decrypt_block(ciphertext), message)


class TestChunkEncryption(unittest.TestCase):
    def setUp(self):
        self.aes = AES(b'z' * 16)
        self.iv = b'\x01' * 16

    def test_long_msg(self):
        message = b'M' * 228
        ciphertext = self.aes.encrypt(message, self.iv)
        self.assertEqual(self.aes.decrypt(ciphertext, self.iv), message)

    def test_diff_iv(self):
        iv2 = b'\x02' * 16
        message = b'M' * 16

        ciphertext1 = self.aes.encrypt(message, self.iv)
        ciphertext2 = self.aes.encrypt(message, iv2)
        self.assertNotEqual(ciphertext1, ciphertext2)

        plaintext1 = self.aes.decrypt(ciphertext1, self.iv)
        plaintext2 = self.aes.decrypt(ciphertext2, iv2)
        self.assertEqual(plaintext1, plaintext2)
        self.assertEqual(plaintext1, message)
        self.assertEqual(plaintext2, message)

    def test_bad_iv(self):
        message = b'M' * 16

        with self.assertRaises(AssertionError):
            self.aes.encrypt(message, b'short')

        with self.assertRaises(AssertionError):
            self.aes.encrypt(message, b'long' * 25)


class TestFileEncryption(unittest.TestCase):
    def setUp(self):
        self.aes = AES(b'z' * 16)
        self.iv = b'\x01' * 16

    def test_small_file_enctime(self):
        filename = "small.txt"
        start = time.time()
        self.aes.encrypt_file(filename, iv=self.iv)
        print(filename + "encrypted within %s seconds" % (time.time() - start))

    def test_small_file_dectime(self):
        filename = "small.txt.enc"
        start = time.time()
        self.aes.decrypt_file(filename)
        print(filename + "decrypted within %s seconds" % (time.time() - start))

    def test_2mbfile_enctime(self):
        filename = "lorem-ipsum.txt"
        start = time.time()
        self.aes.encrypt_file(filename, iv=self.iv)
        print(filename + " encrypted within %s seconds" % (time.time() - start))

    def test_2mbfile_dectime(self):
        filename = "lorem-ipsum.txt.enc"
        start = time.time()
        self.aes.decrypt_file(filename)
        print(filename + " decrypted within %s seconds" % (time.time() - start))

def run():
    unittest.main()


if __name__ == '__main__':
    run()