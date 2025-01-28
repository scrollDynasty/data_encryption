from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


class EncryptionAlgorithm:
    def __init__(self, key_size=256):
        self.key_size = key_size

    def encrypt(self, data, key):
        raise NotImplementedError

    def decrypt(self, data, key):
        raise NotImplementedError


class AESAlgorithm(EncryptionAlgorithm):
    def encrypt(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Добавляем padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Шифруем
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt(self, data, key):
        iv = data[:16]
        encrypted_data = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Расшифровываем
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Удаляем padding
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()