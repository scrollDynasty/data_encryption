from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import os
import base64
from datetime import datetime


class EncryptionAlgorithm:
    def __init__(self, key_size=256):
        self.key_size = key_size
        self.salt = os.urandom(16)
        self.current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    def encrypt(self, data, key):
        raise NotImplementedError

    def decrypt(self, data, key):
        raise NotImplementedError

    def generate_key(self, password):
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key
        except Exception as e:
            raise Exception(f"Key generation error: {str(e)}")


class AESAlgorithm(EncryptionAlgorithm):
    def __init__(self, key_size=256):
        super().__init__(key_size)
        self.block_size = 128

    def encrypt(self, data, key):
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(self.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()

            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            metadata = {
                'algorithm': 'AES',
                'mode': 'CBC',
                'timestamp': self.current_time,
                'key_size': self.key_size
            }

            metadata_bytes = str(metadata).encode()

            return self.salt + iv + len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + encrypted_data
        except Exception as e:
            raise Exception(f"Encryption error: {str(e)}")

    def decrypt(self, data, key):
        try:
            salt = data[:16]
            iv = data[16:32]
            metadata_len = int.from_bytes(data[32:36], 'big')
            metadata_bytes = data[36:36 + metadata_len]
            encrypted_data = data[36 + metadata_len:]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()

            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            unpadder = padding.PKCS7(self.block_size).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")


class RSAAlgorithm(EncryptionAlgorithm):
    def __init__(self, key_size=2048):
        super().__init__(key_size)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, data, key=None):
        try:
            encrypted_data = self.public_key.encrypt(
                data,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_data
        except Exception as e:
            raise Exception(f"RSA encryption error: {str(e)}")

    def decrypt(self, data, key=None):
        try:
            decrypted_data = self.private_key.decrypt(
                data,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_data
        except Exception as e:
            raise Exception(f"RSA decryption error: {str(e)}")


class FernetAlgorithm(EncryptionAlgorithm):
    def encrypt(self, data, key):
        try:
            f = Fernet(key)
            return self.salt + f.encrypt(data)
        except Exception as e:
            raise Exception(f"Fernet encryption error: {str(e)}")

    def decrypt(self, data, key):
        try:
            salt = data[:16]
            encrypted_data = data[16:]
            f = Fernet(key)
            return f.decrypt(encrypted_data)
        except Exception as e:
            raise Exception(f"Fernet decryption error: {str(e)}")


def get_algorithm(algorithm_name, key_size=256):
    algorithms = {
        'AES': AESAlgorithm,
        'RSA': RSAAlgorithm,
        'FERNET': FernetAlgorithm
    }
    if algorithm_name.upper() not in algorithms:
        raise ValueError(f"Unsupported algorithm: {algorithm_name}")
    return algorithms[algorithm_name.upper()](key_size)