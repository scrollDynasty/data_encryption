from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


class FileEncryptor:
    def __init__(self):
        self.salt = os.urandom(16)

    def generate_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_file(self, input_file, output_file, password):
        key = self.generate_key(password)
        f = Fernet(key)

        with open(input_file, 'rb') as file:
            file_data = file.read()

        encrypted_data = f.encrypt(file_data)

        with open(output_file, 'wb') as file:
            file.write(self.salt)
            file.write(encrypted_data)

    def decrypt_file(self, input_file, output_file, password):
        with open(input_file, 'rb') as file:
            self.salt = file.read(16)
            encrypted_data = file.read()

        key = self.generate_key(password)
        f = Fernet(key)

        try:
            decrypted_data = f.decrypt(encrypted_data)
            with open(output_file, 'wb') as file:
                file.write(decrypted_data)
            return True
        except Exception:
            return False