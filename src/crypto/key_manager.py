import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


class KeyManager:
    def __init__(self, iterations=100000):
        self.iterations = iterations

    def generate_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def verify_password(self, password, key, salt):
        generated_key, _ = self.generate_key(password, salt)
        return generated_key == key