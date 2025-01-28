import os
from base64 import b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import logging
from datetime import datetime


class FileEncryptor:
    def __init__(self):
        self.salt = os.urandom(16)
        self.iv = os.urandom(16)
        self.setup_logging()

    def setup_logging(self):
        self.logger = logging.getLogger('FileEncryptor')
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler('encryption.log')
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def generate_key(self, password, algorithm):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = kdf.derive(password.encode())

        if algorithm == "Fernet":
            key = b64encode(key)
        return key

    def encrypt_file(self, input_file, output_file, password, algorithm="Fernet", chunk_size=64 * 1024,
                     progress_callback=None):
        try:
            key = self.generate_key(password, algorithm)
            total_processed = 0
            file_size = os.path.getsize(input_file)

            if algorithm == "Fernet":
                f = Fernet(key)
                with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
                    out_file.write(algorithm.encode())
                    out_file.write(b'\0' * (16 - len(algorithm)))
                    out_file.write(self.salt)

                    while chunk := in_file.read(chunk_size):
                        encrypted_chunk = f.encrypt(chunk)
                        out_file.write(encrypted_chunk)
                        total_processed += len(chunk)
                        if progress_callback:
                            progress_callback(total_processed)

            elif algorithm == "AES":
                cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(128).padder()

                with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
                    out_file.write(algorithm.encode())
                    out_file.write(b'\0' * (16 - len(algorithm)))
                    out_file.write(self.salt)
                    out_file.write(self.iv)

                    while chunk := in_file.read(chunk_size):
                        padded_chunk = padder.update(chunk)
                        encrypted_chunk = encryptor.update(padded_chunk)
                        out_file.write(encrypted_chunk)
                        total_processed += len(chunk)
                        if progress_callback:
                            progress_callback(total_processed)

                    final_padded_chunk = padder.finalize()
                    final_encrypted_chunk = encryptor.update(final_padded_chunk) + encryptor.finalize()
                    out_file.write(final_encrypted_chunk)
                    if progress_callback:
                        progress_callback(file_size)

            self.log_operation("encryption", input_file, "success")
            return True
        except Exception as e:
            self.log_operation("encryption", input_file, "failed", str(e))
            raise

    def decrypt_file(self, input_file, output_file, password, chunk_size=64 * 1024, progress_callback=None):
        try:
            total_processed = 0
            file_size = os.path.getsize(input_file)

            with open(input_file, 'rb') as file:
                algorithm = file.read(16).decode().rstrip('\0')
                self.salt = file.read(16)
                if algorithm == "AES":
                    self.iv = file.read(16)

                key = self.generate_key(password, algorithm)

                if algorithm == "Fernet":
                    f = Fernet(key)
                    with open(output_file, 'wb') as out_file:
                        while chunk := file.read(chunk_size):
                            decrypted_chunk = f.decrypt(chunk)
                            out_file.write(decrypted_chunk)
                            total_processed += len(chunk)
                            if progress_callback:
                                progress_callback(total_processed)

                elif algorithm == "AES":
                    cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
                    decryptor = cipher.decryptor()
                    unpadder = padding.PKCS7(128).unpadder()

                    with open(output_file, 'wb') as out_file:
                        while chunk := file.read(chunk_size):
                            decrypted_chunk = decryptor.update(chunk)
                            try:
                                unpadded_chunk = unpadder.update(decrypted_chunk)
                                out_file.write(unpadded_chunk)
                            except ValueError:
                                pass
                            total_processed += len(chunk)
                            if progress_callback:
                                progress_callback(total_processed)

                        final_chunk = decryptor.finalize()
                        final_unpadded_chunk = unpadder.finalize()
                        out_file.write(final_unpadded_chunk)
                        if progress_callback:
                            progress_callback(file_size)

            self.log_operation("decryption", input_file, "success")
            return True
        except Exception as e:
            self.log_operation("decryption", input_file, "failed", str(e))
            raise

    def log_operation(self, operation_type, file_path, status, error=None):
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "operation": operation_type,
            "file": file_path,
            "status": status
        }
        if error:
            log_entry["error"] = str(error)

        self.logger.info(json.dumps(log_entry))

    def get_supported_algorithms(self):
        return ["Fernet", "AES"]

    def validate_password(self, password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        return True, "OK"