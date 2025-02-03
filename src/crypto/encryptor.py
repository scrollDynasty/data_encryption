import os
from base64 import b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import hashlib

# Константы
PBKDF2_ITERATIONS = 480000
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1 GB
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5


class FileEncryptor:
    def __init__(self):
        self.salt = os.urandom(16)
        self.iv = os.urandom(16)
        self.logger = self.setup_logging()

    def setup_logging(self):
        """Настройка системы логирования с ротацией логов"""
        logger = logging.getLogger('FileEncryptor')
        logger.setLevel(logging.INFO)

        # Создаем директорию для логов, если она не существует
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Формируем имя файла лога с текущей датой
        current_date = datetime.now().strftime("%Y%m%d")
        log_file = os.path.join(log_dir, f'encryption_{current_date}.log')

        # Проверяем, не добавлен ли уже handler
        if not logger.handlers:
            # Создаем RotatingFileHandler для автоматической ротации логов
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=LOG_MAX_SIZE,
                backupCount=LOG_BACKUP_COUNT,
                encoding='utf-8'
            )

            # Создаем форматтер и добавляем его в handler
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                          datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(formatter)

            # Добавляем handler в logger
            logger.addHandler(file_handler)

        return logger

    def generate_key(self, password, algorithm):
        """Генерация ключа на основе пароля"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=PBKDF2_ITERATIONS,
            )
            key = kdf.derive(password.encode())

            if algorithm == "Fernet":
                key = b64encode(key).decode('ascii')
            return key
        except Exception as e:
            raise Exception(f"Key generation error: {str(e)}")

    def check_file_size(self, file_path):
        """Проверка размера файла"""
        size = os.path.getsize(file_path)
        if size > MAX_FILE_SIZE:
            raise ValueError(f"File size exceeds maximum allowed size of {MAX_FILE_SIZE / (1024 * 1024):.0f} MB")
        return size

    def calculate_file_hash(self, file_path):
        """Вычисляет SHA-256 хеш файла"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.digest()

    def safe_open_for_write(self, file_path):
        """Проверка существования файла перед записью"""
        if os.path.exists(file_path):
            raise FileExistsError(f"File {file_path} already exists")

    def encrypt_file(self, input_file, output_file, password, algorithm="Fernet", chunk_size=64 * 1024,
                     progress_callback=None):
        try:
            # Проверяем размер файла
            file_size = self.check_file_size(input_file)

            # Проверяем, не существует ли выходной файл
            self.safe_open_for_write(output_file)

            # Логируем начало операции и параметры
            self.logger.info(json.dumps({
                "operation": "encryption_debug",
                "salt": self.salt.hex(),
                "iv": self.iv.hex() if algorithm == "AES" else None,
                "algorithm": algorithm,
                "file_size": file_size
            }))

            # Вычисляем хеш исходного файла
            original_hash = self.calculate_file_hash(input_file)
            key = self.generate_key(password, algorithm)
            total_processed = 0

            if algorithm == "Fernet":
                f = Fernet(key)
                with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
                    # Записываем метаданные
                    out_file.write(algorithm.encode())
                    out_file.write(b'\0' * (16 - len(algorithm)))
                    out_file.write(self.salt)
                    out_file.write(original_hash)

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
                    # Записываем метаданные
                    out_file.write(algorithm.encode())
                    out_file.write(b'\0' * (16 - len(algorithm)))
                    out_file.write(self.salt)
                    out_file.write(self.iv)
                    out_file.write(original_hash)

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
            # Проверяем размер файла
            file_size = self.check_file_size(input_file)

            # Проверяем, не существует ли выходной файл
            self.safe_open_for_write(output_file)

            total_processed = 0
            decrypted_data = bytearray()

            with open(input_file, 'rb') as file:
                # Читаем метаданные
                algorithm = file.read(16).decode().rstrip('\0')
                salt = file.read(16)

                # Логируем значения для отладки
                self.logger.info(json.dumps({
                    "operation": "decryption_debug",
                    "algorithm": algorithm,
                    "salt_from_file": salt.hex()
                }))

                # Временно сохраняем старый salt
                old_salt = self.salt
                self.salt = salt  # Используем salt из файла для генерации ключа

                if algorithm == "AES":
                    # Сначала читаем IV для AES
                    iv = file.read(16)  # Читаем IV из файла
                    old_iv = self.iv
                    self.iv = iv
                    # Затем читаем хеш
                    original_hash = file.read(32)  # SHA-256 хеш имеет длину 32 байта

                    # Логируем значения для отладки
                    self.logger.info(json.dumps({
                        "operation": "decryption_debug_aes",
                        "iv_from_file": iv.hex()
                    }))
                else:
                    # Для не-AES алгоритмов читаем только хеш
                    original_hash = file.read(32)

                try:
                    key = self.generate_key(password, algorithm)

                    # Логируем сгенерированный ключ для отладки
                    self.logger.info(json.dumps({
                        "operation": "decryption_debug_key",
                        "key": key.hex() if isinstance(key, bytes) else key
                    }))

                    if algorithm == "Fernet":
                        f = Fernet(key)
                        while chunk := file.read(chunk_size):
                            try:
                                decrypted_chunk = f.decrypt(chunk)
                                decrypted_data.extend(decrypted_chunk)
                                total_processed += len(chunk)
                                if progress_callback:
                                    progress_callback(total_processed)
                            except Exception as e:
                                self.logger.error(f"Fernet decryption chunk error: {str(e)}")
                                raise ValueError("Invalid password or corrupted file")

                    elif algorithm == "AES":
                        cipher = Cipher(algorithms.AES(key), modes.CBC(self.iv))
                        decryptor = cipher.decryptor()
                        unpadder = padding.PKCS7(128).unpadder()

                        # Читаем и расшифровываем данные
                        while chunk := file.read(chunk_size):
                            decrypted_chunk = decryptor.update(chunk)
                            try:
                                unpadded_chunk = unpadder.update(decrypted_chunk)
                                decrypted_data.extend(unpadded_chunk)
                            except ValueError:
                                # Сохраняем зашифрованный чанк для последующей обработки
                                pass
                            total_processed += len(chunk)
                            if progress_callback:
                                progress_callback(total_processed)

                        # Обработка последнего блока
                        final_chunk = decryptor.finalize()
                        if final_chunk:
                            try:
                                final_unpadded = unpadder.update(final_chunk)
                                decrypted_data.extend(final_unpadded)
                            except ValueError:
                                pass

                        try:
                            final_unpadded = unpadder.finalize()
                            decrypted_data.extend(final_unpadded)
                        except ValueError as e:
                            self.logger.error(f"Final unpadding error: {str(e)}")
                            raise ValueError("Invalid password or corrupted file")

                    # Проверяем целостность расшифрованных данных
                    decrypted_hash = hashlib.sha256(decrypted_data).digest()

                    # Логируем хеши для отладки
                    self.logger.info(json.dumps({
                        "operation": "decryption_debug_hash",
                        "original_hash": original_hash.hex(),
                        "decrypted_hash": decrypted_hash.hex()
                    }))

                    if decrypted_hash != original_hash:
                        raise ValueError("File integrity check failed")

                    # Если хеши совпадают, сохраняем файл
                    with open(output_file, 'wb') as out_file:
                        out_file.write(decrypted_data)

                finally:
                    # Восстанавливаем оригинальные значения
                    self.salt = old_salt
                    if algorithm == "AES":
                        self.iv = old_iv

            self.log_operation("decryption", input_file, "success")
            return True

        except Exception as e:
            self.log_operation("decryption", input_file, "failed", str(e))
            raise

    def log_operation(self, operation_type, file_path, status, error=None):
        """Логирование операций"""
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "operation": operation_type,
            "file": file_path,
            "status": status,
            "user": os.getenv('USERNAME', 'Unknown')
        }
        if error:
            log_entry["error"] = str(error)

        self.logger.info(json.dumps(log_entry, ensure_ascii=False))

    def get_supported_algorithms(self):
        """Получение списка поддерживаемых алгоритмов"""
        return ["Fernet", "AES"]

    def validate_password(self, password):
        """Расширенная валидация пароля"""
        if not password:
            return False, "Password cannot be empty"
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        return True, "OK"