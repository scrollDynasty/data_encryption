import logging
from datetime import datetime
import os


class EncryptionLogger:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_file = os.path.join(log_dir, f'encryption_{datetime.now().strftime("%Y%m%d")}.log')

        # Настраиваем логирование
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

        self.logger = logging.getLogger(__name__)

    def log_operation(self, operation_type, file_path, status, error=None):
        message = f"Operation: {operation_type}, File: {file_path}, Status: {status}"
        if error:
            self.logger.error(f"{message}, Error: {str(error)}")
        else:
            self.logger.info(message)

    def log_attempt(self, file_path):
        self.logger.warning(f"Failed encryption attempt on file: {file_path}")