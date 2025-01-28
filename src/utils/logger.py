import logging
from datetime import datetime
import os
import json
from threading import Lock
import sys


class EncryptionLogger:
    _instance = None
    _lock = Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance

    def __init__(self, log_dir='logs'):
        if not hasattr(self, 'initialized'):
            self.log_dir = log_dir
            self.initialized = True
            self.setup_logging()

    def setup_logging(self):
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)

            current_date = datetime.now().strftime("%Y%m%d")
            log_file = os.path.join(self.log_dir, f'encryption_{current_date}.log')

            log_format = '%(asctime)s [%(levelname)s] %(message)s'
            date_format = '%Y-%m-%d %H:%M:%S'

            logging.basicConfig(
                level=logging.INFO,
                format=log_format,
                datefmt=date_format,
                handlers=[
                    logging.FileHandler(log_file, encoding='utf-8'),
                    logging.StreamHandler(sys.stdout)
                ]
            )

            self.logger = logging.getLogger(__name__)

            # Добавляем дополнительную информацию при старте
            self.logger.info("=== Starting a new logging session ===")
            self.logger.info(f"Log directory: {self.log_dir}")
            self.logger.info(f"Current user: {os.getenv('USERNAME', 'Unknown')}")

        except Exception as e:
            print(f"Logging setup error: {str(e)}")
            raise

    def log_operation(self, operation_type, file_path, status, error=None):
        try:
            log_data = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'operation': operation_type,
                'file': file_path,
                'status': status,
                'user': os.getenv('USERNAME', 'Unknown')
            }

            if error:
                log_data['error'] = str(error)
                self.logger.error(json.dumps(log_data, ensure_ascii=False))
            else:
                self.logger.info(json.dumps(log_data, ensure_ascii=False))

        except Exception as e:
            self.logger.error(f"Logging error: {str(e)}")

    def log_attempt(self, file_path, details=None):
        try:
            log_data = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'event': 'attempted_access',
                'file': file_path,
                'user': os.getenv('USERNAME', 'Unknown')
            }

            if details:
                log_data['details'] = details

            self.logger.warning(json.dumps(log_data, ensure_ascii=False))

        except Exception as e:
            self.logger.error(f"Error logging attempt: {str(e)}")

    def log_error(self, error_message, additional_info=None):
        try:
            log_data = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'error_message': error_message,
                'user': os.getenv('USERNAME', 'Unknown')
            }

            if additional_info:
                log_data['additional_info'] = additional_info

            self.logger.error(json.dumps(log_data, ensure_ascii=False))

        except Exception as e:
            self.logger.error(f"Error logging error: {str(e)}")

    def get_logs(self, start_date=None, end_date=None, level=None):
        try:
            logs = []
            log_file = os.path.join(self.log_dir, f'encryption_{datetime.now().strftime("%Y%m%d")}.log')

            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.split('] ')[-1])
                            if self._filter_log_entry(log_entry, start_date, end_date, level):
                                logs.append(log_entry)
                        except:
                            continue

            return logs

        except Exception as e:
            self.logger.error(f"Error receiving logs: {str(e)}")
            return []

    def _filter_log_entry(self, entry, start_date, end_date, level):
        try:
            if start_date and entry['timestamp'] < start_date:
                return False
            if end_date and entry['timestamp'] > end_date:
                return False
            if level and entry.get('level') != level:
                return False
            return True
        except:
            return False

    def clear_old_logs(self, days=30):
        try:
            current_date = datetime.now()
            for filename in os.listdir(self.log_dir):
                if filename.startswith('encryption_'):
                    file_path = os.path.join(self.log_dir, filename)
                    file_date = datetime.strptime(filename.split('_')[1].split('.')[0], "%Y%m%d")
                    if (current_date - file_date).days > days:
                        os.remove(file_path)
                        self.logger.info(f"Old log file removed: {filename}")
        except Exception as e:
            self.logger.error(f"Error clearing old logs: {str(e)}")