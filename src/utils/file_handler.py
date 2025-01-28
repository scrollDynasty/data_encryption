import os
from pathlib import Path

class FileHandler:
    @staticmethod
    def validate_file_path(file_path):
        """Проверяет существование файла и доступ к нему"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Файл не найден: {file_path}")
        if not os.access(path, os.R_OK):
            raise PermissionError(f"Нет доступа к файлу: {file_path}")
        return True

    @staticmethod
    def ensure_directory(file_path):
        """Создает директорию для файла, если она не существует"""
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)