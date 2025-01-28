import os
from pathlib import Path

class FileHandler:
    @staticmethod
    def validate_file_path(file_path):
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not os.access(path, os.R_OK):
            raise PermissionError(f"File access denied: {file_path}")
        return True

    @staticmethod
    def ensure_directory(file_path):
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)