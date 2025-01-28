from src.crypto.encryptor import FileEncryptor
from src.utils.file_handler import FileHandler
from src.utils.validators import InputValidator


class CLI:
    def __init__(self):
        self.encryptor = FileEncryptor()
        self.file_handler = FileHandler()
        self.validator = InputValidator()

    def run(self):
        while True:
            print("\n=== Программа шифрования файлов ===")
            print("1. Зашифровать файл")
            print("2. Расшифровать файл")
            print("3. Выход")

            choice = input("\nВыберите действие (1-3): ")

            if choice == '1':
                self.encrypt_file_menu()
            elif choice == '2':
                self.decrypt_file_menu()
            elif choice == '3':
                print("Программа завершена.")
                break
            else:
                print("Неверный выбор. Попробуйте снова.")

    def encrypt_file_menu(self):
        try:
            input_file = input("Введите путь к файлу для шифрования: ")
            self.file_handler.validate_file_path(input_file)

            output_file = input("Введите путь для сохранения зашифрованного файла: ")
            self.file_handler.ensure_directory(output_file)

            while True:
                password = input("Введите пароль: ")
                is_valid, message = self.validator.validate_password(password)
                if is_valid:
                    break
                print(message)

            self.encryptor.encrypt_file(input_file, output_file, password)
            print(f"Файл успешно зашифрован и сохранен как {output_file}")

        except Exception as e:
            print(f"Ошибка: {str(e)}")

    def decrypt_file_menu(self):
        try:
            input_file = input("Введите путь к зашифрованному файлу: ")
            self.file_handler.validate_file_path(input_file)

            output_file = input("Введите путь для сохранения расшифрованного файла: ")
            self.file_handler.ensure_directory(output_file)

            password = input("Введите пароль: ")

            if self.encryptor.decrypt_file(input_file, output_file, password):
                print(f"Файл успешно расшифрован и сохранен как {output_file}")
            else:
                print("Ошибка расшифровки. Возможно, неверный пароль.")

        except Exception as e:
            print(f"Ошибка: {str(e)}")