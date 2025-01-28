import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from src.crypto.encryptor import FileEncryptor
from src.utils.validators import InputValidator
import threading
import os


class EncryptionGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Шифрование файлов")
        self.window.geometry("600x500")

        # Устанавливаем стиль
        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=[20, 5])

        self.encryptor = FileEncryptor()
        self.encrypt_file = None
        self.decrypt_file = None

        self.create_widgets()

    def create_widgets(self):
        # Создаем notebook (вкладки)
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=5)

        # Создаем вкладку шифрования
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text='Шифрование')

        # Создаем вкладку расшифрования
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text='Расшифрование')

        # Наполняем вкладку шифрования
        self.setup_encrypt_tab()

        # Наполняем вкладку расшифрования
        self.setup_decrypt_tab()

    def setup_encrypt_tab(self):
        # Рамка для выбора файла
        file_frame = ttk.LabelFrame(self.encrypt_frame, text="Выбор файла", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)

        self.encrypt_file_btn = ttk.Button(
            file_frame,
            text="Выбрать файл для шифрования",
            command=self.select_encrypt_file
        )
        self.encrypt_file_btn.pack(pady=5)

        self.encrypt_file_label = ttk.Label(file_frame, text="Файл не выбран")
        self.encrypt_file_label.pack(pady=5)

        # Рамка для пароля
        password_frame = ttk.LabelFrame(self.encrypt_frame, text="Защита", padding=10)
        password_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(password_frame, text="Введите пароль:").pack()
        self.encrypt_password_entry = ttk.Entry(password_frame, show="*")
        self.encrypt_password_entry.pack(pady=5)

        ttk.Label(password_frame, text="Повторите пароль:").pack()
        self.encrypt_confirm_password_entry = ttk.Entry(password_frame, show="*")
        self.encrypt_confirm_password_entry.pack(pady=5)

        # Кнопка шифрования
        self.encrypt_btn = ttk.Button(
            self.encrypt_frame,
            text="Зашифровать файл",
            command=self.start_encryption
        )
        self.encrypt_btn.pack(pady=10)

        # Прогресс и статус
        self.encrypt_progress_var = tk.DoubleVar()
        self.encrypt_progress = ttk.Progressbar(
            self.encrypt_frame,
            variable=self.encrypt_progress_var,
            maximum=100
        )
        self.encrypt_progress.pack(fill='x', padx=10, pady=5)

        self.encrypt_status = ttk.Label(self.encrypt_frame, text="")
        self.encrypt_status.pack(pady=5)

    def setup_decrypt_tab(self):
        # Рамка для выбора файла
        file_frame = ttk.LabelFrame(self.decrypt_frame, text="Выбор файла", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)

        self.decrypt_file_btn = ttk.Button(
            file_frame,
            text="Выбрать зашифрованный файл",
            command=self.select_decrypt_file
        )
        self.decrypt_file_btn.pack(pady=5)

        self.decrypt_file_label = ttk.Label(file_frame, text="Файл не выбран")
        self.decrypt_file_label.pack(pady=5)

        # Рамка для пароля
        password_frame = ttk.LabelFrame(self.decrypt_frame, text="Пароль", padding=10)
        password_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(password_frame, text="Введите пароль:").pack()
        self.decrypt_password_entry = ttk.Entry(password_frame, show="*")
        self.decrypt_password_entry.pack(pady=5)

        # Кнопка расшифрования
        self.decrypt_btn = ttk.Button(
            self.decrypt_frame,
            text="Расшифровать файл",
            command=self.start_decryption
        )
        self.decrypt_btn.pack(pady=10)

        # Прогресс и статус
        self.decrypt_progress_var = tk.DoubleVar()
        self.decrypt_progress = ttk.Progressbar(
            self.decrypt_frame,
            variable=self.decrypt_progress_var,
            maximum=100
        )
        self.decrypt_progress.pack(fill='x', padx=10, pady=5)

        self.decrypt_status = ttk.Label(self.decrypt_frame, text="")
        self.decrypt_status.pack(pady=5)

    def select_encrypt_file(self):
        self.encrypt_file = filedialog.askopenfilename(
            title="Выберите файл для шифрования"
        )
        if self.encrypt_file:
            filename = os.path.basename(self.encrypt_file)
            self.encrypt_file_label.config(text=f"Выбран: {filename}")
            self.encrypt_status.config(text="")
            self.encrypt_progress_var.set(0)

    def select_decrypt_file(self):
        self.decrypt_file = filedialog.askopenfilename(
            title="Выберите зашифрованный файл",
            filetypes=[("Зашифрованные файлы", "*.encrypted"), ("Все файлы", "*.*")]
        )
        if self.decrypt_file:
            filename = os.path.basename(self.decrypt_file)
            self.decrypt_file_label.config(text=f"Выбран: {filename}")
            self.decrypt_status.config(text="")
            self.decrypt_progress_var.set(0)

    def start_encryption(self):
        if not self.encrypt_file:
            messagebox.showerror("Ошибка", "Выберите файл для шифрования!")
            return

        password = self.encrypt_password_entry.get()
        confirm_password = self.encrypt_confirm_password_entry.get()

        if password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают!")
            return

        is_valid, message = InputValidator.validate_password(password)
        if not is_valid:
            messagebox.showerror("Ошибка", message)
            return

        output_file = filedialog.asksaveasfilename(
            defaultextension=".encrypted",
            filetypes=[("Зашифрованные файлы", "*.encrypted")],
            initialfile=os.path.basename(self.encrypt_file) + ".encrypted"
        )
        if not output_file:
            return

        self.encrypt_btn.state(['disabled'])
        self.encrypt_status.config(text="Шифрование...")

        thread = threading.Thread(
            target=self.process_encryption,
            args=(password, output_file)
        )
        thread.start()

    def start_decryption(self):
        if not self.decrypt_file:
            messagebox.showerror("Ошибка", "Выберите зашифрованный файл!")
            return

        password = self.decrypt_password_entry.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль!")
            return

        # Предлагаем имя файла без расширения .encrypted
        suggested_name = os.path.splitext(os.path.basename(self.decrypt_file))[0]
        if suggested_name.endswith('.encrypted'):
            suggested_name = suggested_name[:-10]

        output_file = filedialog.asksaveasfilename(
            initialfile=suggested_name
        )
        if not output_file:
            return

        self.decrypt_btn.state(['disabled'])
        self.decrypt_status.config(text="Расшифровка...")

        thread = threading.Thread(
            target=self.process_decryption,
            args=(password, output_file)
        )
        thread.start()

    def process_encryption(self, password, output_file):
        try:
            self.encryptor.encrypt_file(self.encrypt_file, output_file, password)
            self.window.after(0, self.encryption_complete, True)
        except Exception as e:
            self.window.after(0, self.encryption_complete, False, str(e))

    def process_decryption(self, password, output_file):
        try:
            success = self.encryptor.decrypt_file(self.decrypt_file, output_file, password)
            if success:
                self.window.after(0, self.decryption_complete, True)
            else:
                self.window.after(0, self.decryption_complete, False, "Неверный пароль или поврежденный файл")
        except Exception as e:
            self.window.after(0, self.decryption_complete, False, str(e))

    def encryption_complete(self, success, error_message=None):
        self.encrypt_btn.state(['!disabled'])

        if success:
            self.encrypt_progress_var.set(100)
            self.encrypt_status.config(text="Файл успешно зашифрован")
            messagebox.showinfo("Успех", "Файл успешно зашифрован")
        else:
            self.encrypt_progress_var.set(0)
            self.encrypt_status.config(text="Ошибка шифрования")
            messagebox.showerror("Ошибка", error_message or "Произошла ошибка при шифровании")

    def decryption_complete(self, success, error_message=None):
        self.decrypt_btn.state(['!disabled'])

        if success:
            self.decrypt_progress_var.set(100)
            self.decrypt_status.config(text="Файл успешно расшифрован")
            messagebox.showinfo("Успех", "Файл успешно расшифрован")
        else:
            self.decrypt_progress_var.set(0)
            self.decrypt_status.config(text="Ошибка расшифровки")
            messagebox.showerror("Ошибка", error_message or "Произошла ошибка при расшифровке")

    def run(self):
        self.window.mainloop()