import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from datetime import datetime
import json
from src.crypto.encryptor import FileEncryptor
from src.utils.logger import EncryptionLogger


class EncryptionGUI:
    def __init__(self, window):
        self.encrypt_btn = None
        self.window = window
        self.window.title("File Encryptor")
        self.window.geometry("600x800")
        self.window.resizable(False, False)

        self.encryptor = FileEncryptor()
        self.logger = EncryptionLogger()

        self.encrypt_file = None
        self.decrypt_file = None

        self.setup_gui()
        self.logger.log_operation(
            operation_type="gui_start",
            file_path=None,
            status="initialized"
        )

    def setup_gui(self):
        notebook = ttk.Notebook(self.window)
        notebook.pack(pady=10, expand=True)

        encrypt_frame = ttk.Frame(notebook)
        notebook.add(encrypt_frame, text="Encryption")

        decrypt_frame = ttk.Frame(notebook)
        notebook.add(decrypt_frame, text="Decoding")

        self.setup_encrypt_tab(encrypt_frame)
        self.setup_decrypt_tab(decrypt_frame)

        self.setup_menu()

    def setup_encrypt_tab(self, parent):
        file_frame = ttk.LabelFrame(parent, text="File selection", padding=10)
        file_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(
            file_frame,
            text="Select file",
            command=self.select_encrypt_file
        ).pack(side="left", padx=5)

        self.encrypt_file_label = ttk.Label(file_frame, text="File not selected")
        self.encrypt_file_label.pack(side="left", padx=5)

        metadata_frame = ttk.LabelFrame(parent, text="Metadata", padding=10)
        metadata_frame.pack(fill="x", padx=10, pady=5)

        self.metadata_text = tk.Text(metadata_frame, height=4, width=50)
        self.metadata_text.pack()

        algo_frame = ttk.LabelFrame(parent, text="Encryption algorithm", padding=10)
        algo_frame.pack(fill="x", padx=10, pady=5)

        self.algorithm_var = tk.StringVar(value="Fernet")
        for algo in ["Fernet", "AES", "RSA"]:
            ttk.Radiobutton(
                algo_frame,
                text=algo,
                variable=self.algorithm_var,
                value=algo
            ).pack(side="left", padx=10)

        pass_frame = ttk.LabelFrame(parent, text="Password", padding=10)
        pass_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(pass_frame, text="Password:").pack()
        self.encrypt_password_entry = ttk.Entry(pass_frame, show="*")
        self.encrypt_password_entry.pack(fill="x", pady=5)

        ttk.Label(pass_frame, text="Confirm your password:").pack()
        self.encrypt_confirm_password_entry = ttk.Entry(pass_frame, show="*")
        self.encrypt_confirm_password_entry.pack(fill="x", pady=5)

        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill="x", padx=10, pady=5)

        self.encrypt_progress_var = tk.DoubleVar()
        ttk.Progressbar(
            progress_frame,
            variable=self.encrypt_progress_var,
            maximum=100
        ).pack(fill="x", pady=5)

        self.encrypt_status = ttk.Label(progress_frame, text="")
        self.encrypt_status.pack()

        self.encrypt_btn = ttk.Button(
            progress_frame,
            text="Encrypt",
            command=self.start_encryption
        )
        self.encrypt_btn.pack(pady=10)

    def setup_decrypt_tab(self, parent):
        file_frame = ttk.LabelFrame(parent, text="File selection", padding=10)
        file_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(
            file_frame,
            text="Select file",
            command=self.select_decrypt_file
        ).pack(side="left", padx=5)

        self.decrypt_file_label = ttk.Label(file_frame, text="File not selected")
        self.decrypt_file_label.pack(side="left", padx=5)

        metadata_frame = ttk.LabelFrame(parent, text="Metadata", padding=10)
        metadata_frame.pack(fill="x", padx=10, pady=5)

        self.decrypt_metadata_text = tk.Text(metadata_frame, height=4, width=50)
        self.decrypt_metadata_text.pack()

        pass_frame = ttk.LabelFrame(parent, text="Password", padding=10)
        pass_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(pass_frame, text="Password:").pack()
        self.decrypt_password_entry = ttk.Entry(pass_frame, show="*")
        self.decrypt_password_entry.pack(fill="x", pady=5)

        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill="x", padx=10, pady=5)

        self.decrypt_progress_var = tk.DoubleVar()
        ttk.Progressbar(
            progress_frame,
            variable=self.decrypt_progress_var,
            maximum=100
        ).pack(fill="x", pady=5)

        self.decrypt_status = ttk.Label(progress_frame, text="")
        self.decrypt_status.pack()

        self.decrypt_btn = ttk.Button(
            progress_frame,
            text="Decipher",
            command=self.start_decryption
        )
        self.decrypt_btn.pack(pady=10)

    def setup_menu(self):
        menubar = tk.Menu(self.window)
        self.window.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.quit_application)

        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Viewing logs", command=self.view_logs)
        view_menu.add_command(label="Clear history", command=self.clear_history)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About the program", command=self.show_about)

    def update_metadata(self, file_path):
        metadata = {
            "File name": os.path.basename(file_path),
            "Size": f"{os.path.getsize(file_path):,} byte",
            "Date modified": datetime.fromtimestamp(
                os.path.getmtime(file_path)
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "Algorithm": self.algorithm_var.get() if hasattr(self, 'algorithm_var') else "Unknown"
        }
        return metadata

    def select_encrypt_file(self):
        self.encrypt_file = filedialog.askopenfilename(
            title="Select a file to encrypt"
        )
        if self.encrypt_file:
            self.encrypt_file_label.config(
                text=os.path.basename(self.encrypt_file)
            )
            metadata = self.update_metadata(self.encrypt_file)
            self.metadata_text.delete(1.0, tk.END)
            self.metadata_text.insert(
                1.0,
                "\n".join(f"{k}: {v}" for k, v in metadata.items())
            )
            self.logger.log_operation(
                operation_type="file_selection",
                file_path=self.encrypt_file,
                status="selected_for_encryption"
            )

    def select_decrypt_file(self):
        self.decrypt_file = filedialog.askopenfilename(
            title="Select file to decrypt",
            filetypes=[("Encrypted files", "*.encrypted")]
        )
        if self.decrypt_file:
            self.decrypt_file_label.config(
                text=os.path.basename(self.decrypt_file)
            )
            metadata = self.update_metadata(self.decrypt_file)
            self.decrypt_metadata_text.delete(1.0, tk.END)
            self.decrypt_metadata_text.insert(
                1.0,
                "\n".join(f"{k}: {v}" for k, v in metadata.items())
            )
            self.logger.log_operation(
                operation_type="file_selection",
                file_path=self.decrypt_file,
                status="selected_for_decryption"
            )

    def start_encryption(self):
        if not self.encrypt_file:
            self.show_error("Error", "Select a file to encrypt")
            return

        password = self.encrypt_password_entry.get()
        confirm_password = self.encrypt_confirm_password_entry.get()

        if not password or not confirm_password:
            self.show_error("Error", "Enter your password and confirmation")
            return

        if password != confirm_password:
            self.show_error("Error", "The passwords do not match")
            return

        valid, message = self.encryptor.validate_password(password)
        if not valid:
            self.show_error("Error", message)
            return

        algorithm = self.algorithm_var.get()
        if algorithm == "RSA":
            self.show_error("Error", "RSA encryption is temporarily unavailable")
            return

        output_file = f"{self.encrypt_file}.encrypted"
        self.encrypt_btn.state(['disabled'])
        self.encrypt_progress_var.set(0)
        self.encrypt_status.config(text="Encryption...")

        try:
            self.process_encryption(password, output_file, algorithm)
        except Exception as e:
            self.show_error("Error", f"Encryption error: {str(e)}")
            self.encrypt_btn.state(['!disabled'])
            self.encrypt_status.config(text="Encryption error")
            self.encrypt_progress_var.set(0)

    def start_decryption(self):
        if not self.decrypt_file:
            self.show_error("Error", "Select file to decrypt")
            return

        password = self.decrypt_password_entry.get()
        if not password:
            self.show_error("Error", "Enter your password")
            return

        output_file = self.decrypt_file.replace('.encrypted', '')
        if os.path.exists(output_file):
            output_file = self.get_unique_filename(output_file)

        self.decrypt_btn.state(['disabled'])
        self.decrypt_progress_var.set(0)
        self.decrypt_status.config(text="Decoding...")

        try:
            self.process_decryption(password, output_file)
        except Exception as e:
            self.show_error("Error", f"Decryption error: {str(e)}")
            self.decrypt_btn.state(['!disabled'])
            self.decrypt_status.config(text="Decryption error")
            self.decrypt_progress_var.set(0)

    def get_unique_filename(self, filename):
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(filename):
            filename = f"{base}_{counter}{ext}"
            counter += 1
        return filename

    def process_encryption(self, password, output_file, algorithm):
        file_size = os.path.getsize(self.encrypt_file)
        self.encrypt_progress_var.set(5)

        def progress_callback(processed_bytes):
            progress = (processed_bytes / file_size) * 100
            self.encrypt_progress_var.set(progress)
            self.window.update()

        self.encryptor.encrypt_file(
            self.encrypt_file,
            output_file,
            password,
            algorithm,
            progress_callback=progress_callback
        )

        self.window.after(0, self.encryption_complete, True)

    def process_decryption(self, password, output_file):
        file_size = os.path.getsize(self.decrypt_file)
        self.decrypt_progress_var.set(5)

        def progress_callback(processed_bytes):
            progress = (processed_bytes / file_size) * 100
            self.decrypt_progress_var.set(progress)
            self.window.update()

        success = self.encryptor.decrypt_file(
            self.decrypt_file,
            output_file,
            password,
            progress_callback=progress_callback
        )

        if success:
            self.window.after(0, self.decryption_complete, True)
        else:
            self.window.after(0, self.decryption_complete, False, "Incorrect password or corrupted file")

    def encryption_complete(self, success, error_message=None):
        self.encrypt_btn.state(['!disabled'])

        if success:
            self.encrypt_progress_var.set(100)
            self.encrypt_status.config(text="The file was successfully encrypted")
            self.show_success("Success", "The file was successfully encrypted")
            self.encrypt_password_entry.delete(0, tk.END)
            self.encrypt_confirm_password_entry.delete(0, tk.END)
        else:
            self.encrypt_progress_var.set(0)
            self.encrypt_status.config(text="Encryption error")
            self.show_error("Error", error_message or "An error occurred while encrypting")

    def decryption_complete(self, success, error_message=None):
        self.decrypt_btn.state(['!disabled'])

        if success:
            self.decrypt_progress_var.set(100)
            self.decrypt_status.config(text="The file was successfully decrypted")
            self.show_success("Success", "The file was successfully decrypted")
            self.decrypt_password_entry.delete(0, tk.END)
        else:
            self.decrypt_progress_var.set(0)
            self.decrypt_status.config(text="Decryption error")
            self.show_error("Error", error_message or "An error occurred while decrypting")

    def show_error(self, title, message):
        messagebox.showerror(title, message)
        self.logger.log_error(message)

    def show_success(self, title, message):
        messagebox.showinfo(title, message)
        self.logger.log_operation(
            operation_type="notification",
            file_path=None,
            status="success"
        )

    def show_about(self):
        about_text = """
                File encryption program
                Version: 1.0

                Developer: scrollDynasty
                © 2025 All rights reserved

                Supported algorithms:
                - Fernet (default)
                - AES
                - RSA (in development)

                The program is designed for 
                secure encryption and decryption o
                f files using modern algorithms.
                """
        messagebox.showinfo("About the program", about_text.strip())

    def view_logs(self):
        try:
            logs = self.logger.get_logs()
            if logs:
                log_window = tk.Toplevel(self.window)
                log_window.title("Viewing logs")
                log_window.geometry("600x400")

                log_text = tk.Text(log_window, wrap=tk.WORD)
                log_text.pack(expand=True, fill='both', padx=10, pady=5)

                scrollbar = ttk.Scrollbar(log_window, command=log_text.yview)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                log_text.config(yscrollcommand=scrollbar.set)

                for log in logs:
                    log_text.insert(tk.END, f"{json.dumps(log, indent=2, ensure_ascii=False)}\n\n")

                log_text.config(state='disabled')
            else:
                messagebox.showinfo("Logs", "No log entries")
        except Exception as e:
            self.show_error("Error", f"Failed to load logs: {str(e)}")

    def clear_history(self):
        if messagebox.askyesno("Confirmation", "Вы really want to clear your history?"):
            try:
                self.logger.clear_old_logs(days=0)
                messagebox.showinfo("Success", "History cleared successfully")
            except Exception as e:
                self.show_error("Error", f"Failed to clear history: {str(e)}")

    def quit_application(self):
        if messagebox.askyesno("Confirmation", "Do you really want to go out?"):
            self.logger.log_operation(
                operation_type="application_shutdown",
                file_path=None,
                status="user_initiated"
            )
            self.window.quit()

    def run(self):
        try:
            self.window.mainloop()
        except Exception as e:
            self.logger.log_error(f"Critical error in main loop: {str(e)}")
            raise