import tkinter as tk
from tkinter import ttk


class PasswordDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Entering your password")
        self.result = None

        self.password_var = tk.StringVar()

        ttk.Label(self, text="Enter your password:").pack(pady=5)
        ttk.Entry(self, textvariable=self.password_var, show="*").pack(pady=5)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="OK", command=self.ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.cancel).pack(side=tk.LEFT)

        self.transient(parent)
        self.grab_set()

    def ok(self):
        self.result = self.password_var.get()
        self.destroy()

    def cancel(self):
        self.destroy()