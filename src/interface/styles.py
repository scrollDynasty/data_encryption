from tkinter import ttk


class StyleManager:
    @staticmethod
    def apply_styles(root):
        style = ttk.Style()

        # Настройка основных стилей
        style.configure('TLabel', padding=5)
        style.configure('TButton', padding=5)
        style.configure('TEntry', padding=5)

        # Настройка вкладок
        style.configure('TNotebook.Tab', padding=[20, 5])

        # Настройка рамок
        style.configure('TLabelframe', padding=10)