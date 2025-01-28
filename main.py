import sys
import tkinter as tk
from src.interface.gui import EncryptionGUI
from src.utils.logger import EncryptionLogger


def setup_logging():
    """Initialize logging configuration"""
    try:
        return EncryptionLogger()
    except Exception as e:
        print(f"Failed to initialize logger: {str(e)}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main application entry point"""
    logger = setup_logging()

    try:
        logger.log_operation(
            operation_type="application_start",
            file_path=None,
            status="starting"
        )

        root = tk.Tk()
        app = EncryptionGUI(root)
        root.mainloop()

        logger.log_operation(
            operation_type="application_shutdown",
            file_path=None,
            status="success"
        )

    except Exception as e:
        error_message = f"Critical error starting application: {str(e)}"
        logger.log_error(error_message)
        print(error_message, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())