# main.py
from src.interface.gui import EncryptionGUI

def main():
    try:
        app = EncryptionGUI()
        app.run()
    except Exception as e:
        print(f"Error starting application: {str(e)}")

if __name__ == "__main__":
    main()