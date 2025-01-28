class InputValidator:
    @staticmethod
    def validate_password(password):
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            return False, "The password must contain at least one capital letter."
        if not any(c.islower() for c in password):
            return False, "The password must contain at least one lowercase letter."
        if not any(c.isdigit() for c in password):
            return False, "The password must contain at least one number."
        return True, "Password meets requirements"