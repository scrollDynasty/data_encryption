class InputValidator:
    @staticmethod
    def validate_password(password):
        """Проверяет надежность пароля"""
        if len(password) < 8:
            return False, "Пароль должен содержать минимум 8 символов"
        if not any(c.isupper() for c in password):
            return False, "Пароль должен содержать хотя бы одну заглавную букву"
        if not any(c.islower() for c in password):
            return False, "Пароль должен содержать хотя бы одну строчную букву"
        if not any(c.isdigit() for c in password):
            return False, "Пароль должен содержать хотя бы одну цифру"
        return True, "Пароль соответствует требованиям"