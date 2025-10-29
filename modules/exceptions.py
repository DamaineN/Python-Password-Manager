# modules/exceptions.py
# Simple custom exception classes used across the app.

class UserExits(Exception):
    """Raised when user types 'exit' or chooses to exit."""
    pass

class PasswordFileDoesNotExist(Exception):
    pass

class PasswordFileIsEmpty(Exception):
    pass

class PasswordNotFound(Exception):
    pass

class PasswordNotLongEnough(Exception):
    pass

class EmptyField(Exception):
    pass

class MasterPasswordIncorrect(Exception):
    pass

class AccountExists(Exception):
    pass

class InvalidCredentials(Exception):
    pass

class AccountLocked(Exception):
    pass

class SessionExpired(Exception):
    pass
