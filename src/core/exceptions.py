"""
Custom exception classes for the application.

Provides specific exception types for different error conditions
with proper error codes and messages.
"""


class TerminalServerError(Exception):
    """
    Base exception class for all application errors.
    """
    
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        super().__init__(self.message)


class ValidationError(TerminalServerError):
    """
    Raised when input validation fails.
    """
    pass


class SecurityViolationError(TerminalServerError):
    """
    Raised when a security policy is violated.
    """
    pass


class AuthenticationError(TerminalServerError):
    """
    Raised when authentication fails.
    """
    pass


class AuthorizationError(TerminalServerError):
    """
    Raised when authorization fails.
    """
    pass


class CommandNotFoundError(TerminalServerError):
    """
    Raised when a requested command template is not found.
    """
    pass


class CommandExecutionError(TerminalServerError):
    """
    Raised when command execution fails.
    """
    
    def __init__(self, message: str, return_code: int = None, stderr: str = None):
        super().__init__(message)
        self.return_code = return_code
        self.stderr = stderr


class SandboxError(TerminalServerError):
    """
    Raised when sandbox setup or execution fails.
    """
    pass


class ResourceLimitError(TerminalServerError):
    """
    Raised when resource limits are exceeded.
    """
    pass


class ConfigurationError(TerminalServerError):
    """
    Raised when configuration is invalid or missing.
    """
    pass


class DatabaseError(TerminalServerError):
    """
    Raised when database operations fail.
    """
    pass


class RedisError(TerminalServerError):
    """
    Raised when Redis operations fail.
    """
    pass
