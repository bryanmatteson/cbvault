from typing import Iterable, Optional


class VaultError(Exception):
    def __init__(
        self,
        message: Optional[str] = None,
        errors: Optional[Iterable[str]] = None,
        method: Optional[str] = None,
        url: Optional[str] = None,
    ):
        if errors:
            message = ", ".join(errors)

        self.errors = errors
        self.method = method
        self.url = url

        super().__init__(message)

    def __str__(self):
        return "{0}, on {1} {2}".format(self.args[0], self.method, self.url)


class InvalidRequest(VaultError):
    """Raised when the request is invalid."""


class Unauthorized(VaultError):
    """Raised when the client is not authorized to perform the requested operation."""


class Forbidden(VaultError):
    """Raised when the request is forbidden."""


class InvalidPath(VaultError):
    """Raised when the path is invalid."""


class RateLimitExceeded(VaultError):
    """Raised when the rate limit has been exceeded."""


class InternalServerError(VaultError):
    """Raised when the Vault server returns a 500 error."""


class VaultNotInitialized(VaultError):
    """Raised when Vault is not initialized"""


class VaultDown(VaultError):
    """Raised when Vault is down."""


class UnexpectedError(VaultError):
    """Raised when an unexpected error occurs."""


class BadGateway(VaultError):
    """Raised when the Vault server is unreachable."""


class ParamValidationError(VaultError):
    """Raised when a parameter is invalid."""
