"""Domain errors shared by all layers. The HTTP layer maps each class to a
status code; pass a message to add detail."""


class DomainError(Exception):
    default_message = "error"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.default_message)

    @property
    def message(self) -> str:
        return str(self.args[0])


class NotFoundError(DomainError):
    default_message = "not found"


class ConflictError(DomainError):
    default_message = "conflict"


class UnauthenticatedError(DomainError):
    default_message = "authentication required"


class InvalidCredentialsError(DomainError):
    default_message = "invalid email or password"


class InvalidTokenError(DomainError):
    default_message = "invalid or expired token"


class UserDisabledError(DomainError):
    default_message = "account is disabled"


class ForbiddenError(DomainError):
    default_message = "forbidden"


class ValidationError(DomainError):
    """Invalid input from the client."""

    default_message = "invalid request"
