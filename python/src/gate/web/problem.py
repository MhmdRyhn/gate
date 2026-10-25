"""RFC 9457 "problem details" error responses (application/problem+json).
``code`` is a stable, machine-readable extension."""

import json
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any, Final

from starlette.responses import Response

from gate import requestctx
from gate.domain import (
    ConflictError,
    DomainError,
    ForbiddenError,
    InvalidCredentialsError,
    InvalidTokenError,
    NotFoundError,
    UnauthenticatedError,
    UserDisabledError,
    ValidationError,
)

PROBLEM_JSON: Final = "application/problem+json"


class ProblemError(Exception):
    """Raised by the transport layer to answer with a specific problem."""

    def __init__(self, status: int, code: str, detail: str, headers: Mapping[str, str] | None = None) -> None:
        super().__init__(detail)
        self.status: Final = status
        self.code: Final = code
        self.detail: Final = detail
        self.headers: Final = dict(headers or {})


def problem_body(status: int, code: str, detail: str, request_id: str) -> bytes:
    body: dict[str, object] = {"type": "about:blank", "title": HTTPStatus(status).phrase, "status": status}
    if detail:
        body["detail"] = detail
    body["code"] = code
    if request_id:
        body["request_id"] = request_id
    return json.dumps(body, separators=(",", ":")).encode()


def problem(status: int, code: str, detail: str, headers: Mapping[str, str] | None = None) -> Response:
    rid = requestctx.current().request_id
    return Response(
        problem_body(status, code, detail, rid), status_code=status, headers=headers, media_type=PROBLEM_JSON
    )


def from_problem_error(e: ProblemError) -> Response:
    return problem(e.status, e.code, e.detail, e.headers)


_INVALID_TOKEN_HEADERS: Final = frozendict({"WWW-Authenticate": 'Bearer realm="rbac-service", error="invalid_token"'})
_UNAUTHENTICATED_HEADERS: Final = frozendict({"WWW-Authenticate": 'Bearer realm="rbac-service"'})


def from_domain_error(e: DomainError) -> Response:
    """Maps a domain error to its problem response."""
    match e:
        case ValidationError():
            return problem(400, "invalid_request", e.message)
        case NotFoundError():
            return problem(404, "not_found", "resource not found")
        case ConflictError():
            return problem(409, "conflict", f"conflict: {e.message}")
        case UnauthenticatedError():
            return problem(401, "unauthenticated", "authentication required", _UNAUTHENTICATED_HEADERS)
        case InvalidTokenError():
            return problem(401, "invalid_token", "invalid or expired token", _INVALID_TOKEN_HEADERS)
        case InvalidCredentialsError():
            return problem(401, "invalid_credentials", "invalid credentials")
        case UserDisabledError():
            return problem(403, "account_disabled", "account is disabled")
        case ForbiddenError():
            return problem(403, "forbidden", f"forbidden: {e.message}")
        case _:
            return problem(500, "internal_error", "internal server error")


def describe_validation(errors: Sequence[Any]) -> str:
    """Turns pydantic validation errors into one readable sentence,
    reporting JSON field names ("full_name")."""
    msgs: list[str] = []
    for err in errors:
        loc = [str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path", "header")]
        field = ".".join(loc) or "body"
        ctx = err.get("ctx") or {}
        match err.get("type"):
            case "missing" if not loc:
                msgs.append("invalid JSON body: request body is required")
            case "missing" | "string_too_short" if ctx.get("min_length", 1) == 1:
                msgs.append(f"{field} is required")
            case "string_too_long" | "too_long":
                msgs.append(f"{field} must be at most {ctx.get('max_length')}")
            case "too_short":
                msgs.append(f"{field} must have at least {ctx.get('min_length')}")
            case "literal_error" | "enum":
                msgs.append(f"{field} must be one of: {ctx.get('expected', '')}")
            case "extra_forbidden":
                msgs.append(f'invalid JSON body: unknown field "{field}"')
            case "json_invalid":
                msgs.append("invalid JSON body")
            case "uuid_parsing" | "uuid_type":
                msgs.append(f"{field} must be a UUID")
            case _:
                msgs.append(f"{field}: {err.get('msg', 'invalid value')}")
    return "; ".join(msgs)
