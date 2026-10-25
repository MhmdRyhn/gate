"""Route-level access control as FastAPI dependencies. Every dependency is
``async`` so none is pushed to the thread pool.

Use one ``Authenticate`` instance per application: FastAPI caches a
dependency per request by identity, so a route that lists both the
authentication dependency and a ``require_*`` check verifies the token once.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Protocol

from fastapi import Depends, Request

from gate.domain import Permission, Principal, UnauthenticatedError, UserKind
from gate.web.problem import ProblemError
from gate.web.ratelimit import IPRateLimiter


class Authenticator(Protocol):
    """Verifies a bearer token and returns the principal (AuthService)."""

    async def authenticate(self, raw_token: str) -> Principal: ...


type Authenticate = Callable[[Request], Awaitable[Principal]]
type Check = Callable[..., Awaitable[None]]


def make_authenticate(authenticator: Authenticator) -> Authenticate:
    """Requires a valid bearer access token; yields the principal."""

    async def authenticate(request: Request) -> Principal:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise UnauthenticatedError
        p = await authenticator.authenticate(token)
        request.scope["gate.user_id"] = str(p.user_id)  # for the access log
        return p

    return authenticate


def require_kind(authn: Authenticate, kind: UserKind) -> Check:
    """Allows only users of the given kind (internal or public)."""

    async def check(p: Annotated[Principal, Depends(authn)]) -> None:
        if p.kind != kind:
            raise ProblemError(403, "forbidden", f"only {kind} users may call this endpoint")

    return check


def require_permissions(authn: Authenticate, *perms: Permission) -> Check:
    """Allows only principals holding every listed permission."""

    async def check(p: Annotated[Principal, Depends(authn)]) -> None:
        for perm in perms:
            if not p.can(perm):
                raise ProblemError(403, "forbidden", f'requires permission "{perm}"')

    return check


def require_public_type(authn: Authenticate, *types: str) -> Check:
    """Allows only public users holding at least one of types. Use it for
    public endpoints that differ per type (e.g. vendor-only)."""

    async def check(p: Annotated[Principal, Depends(authn)]) -> None:
        if not p.has_public_type(*types):
            raise ProblemError(403, "forbidden", f"requires public type: {' or '.join(types)}")

    return check


def rate_limit(limiter: IPRateLimiter) -> Check:
    """Applies the per-client-IP token bucket."""

    async def check(request: Request) -> None:
        if not limiter.allow(request.scope.get("gate.client_ip", "")):
            raise ProblemError(
                429, "rate_limited", "too many requests", {"Retry-After": str(limiter.retry_after_seconds)}
            )

    return check
