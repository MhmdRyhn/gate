"""Per-request metadata (request ID, client IP, user agent) carried in a
context variable, so services can record it in sessions and audit events
without depending on the transport layer. Each asyncio task has its own
context, so concurrent requests never see each other's values."""

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class RequestMeta:
    request_id: str = ""
    ip: str = ""
    user_agent: str = ""


_EMPTY = RequestMeta()
_current: ContextVar[RequestMeta] = ContextVar("gate_request_meta", default=_EMPTY)


def current() -> RequestMeta:
    """The metadata of the running request, or empty values (e.g. CLI)."""
    return _current.get()


def bind(meta: RequestMeta) -> object:
    """Sets the metadata for the current context; returns a reset token."""
    return _current.set(meta)


def reset(token: object) -> None:
    _current.reset(token)  # type: ignore[arg-type]
