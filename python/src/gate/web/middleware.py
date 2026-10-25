"""One pure-ASGI middleware for every cross-cutting concern: request ID,
client IP, security headers, body size limit, crash recovery and the
access log. A single layer (rather than one per concern, or Starlette's
BaseHTTPMiddleware) keeps per-request overhead low under high traffic."""

import re
import time
import traceback
import uuid
from collections.abc import Sequence
from ipaddress import ip_address
from typing import Final

from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gate import requestctx
from gate.config.settings import Network
from gate.logs import Logger
from gate.web.problem import PROBLEM_JSON, problem_body

_VALID_REQUEST_ID: Final = re.compile(rb"^[A-Za-z0-9._-]{1,64}$")

# This is a JSON API: nothing may be framed, sniffed or cached (RFC 6749
# §5.1 requires no-store for tokens). Handlers may override Cache-Control.
_SECURITY_HEADERS: Final = (
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"pragma", b"no-cache"),
)


class BodyTooLargeError(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413, detail="body too large")


def client_ip(scope: Scope, forwarded_for: bytes | None, trusted: Sequence[Network]) -> str:
    """The client IP. X-Forwarded-For is honoured only when the direct peer
    is a trusted proxy; it is walked right to left, skipping trusted hops."""
    peer = scope["client"][0] if scope.get("client") else ""
    if not trusted or not forwarded_for or not _is_trusted(peer, trusted):
        return peer
    hops = [h.strip() for h in forwarded_for.decode("latin-1").split(",")]
    for hop in reversed(hops):
        if not _is_trusted(hop, trusted):
            try:
                return str(ip_address(hop))
            except ValueError:
                return peer
    return hops[0] or peer


def _is_trusted(ip: str, trusted: Sequence[Network]) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in trusted)


class GateMiddleware:
    __slots__ = ("_app", "_log", "_max_body", "_trusted")

    def __init__(self, app: ASGIApp, *, log: Logger, max_body_bytes: int, trusted: Sequence[Network]) -> None:
        self._app: Final = app
        self._log: Final = log
        self._max_body: Final = max_body_bytes
        self._trusted: Final = tuple(trusted)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        start = time.perf_counter()
        incoming_id = forwarded = user_agent = content_length = None
        for name, value in scope["headers"]:
            match name:
                case b"x-request-id":
                    incoming_id = value
                case b"x-forwarded-for":
                    forwarded = value
                case b"user-agent":
                    user_agent = value
                case b"content-length":
                    content_length = value
        # Reuse a well-formed incoming request ID for cross-service tracing.
        rid = incoming_id.decode() if incoming_id and _VALID_REQUEST_ID.match(incoming_id) else str(uuid.uuid4())
        ip = client_ip(scope, forwarded, self._trusted)
        scope["gate.client_ip"] = ip
        token = requestctx.bind(
            requestctx.RequestMeta(request_id=rid, ip=ip, user_agent=user_agent.decode("latin-1") if user_agent else "")
        )
        status = 0
        rid_header = (b"x-request-id", rid.encode())

        async def send_with_headers(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers: list[tuple[bytes, bytes]] = list(message.get("headers", ()))
                present = {k.lower() for k, _ in headers}
                headers += [h for h in _SECURITY_HEADERS if h[0] not in present]
                headers.append(rid_header)
                message["headers"] = headers
            await send(message)

        async def send_problem(code: int, problem_code: str, detail: str) -> None:
            body = problem_body(code, problem_code, detail, rid)
            await send_with_headers(
                {
                    "type": "http.response.start",
                    "status": code,
                    "headers": [(b"content-type", PROBLEM_JSON.encode()), (b"content-length", str(len(body)).encode())],
                }
            )
            await send({"type": "http.response.body", "body": body})

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_body:
                    raise BodyTooLargeError
            return message

        try:
            if content_length is not None and content_length.isdigit() and int(content_length) > self._max_body:
                await send_problem(413, "invalid_request", "invalid JSON body: body too large")
                return
            await self._app(scope, limited_receive, send_with_headers)
        except Exception as e:
            self._log.error(
                "unhandled exception", request_id=rid, error=repr(e), stack="".join(traceback.format_exception(e))
            )
            if status == 0:  # nothing sent yet
                await send_problem(500, "internal_error", "internal server error")
        finally:
            route = scope.get("route")
            event = self._log.warning if status >= 500 else self._log.info
            event(
                "http request",
                method=scope["method"],
                # The route template, not the raw path: tokens, codes or PII
                # in URLs never reach the logs.
                route=getattr(route, "path", ""),
                status=status,
                latency_ms=round((time.perf_counter() - start) * 1000, 2),
                ip=ip,
                request_id=rid,
                user_id=scope.get("gate.user_id", ""),
            )
            requestctx.reset(token)
