import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from gate import requestctx
from gate.domain import AuditEvent, AuditFilter, JSONValue
from gate.logs import Logger
from gate.repository import AuditRepository
from gate.service.guard import new_id, truncate

# Writes allowed in the background before callers start waiting, so a slow
# database applies back-pressure instead of growing memory without bound.
_MAX_PENDING: Final = 1000
_WRITE_TIMEOUT: Final = 3.0


class AuditAction(StrEnum):
    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    REGISTERED = "auth.registered"
    SSO_LOGIN = "auth.sso.login"
    SSO_LINKED = "auth.sso.linked"
    REFRESH_REUSE = "auth.refresh.reuse_detected"
    LOGOUT = "auth.logout"
    LOGOUT_ALL = "auth.logout_all"
    PASSWORD_CHANGED = "auth.password.changed"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_ROLES_CHANGED = "user.roles.changed"
    USER_TYPES_CHANGED = "user.public_types.changed"
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DELETED = "role.deleted"
    ADMIN_BOOTSTRAPPED = "admin.bootstrapped"


class Auditor:
    """Records security events.

    Writes happen in the background so they add no latency to the request,
    and they are detached from it: an event is stored even if the client
    disconnects. A failed write is logged but never fails the request:
    availability of sign-in outweighs a missing audit row, and the log line
    still captures the event. ``close()`` waits for pending writes.
    """

    __slots__ = ("_log", "_pending", "_repo")

    def __init__(self, repo: AuditRepository, log: Logger) -> None:
        self._repo: Final = repo
        self._log: Final = log.bind(logger="audit")
        self._pending: Final[set[asyncio.Task[None]]] = set()

    async def record(
        self,
        action: AuditAction,
        *,
        actor: UUID | None = None,
        target_type: str = "",
        target_id: str = "",
        details: Mapping[str, JSONValue] | None = None,
    ) -> None:
        """Queues the event, enriched with request ID, IP and user agent."""
        meta = requestctx.current()
        event = AuditEvent(
            id=new_id(),
            occurred_at=datetime.now(UTC),
            actor_user_id=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip=meta.ip,
            user_agent=truncate(meta.user_agent, 512),
            request_id=meta.request_id,
            details=frozendict(details or {}),
        )
        if len(self._pending) >= _MAX_PENDING:
            await self._write(event)
            return
        task = asyncio.create_task(self._write(event))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _write(self, event: AuditEvent) -> None:
        try:
            async with asyncio.timeout(_WRITE_TIMEOUT):
                await self._repo.record(event)
        except Exception as e:
            self._log.error(
                "failed to record audit event", action=event.action, target_id=event.target_id, error=repr(e)
            )

    async def list(self, f: AuditFilter) -> tuple[AuditEvent, ...]:
        """Events, newest first."""
        return await self._repo.list(f)

    async def close(self) -> None:
        """Waits for queued writes (bounded by their own timeout)."""
        if self._pending:
            await asyncio.gather(*self._pending, return_exceptions=True)
