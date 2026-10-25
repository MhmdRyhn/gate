import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Final
from uuid import UUID

from gate.domain import ConflictError, ForbiddenError, Principal, Role, UserKind, ValidationError
from gate.repository import RoleRepository
from gate.service.audit import AuditAction, Auditor
from gate.service.auth import utcnow
from gate.service.guard import clean_permissions, ensure_holds, new_id

_ROLE_NAME: Final = re.compile(r"^[a-z][a-z0-9_-]{1,49}$")


@dataclass(frozen=True, slots=True, kw_only=True)
class RoleInput:
    """Creates a role; for updates None fields are left unchanged."""

    name: str | None = None
    description: str | None = None
    permissions: tuple[str, ...] | None = None


def _apply(r: Role, data: RoleInput) -> Role:
    """A validated copy of r with the given changes."""
    name = (data.name if data.name is not None else r.name).strip()
    description = (data.description if data.description is not None else r.description).strip()
    if not _ROLE_NAME.match(name):
        raise ValidationError("name must be 2-50 chars of a-z, 0-9, '_' or '-', starting with a letter")
    if len(description) > 500:
        raise ValidationError("description must be at most 500 characters")
    perms = clean_permissions(data.permissions if data.permissions is not None else r.permissions)
    return replace(r, name=name, description=description, permissions=perms)


class RoleService:
    """Manages internal roles. System roles (defined in code) are read-only
    here."""

    __slots__ = ("_audit", "_now", "_roles")

    def __init__(self, *, roles: RoleRepository, audit: Auditor, now: Callable[[], datetime] = utcnow) -> None:
        self._roles: Final = roles
        self._audit: Final = audit
        self._now: Final = now

    async def list(self) -> tuple[Role, ...]:
        return await self._roles.list()

    async def get(self, id: UUID) -> Role:
        return await self._roles.get_by_id(id)

    async def create(self, actor: Principal, data: RoleInput) -> Role:
        """Adds an internal role from permissions the actor holds."""
        now = self._now()
        blank = Role(
            id=new_id(),
            name="",
            description="",
            audience=UserKind.INTERNAL,
            is_system=False,
            permissions=(),
            created_at=now,
            updated_at=now,
        )
        r = _apply(blank, data)
        ensure_holds(actor, r.permissions)
        try:
            created = await self._roles.create(r)
        except ConflictError:
            raise ConflictError("role name already exists") from None
        await self._audit.record(
            AuditAction.ROLE_CREATED,
            actor=actor.user_id,
            target_type="role",
            target_id=str(r.id),
            details={"name": r.name, "permissions": list(r.permissions)},
        )
        return created

    async def update(self, actor: Principal, id: UUID, data: RoleInput) -> Role:
        """Modifies a role the actor fully holds."""
        before = await self._editable(actor, id)
        after = _apply(before, data)
        ensure_holds(actor, after.permissions)
        try:
            await self._roles.update(after)
        except ConflictError:
            raise ConflictError("role name already exists") from None
        await self._audit.record(
            AuditAction.ROLE_UPDATED,
            actor=actor.user_id,
            target_type="role",
            target_id=str(id),
            details={"permissions_before": list(before.permissions), "permissions_after": list(after.permissions)},
        )
        return await self._roles.get_by_id(id)

    async def delete(self, actor: Principal, id: UUID) -> None:
        """Removes a role that is no longer assigned."""
        r = await self._editable(actor, id)
        try:
            await self._roles.delete(id)
        except ConflictError:
            raise ConflictError("role is still assigned to users") from None
        await self._audit.record(
            AuditAction.ROLE_DELETED,
            actor=actor.user_id,
            target_type="role",
            target_id=str(id),
            details={"name": r.name},
        )

    async def _editable(self, actor: Principal, id: UUID) -> Role:
        """A non-system role whose permissions the actor holds."""
        r = await self._roles.get_by_id(id)
        if r.is_system:
            raise ForbiddenError("system roles are managed in code")
        ensure_holds(actor, r.permissions)
        return r
