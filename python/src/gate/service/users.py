from dataclasses import dataclass, replace
from typing import Final
from uuid import UUID

from gate import rbac
from gate.domain import (
    ForbiddenError,
    Principal,
    Role,
    User,
    UserFilter,
    UserKind,
    UserPatch,
    UserStatus,
    ValidationError,
)
from gate.repository import CreateUserOptions, RoleRepository, UserRepository
from gate.service.audit import AuditAction, Auditor
from gate.service.auth import AuthService, create_user
from gate.service.guard import (
    clean_full_name,
    ensure_can_grant_public_types,
    ensure_can_grant_roles,
    ensure_can_manage_user,
)


@dataclass(frozen=True, slots=True)
class UserDetails:
    """A user with its effective roles."""

    user: User
    roles: tuple[Role, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class CreateUserInput:
    password: str
    email: str = ""
    phone: str = ""
    full_name: str = ""
    kind: UserKind = UserKind.INTERNAL
    role_ids: tuple[UUID, ...] = ()  # internal users only
    public_types: tuple[str, ...] = ()  # public users only, at least one


class UserService:
    """Manages users on behalf of internal staff."""

    __slots__ = ("_audit", "_auth", "_roles", "_users")

    def __init__(self, *, users: UserRepository, roles: RoleRepository, auth: AuthService, audit: Auditor) -> None:
        self._users: Final = users
        self._roles: Final = roles
        self._auth: Final = auth
        self._audit: Final = audit

    async def create(self, actor: Principal, data: CreateUserInput) -> UserDetails:
        """Adds a user. Granting roles requires users:assign_roles, and the
        actor must hold every permission the new user would receive."""
        opts = CreateUserOptions()
        match data.kind:
            case UserKind.INTERNAL:
                if data.public_types:
                    raise ValidationError("public_types are only allowed for public users")
                if data.role_ids:
                    if not actor.can(rbac.USERS_ASSIGN_ROLES):
                        raise ForbiddenError(f"requires permission {rbac.USERS_ASSIGN_ROLES!r}")
                    opts = replace(opts, role_ids=await ensure_can_grant_roles(self._roles, actor, data.role_ids))
            case UserKind.PUBLIC:
                if data.role_ids:
                    raise ValidationError("public users get access through public_types; role_ids are not allowed")
                opts = replace(
                    opts, public_types=await ensure_can_grant_public_types(self._roles, actor, data.public_types)
                )

        u = await self._auth.new_user(data.email, data.phone, data.full_name, data.password, data.kind)
        u = await create_user(self._users, u, opts)
        await self._audit.record(
            AuditAction.USER_CREATED,
            actor=actor.user_id,
            target_type="user",
            target_id=str(u.id),
            details={
                "kind": str(u.kind),
                "role_ids": [str(i) for i in opts.role_ids],
                "public_types": list(opts.public_types),
            },
        )
        return await self.get(u.id)

    async def get(self, id: UUID) -> UserDetails:
        u = await self._users.get_by_id(id)
        return UserDetails(u, await self._users.effective_roles(id))

    async def list(self, f: UserFilter) -> tuple[User, ...]:
        return await self._users.list(f)

    async def update(self, actor: Principal, id: UUID, patch: UserPatch) -> UserDetails:
        """Changes profile fields or status. Disabling a user revokes all of
        their sessions immediately."""
        if patch.full_name is not None:
            patch = replace(patch, full_name=clean_full_name(patch.full_name))
        if patch.status is not None and id == actor.user_id:
            raise ValidationError("you cannot change your own status")
        await ensure_can_manage_user(self._users, actor, id)
        await self._users.update(id, patch)
        if patch.status == UserStatus.DISABLED:
            await self._auth.sessions.revoke_all_for_user(id)
        await self._audit.record(
            AuditAction.USER_UPDATED,
            actor=actor.user_id,
            target_type="user",
            target_id=str(id),
            details={"full_name_changed": patch.full_name is not None, "status": patch.status},
        )
        return await self.get(id)

    async def set_roles(self, actor: Principal, id: UUID, role_ids: tuple[UUID, ...]) -> UserDetails:
        """Replaces an internal user's roles. The actor must be able to
        manage both the roles removed and the roles granted."""
        if id == actor.user_id:
            raise ValidationError("you cannot change your own roles")
        u = await ensure_can_manage_user(self._users, actor, id)
        if u.kind != UserKind.INTERNAL:
            raise ValidationError("public users get access through public types; use the public-types endpoint")
        ids = await ensure_can_grant_roles(self._roles, actor, role_ids)
        await self._users.set_roles(id, ids)
        await self._audit.record(
            AuditAction.USER_ROLES_CHANGED,
            actor=actor.user_id,
            target_type="user",
            target_id=str(id),
            details={"role_ids": [str(i) for i in ids]},
        )
        return await self.get(id)

    async def set_public_types(self, actor: Principal, id: UUID, types: tuple[str, ...]) -> UserDetails:
        """Replaces a public user's types (one or more)."""
        u = await ensure_can_manage_user(self._users, actor, id)
        if u.kind != UserKind.PUBLIC:
            raise ValidationError("public types can only be set on public users")
        names = await ensure_can_grant_public_types(self._roles, actor, types)
        await self._users.set_public_types(id, names)
        await self._audit.record(
            AuditAction.USER_TYPES_CHANGED,
            actor=actor.user_id,
            target_type="user",
            target_id=str(id),
            details={"from": list(u.public_types), "to": list(names)},
        )
        return await self.get(id)
