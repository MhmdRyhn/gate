"""Persistence ports. Services depend only on these protocols;
``gate.repository.postgres`` implements them with asyncpg. Methods raise
NotFoundError / ConflictError where relevant and return new immutable
entities rather than mutating their arguments."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from gate.domain import (
    AuditEvent,
    AuditFilter,
    PermissionDef,
    Principal,
    PublicUserType,
    RefreshToken,
    Role,
    Session,
    User,
    UserFilter,
    UserIdentity,
    UserPatch,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class CreateUserOptions:
    """Written atomically with a new user."""

    role_ids: tuple[UUID, ...] = ()  # internal users
    public_types: tuple[str, ...] = ()  # public users
    identity: UserIdentity | None = None  # SSO sign-up


class UserRepository(Protocol):
    async def create(self, u: User, opts: CreateUserOptions) -> User: ...
    async def get_by_id(self, id: UUID) -> User: ...
    async def get_by_email(self, email: str) -> User: ...
    async def get_by_phone(self, phone: str) -> User: ...
    async def list(self, f: UserFilter) -> tuple[User, ...]: ...
    async def count(self) -> int: ...
    async def update(self, id: UUID, patch: UserPatch) -> User: ...
    async def update_password(self, id: UUID, hash: str) -> None: ...
    async def touch_last_login(self, id: UUID) -> None: ...
    async def set_roles(self, user_id: UUID, role_ids: Sequence[UUID]) -> None:
        """Replaces an internal user's roles."""
        ...

    async def set_public_types(self, user_id: UUID, types: Sequence[str]) -> None:
        """Replaces a public user's types."""
        ...

    async def effective_roles(self, user_id: UUID) -> tuple[Role, ...]:
        """Assigned roles plus roles granted by the user's public types."""
        ...

    async def get_principal(self, user_id: UUID, session_id: UUID) -> Principal:
        """Loads an active user and session with effective permissions.
        NotFoundError if the session is unknown, revoked or expired;
        UserDisabledError if the user is disabled."""
        ...


class RoleRepository(Protocol):
    async def create(self, r: Role) -> Role: ...
    async def update(self, r: Role) -> None: ...
    async def delete(self, id: UUID) -> None: ...
    async def get_by_id(self, id: UUID) -> Role: ...
    async def get_by_name(self, name: str) -> Role: ...
    async def get_by_ids(self, ids: Sequence[UUID]) -> tuple[Role, ...]: ...
    async def list(self) -> tuple[Role, ...]: ...
    async def sync_permissions(self, defs: Sequence[PermissionDef]) -> None:
        """Makes the permissions table equal defs."""
        ...

    async def seed_role(self, r: Role, *, overwrite: bool) -> UUID:
        """Creates r if missing; with overwrite, an existing role's
        description and permissions are replaced. Returns the role's ID."""
        ...

    async def sync_public_user_types(self, defs: Sequence[PublicUserType]) -> None:
        """Makes public_user_types equal defs. Removing a type still held by
        users fails."""
        ...


class SessionRepository(Protocol):
    async def create(self, s: Session, rt: RefreshToken) -> None:
        """Stores a new session with its first refresh token."""
        ...

    async def get_by_refresh_token(self, token_hash: bytes) -> tuple[RefreshToken, Session]: ...
    async def rotate(self, old_token_id: UUID, next_token: RefreshToken) -> None:
        """Marks old_token_id used and stores next_token, atomically. Raises
        InvalidTokenError if old_token_id was already used."""
        ...

    async def revoke(self, session_id: UUID) -> None: ...
    async def revoke_all_for_user(self, user_id: UUID, keep: UUID | None = None) -> None: ...
    async def purge(self, before: datetime) -> int:
        """Deletes sessions and refresh tokens that ended before ``before``."""
        ...


class IdentityRepository(Protocol):
    async def find_user(self, provider: str, subject: str) -> User:
        """The user linked to (provider, subject); records the use."""
        ...

    async def link(self, identity: UserIdentity) -> None: ...


class AuditRepository(Protocol):
    async def record(self, e: AuditEvent) -> None: ...
    async def list(self, f: AuditFilter) -> tuple[AuditEvent, ...]: ...


class HealthChecker(Protocol):
    async def ping(self) -> None: ...
