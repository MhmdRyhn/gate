"""Core entities of the identity and access system. They depend on nothing
but the standard library, so every other layer can share them.

    User ──< UserRole >── Role ──< RolePermission >── Permission   (internal users)
    User ──< UserPublicType >── PublicUserType ──(optional)──> Role (public users)
    User ──< UserIdentity                                           (SSO links)
    User ──< Session ──< RefreshToken                               (sign-ins)

Every entity is a frozen, slotted dataclass: attributes cannot be reassigned
and collections are tuples, frozensets or frozendicts. Use
``dataclasses.replace`` to derive a changed copy.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import NewType
from uuid import UUID

type JSONValue = str | int | float | bool | list[JSONValue] | dict[str, JSONValue] | None

# One operation, formatted "<resource>:<action>".
Permission = NewType("Permission", str)


class UserStatus(StrEnum):
    """Controls whether a user may authenticate at all."""

    ACTIVE = "active"
    DISABLED = "disabled"


class UserKind(StrEnum):
    """Separates staff from users of the public application. Fixed at
    creation; roles carry the same value as their audience."""

    INTERNAL = "internal"
    PUBLIC = "public"


@dataclass(frozen=True, slots=True, kw_only=True)
class User:
    """An account. Signs in with an email or phone (at least one is set)
    plus a password, and/or through linked SSO identities. Users are
    disabled rather than deleted so references stay intact."""

    id: UUID
    email: str | None  # lower-cased
    phone: str | None  # E.164, e.g. +8801712345678
    full_name: str
    password_hash: str  # empty for SSO-only accounts
    kind: UserKind
    status: UserStatus
    created_at: datetime
    updated_at: datetime
    public_types: tuple[str, ...] = ()  # public users only
    email_verified_at: datetime | None = None
    phone_verified_at: datetime | None = None
    last_login_at: datetime | None = None

    @property
    def has_password(self) -> bool:
        return self.password_hash != ""


@dataclass(frozen=True, slots=True, kw_only=True)
class UserPatch:
    """A partial update; None fields are left unchanged."""

    full_name: str | None = None
    status: UserStatus | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class UserFilter:
    """Narrows user listings; None matches everything."""

    kind: UserKind | None = None
    public_type: str | None = None
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True, slots=True, kw_only=True)
class Role:
    """A named bundle of permissions. System roles are defined in code
    (module rbac) and are read-only through the API."""

    id: UUID
    name: str
    description: str
    audience: UserKind
    is_system: bool
    permissions: tuple[Permission, ...]
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class PermissionDef:
    """A permission in the registry."""

    code: Permission
    description: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PublicUserType:
    """A category of public user (e.g. customer, vendor). Defined in code;
    a user may hold several."""

    name: str
    description: str
    # Optionally names a public role whose permissions holders of this type
    # receive. Empty means the type grants no permissions.
    role: str = ""
    # Allows public sign-up with this type. Other types are granted by
    # internal users only.
    self_registration: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class UserIdentity:
    """Links a user to an account at an external identity provider. The
    pair (provider, subject) is globally unique."""

    id: UUID
    user_id: UUID
    provider: str  # registry name, e.g. "google"
    subject: str  # provider's stable user ID ("sub" claim)
    email: str  # as asserted by the provider at link time
    created_at: datetime
    last_used_at: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Session:
    """One sign-in on one device. Access tokens reference it ("sid"), so
    revoking a session immediately invalidates its access tokens here."""

    id: UUID
    user_id: UUID
    auth_method: str  # "password" or "sso:<provider>"
    ip: str
    user_agent: str
    created_at: datetime
    last_refreshed_at: datetime
    expires_at: datetime  # absolute lifetime
    revoked_at: datetime | None = None

    def active(self, now: datetime) -> bool:
        return self.revoked_at is None and now < self.expires_at


@dataclass(frozen=True, slots=True, kw_only=True)
class RefreshToken:
    """A single-use credential of a session. Only the SHA-256 hash is
    stored. Using it rotates it; presenting a used token again revokes the
    session."""

    id: UUID
    session_id: UUID
    token_hash: bytes
    expires_at: datetime
    created_at: datetime
    used_at: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditEvent:
    """A security-relevant action."""

    id: UUID
    occurred_at: datetime
    action: str  # e.g. "auth.login.failed", "user.roles.changed"
    actor_user_id: UUID | None = None
    target_type: str = ""  # e.g. "user", "role", "session"
    target_id: str = ""
    ip: str = ""
    user_agent: str = ""
    request_id: str = ""
    details: frozendict[str, JSONValue] = field(default_factory=frozendict)


@dataclass(frozen=True, slots=True, kw_only=True)
class AuditFilter:
    actor_user_id: UUID | None = None
    action: str = ""
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True, slots=True, kw_only=True)
class Principal:
    """The authenticated actor of a request."""

    user_id: UUID
    session_id: UUID
    kind: UserKind
    public_types: tuple[str, ...] = ()
    permissions: frozenset[Permission] = frozenset()

    def can(self, perm: Permission) -> bool:
        return perm in self.permissions

    def has_public_type(self, *types: str) -> bool:
        return not set(types).isdisjoint(self.public_types)
