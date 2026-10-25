"""Input normalisation and the authorization rules that depend on data
(privilege escalation, kind separation). The HTTP layer only checks
route-level access."""

import re
import uuid
from collections.abc import Iterable, Sequence
from email.utils import parseaddr
from typing import Final
from uuid import UUID

from gate import rbac
from gate.domain import ForbiddenError, Permission, Principal, Role, User, UserKind, ValidationError
from gate.repository import RoleRepository, UserRepository

# Limits on collection inputs, to bound work per request.
MAX_ROLES_PER_USER: Final = 50
MAX_PUBLIC_TYPES_PER_USER: Final = 10

_PHONE_SEPARATORS: Final = str.maketrans("", "", " -().")
_E164: Final = re.compile(r"^\+[1-9][0-9]{7,14}$")
_EMAIL: Final = re.compile(r"^[^@\s<>()\[\],;:\"]+@[^@\s<>()\[\],;:\"]+\.[^@\s<>()\[\],;:\"]+$")


def new_id() -> UUID:
    """A time-ordered UUIDv7, which keeps B-tree inserts local."""
    return uuid.uuid7()


def ensure_holds(actor: Principal, perms: Iterable[Permission]) -> None:
    """The privilege-escalation guard: an actor may only grant, revoke or
    edit permissions they hold themselves. A manager therefore cannot create
    an admin, edit an admin's roles or disable an admin."""
    for p in perms:
        if not actor.can(p):
            raise ForbiddenError(f"requires permission {p!r}")


def role_permissions(roles: Iterable[Role]) -> list[Permission]:
    return [p for r in roles for p in r.permissions]


async def ensure_can_grant_roles(roles: RoleRepository, actor: Principal, ids: Sequence[UUID]) -> tuple[UUID, ...]:
    """Every role must exist and be internal, and the actor must hold all of
    its permissions. Returns de-duplicated IDs."""
    unique = dedupe(ids)
    if len(unique) > MAX_ROLES_PER_USER:
        raise ValidationError(f"at most {MAX_ROLES_PER_USER} roles per user")
    found = await roles.get_by_ids(unique)
    if len(found) != len(unique):
        raise ValidationError("one or more roles do not exist")
    for r in found:
        if r.audience != UserKind.INTERNAL:
            raise ValidationError(f"role {r.name!r} is a public role and is granted through public types")
    ensure_holds(actor, role_permissions(found))
    return unique


async def ensure_can_grant_public_types(
    roles: RoleRepository, actor: Principal, types: Sequence[str]
) -> tuple[str, ...]:
    """Every type must exist and, for types that carry a role, the actor
    must hold the role's permissions. Returns sorted, de-duplicated names."""
    unique = dedupe(types)
    if not unique:
        raise ValidationError("public users need at least one public type")
    if len(unique) > MAX_PUBLIC_TYPES_PER_USER:
        raise ValidationError(f"at most {MAX_PUBLIC_TYPES_PER_USER} public types per user")
    for name in unique:
        t = rbac.lookup_public_type(name)
        if t is None:
            raise ValidationError(f"unknown public type {name!r}")
        if t.role:
            ensure_holds(actor, (await roles.get_by_name(t.role)).permissions)
    return tuple(sorted(unique))


async def ensure_can_manage_user(users: UserRepository, actor: Principal, id: UUID) -> User:
    """Loads the target and checks that the actor holds every permission the
    target holds."""
    u = await users.get_by_id(id)
    ensure_holds(actor, role_permissions(await users.effective_roles(id)))
    return u


def clean_permissions(perms: Iterable[str]) -> tuple[Permission, ...]:
    """Validates, de-duplicates and sorts permission codes."""
    out = tuple(sorted(set(perms)))
    for p in out:
        if not rbac.is_known(p):
            raise ValidationError(f"unknown permission {p!r}")
    return tuple(Permission(p) for p in out)


def normalize_email(s: str) -> str:
    s = s.strip().lower()
    _, addr = parseaddr(s)
    if addr != s or len(s) > 254 or not _EMAIL.match(s):
        raise ValidationError("invalid email address")
    return s


def normalize_phone(s: str) -> str:
    """Accepts international numbers with common separators
    ("+880 1712-345678", "00880...") and returns E.164."""
    s = s.strip().translate(_PHONE_SEPARATORS)
    if s.startswith("00"):
        s = "+" + s[2:]
    if not _E164.match(s):
        raise ValidationError("phone must be in international format, e.g. +8801712345678")
    return s


def contact_input(email: str, phone: str) -> tuple[str | None, str | None]:
    """Validates an optional email and phone (at least one is required)."""
    e = normalize_email(email) if email.strip() else None
    p = normalize_phone(phone) if phone.strip() else None
    if e is None and p is None:
        raise ValidationError("email or phone is required")
    return e, p


def clean_full_name(s: str) -> str:
    s = s.strip()
    if len(s) > 200:
        raise ValidationError("full_name must be at most 200 characters")
    return s


def dedupe[T](items: Iterable[T]) -> tuple[T, ...]:
    """Removes duplicates, keeping first occurrences in order."""
    return tuple(dict.fromkeys(items))


def truncate(s: str, n: int) -> str:
    return s[:n]
