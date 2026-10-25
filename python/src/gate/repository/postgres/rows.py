"""Reusable query fragments and the mapping from result rows (asyncpg
Records or SQLAlchemy RowMappings) to immutable domain entities. Storage
concerns (NULL password hashes, jsonb) stay here."""

from typing import Any, Final
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

from gate.domain import AuditEvent, Permission, RefreshToken, Role, Session, User, UserKind, UserStatus
from gate.repository.postgres import tables as t
from gate.repository.postgres.db import Record

U, R, S, RT, A = t.users, t.roles, t.sessions, t.refresh_tokens, t.audit_events
UPT, UR, PUT, RP = t.user_public_types, t.user_roles, t.public_user_types, t.role_permissions

UUID_ARRAY: Final = ARRAY(sa.Uuid)
TEXT_ARRAY: Final = ARRAY(sa.Text)


def _array(subquery: sa.Select[Any]) -> sa.ColumnElement[Any]:
    """PostgreSQL's ARRAY(SELECT ...): aggregates a correlated subquery into
    a list in the same round trip ('{}' when empty, never NULL)."""
    return sa.func.array(subquery.scalar_subquery())


# A user's public types, aggregated in the same query as the user.
PUBLIC_TYPES: Final = _array(sa.select(UPT.c.type_name).where(UPT.c.user_id == U.c.id).order_by(UPT.c.type_name))
# A role's permission codes.
ROLE_PERMISSIONS: Final = _array(
    sa.select(RP.c.permission_code).where(RP.c.role_id == R.c.id).order_by(RP.c.permission_code)
)

# The roles that apply to user :user_id: roles assigned directly (internal
# users) plus roles granted by their public types.
EFFECTIVE_ROLE_IDS: Final = sa.union(
    sa.select(UR.c.role_id).where(UR.c.user_id == sa.bindparam("user_id", type_=sa.Uuid)),
    sa.select(PUT.c.role_id)
    .join(UPT, UPT.c.type_name == PUT.c.name)
    .where(UPT.c.user_id == sa.bindparam("user_id", type_=sa.Uuid), PUT.c.role_id.is_not(None)),
)


def select_users() -> sa.Select[Any]:
    return sa.select(*U.c, PUBLIC_TYPES.label("public_types"))


def select_roles() -> sa.Select[Any]:
    return sa.select(*R.c, ROLE_PERMISSIONS.label("permissions"))


def uuid(v: Any) -> UUID:
    # asyncpg returns its own UUID subclass; normalise to the stdlib type.
    return v if type(v) is UUID else UUID(str(v))


def user(r: Record) -> User:
    return User(
        id=uuid(r["id"]),
        email=r["email"],
        phone=r["phone"],
        full_name=r["full_name"],
        password_hash=r["password_hash"] or "",
        kind=UserKind(r["kind"]),
        status=UserStatus(r["status"]),
        public_types=tuple(r["public_types"]),
        email_verified_at=r["email_verified_at"],
        phone_verified_at=r["phone_verified_at"],
        last_login_at=r["last_login_at"],
        created_at=r["created_at"],
        updated_at=r["updated_at"],
    )


def role(r: Record) -> Role:
    return Role(
        id=uuid(r["id"]),
        name=r["name"],
        description=r["description"],
        audience=UserKind(r["audience"]),
        is_system=r["is_system"],
        permissions=tuple(Permission(p) for p in r["permissions"]),
        created_at=r["created_at"],
        updated_at=r["updated_at"],
    )


def session(r: Record) -> Session:
    return Session(
        id=uuid(r["id"]),
        user_id=uuid(r["user_id"]),
        auth_method=r["auth_method"],
        ip=r["ip"],
        user_agent=r["user_agent"],
        created_at=r["created_at"],
        last_refreshed_at=r["last_refreshed_at"],
        expires_at=r["expires_at"],
        revoked_at=r["revoked_at"],
    )


def refresh_token(r: Record) -> RefreshToken:
    return RefreshToken(
        id=uuid(r["id"]),
        session_id=uuid(r["session_id"]),
        token_hash=bytes(r["token_hash"]),
        expires_at=r["expires_at"],
        used_at=r["used_at"],
        created_at=r["created_at"],
    )


def audit_event(r: Record) -> AuditEvent:
    return AuditEvent(
        id=uuid(r["id"]),
        occurred_at=r["occurred_at"],
        actor_user_id=uuid(r["actor_user_id"]) if r["actor_user_id"] is not None else None,
        action=r["action"],
        target_type=r["target_type"],
        target_id=r["target_id"],
        ip=r["ip"],
        user_agent=r["user_agent"],
        request_id=r["request_id"],
        details=frozendict(r["details"] or {}),
    )
