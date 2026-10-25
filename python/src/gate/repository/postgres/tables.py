"""SQLAlchemy Core table definitions mirroring ../migrations.

The migrations are the source of truth for the schema: the application
never runs DDL from these definitions (no ``metadata.create_all``). They
exist to build type-checked queries. tests/test_tables.py checks that every
table and column here also appears in the migration.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

metadata = sa.MetaData()

_TS = sa.DateTime(timezone=True)


def _uuid_pk() -> sa.Column[object]:
    return sa.Column("id", sa.Uuid, primary_key=True)


users = sa.Table(
    "users",
    metadata,
    _uuid_pk(),
    sa.Column("email", sa.Text),
    sa.Column("phone", sa.Text),
    sa.Column("full_name", sa.Text, nullable=False),
    sa.Column("password_hash", sa.Text),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("email_verified_at", _TS),
    sa.Column("phone_verified_at", _TS),
    sa.Column("last_login_at", _TS),
    sa.Column("created_at", _TS, nullable=False),
    sa.Column("updated_at", _TS, nullable=False),
)

permissions = sa.Table(
    "permissions",
    metadata,
    sa.Column("code", sa.Text, primary_key=True),
    sa.Column("description", sa.Text, nullable=False),
)

roles = sa.Table(
    "roles",
    metadata,
    _uuid_pk(),
    sa.Column("name", sa.Text, nullable=False, unique=True),
    sa.Column("description", sa.Text, nullable=False),
    sa.Column("audience", sa.Text, nullable=False),
    sa.Column("is_system", sa.Boolean, nullable=False),
    sa.Column("created_at", _TS, nullable=False),
    sa.Column("updated_at", _TS, nullable=False),
)

role_permissions = sa.Table(
    "role_permissions",
    metadata,
    sa.Column("role_id", sa.Uuid, sa.ForeignKey("roles.id"), primary_key=True),
    sa.Column("permission_code", sa.Text, sa.ForeignKey("permissions.code"), primary_key=True),
)

user_roles = sa.Table(
    "user_roles",
    metadata,
    sa.Column("user_id", sa.Uuid, sa.ForeignKey("users.id"), primary_key=True),
    sa.Column("role_id", sa.Uuid, sa.ForeignKey("roles.id"), primary_key=True),
    sa.Column("granted_at", _TS, nullable=False, server_default=sa.func.now()),
)

public_user_types = sa.Table(
    "public_user_types",
    metadata,
    sa.Column("name", sa.Text, primary_key=True),
    sa.Column("description", sa.Text, nullable=False),
    sa.Column("role_id", sa.Uuid, sa.ForeignKey("roles.id")),
    sa.Column("self_registration", sa.Boolean, nullable=False),
)

user_public_types = sa.Table(
    "user_public_types",
    metadata,
    sa.Column("user_id", sa.Uuid, sa.ForeignKey("users.id"), primary_key=True),
    sa.Column("type_name", sa.Text, sa.ForeignKey("public_user_types.name"), primary_key=True),
    sa.Column("granted_at", _TS, nullable=False, server_default=sa.func.now()),
)

user_identities = sa.Table(
    "user_identities",
    metadata,
    _uuid_pk(),
    sa.Column("user_id", sa.Uuid, sa.ForeignKey("users.id"), nullable=False),
    sa.Column("provider", sa.Text, nullable=False),
    sa.Column("subject", sa.Text, nullable=False),
    sa.Column("email", sa.Text, nullable=False),
    sa.Column("created_at", _TS, nullable=False),
    sa.Column("last_used_at", _TS),
)

sessions = sa.Table(
    "sessions",
    metadata,
    _uuid_pk(),
    sa.Column("user_id", sa.Uuid, sa.ForeignKey("users.id"), nullable=False),
    sa.Column("auth_method", sa.Text, nullable=False),
    sa.Column("ip", sa.Text, nullable=False),
    sa.Column("user_agent", sa.Text, nullable=False),
    sa.Column("created_at", _TS, nullable=False),
    sa.Column("last_refreshed_at", _TS, nullable=False),
    sa.Column("expires_at", _TS, nullable=False),
    sa.Column("revoked_at", _TS),
)

refresh_tokens = sa.Table(
    "refresh_tokens",
    metadata,
    _uuid_pk(),
    sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id"), nullable=False),
    sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
    sa.Column("expires_at", _TS, nullable=False),
    sa.Column("used_at", _TS),
    sa.Column("created_at", _TS, nullable=False),
)

audit_events = sa.Table(
    "audit_events",
    metadata,
    _uuid_pk(),
    sa.Column("occurred_at", _TS, nullable=False),
    sa.Column("actor_user_id", sa.Uuid),  # no FK: events outlive users
    sa.Column("action", sa.Text, nullable=False),
    sa.Column("target_type", sa.Text, nullable=False),
    sa.Column("target_id", sa.Text, nullable=False),
    sa.Column("ip", sa.Text, nullable=False),
    sa.Column("user_agent", sa.Text, nullable=False),
    sa.Column("request_id", sa.Text, nullable=False),
    sa.Column("details", JSONB, nullable=False),
)
