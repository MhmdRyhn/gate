import functools
from datetime import UTC, datetime
from typing import Final

import sqlalchemy as sa

from gate.domain import AuditEvent, AuditFilter, NotFoundError, User, UserIdentity
from gate.repository.postgres import rows
from gate.repository.postgres import tables as t
from gate.repository.postgres.db import Database, Prepared, prepare
from gate.repository.postgres.rows import A, U

_I = t.user_identities

# Finds the linked user and records the use in one statement: the UPDATE
# ... RETURNING runs as a CTE joined to the user query.
_LINK = (
    sa.update(_I)
    .where(
        _I.c.provider == sa.bindparam("p_provider", type_=sa.Text),
        _I.c.subject == sa.bindparam("p_subject", type_=sa.Text),
    )
    .values(last_used_at=sa.bindparam("p_now", type_=sa.DateTime(timezone=True)))
    .returning(_I.c.user_id)
    .cte("link")
)
_FIND_USER: Final = prepare(rows.select_users().join_from(U, _LINK, _LINK.c.user_id == U.c.id))
_INSERT_LINK: Final = prepare(
    sa.insert(_I).values({c.name: sa.bindparam(f"p_{c.name}", type_=c.type) for c in _I.c if c.name != "last_used_at"})
)


@functools.cache
def _list_events(*, by_actor: bool, by_action: bool) -> Prepared:
    """Four statement shapes from the optional filters; each prepared once."""
    stmt = sa.select(A)
    if by_actor:
        stmt = stmt.where(A.c.actor_user_id == sa.bindparam("p_actor", type_=sa.Uuid))
    if by_action:
        stmt = stmt.where(A.c.action == sa.bindparam("p_action", type_=sa.Text))
    return prepare(
        stmt.order_by(A.c.occurred_at.desc(), A.c.id.desc())
        .limit(sa.bindparam("p_limit", type_=sa.Integer))
        .offset(sa.bindparam("p_offset", type_=sa.Integer))
    )


class PostgresIdentityRepository:
    __slots__ = ("_db",)

    def __init__(self, db: Database) -> None:
        self._db: Final = db

    async def find_user(self, provider: str, subject: str) -> User:
        """The user linked to (provider, subject); records the use."""
        r = await self._db.fetchrow(
            _FIND_USER, {"p_provider": provider, "p_subject": subject, "p_now": datetime.now(UTC)}
        )
        if r is None:
            raise NotFoundError
        return rows.user(r)

    async def link(self, identity: UserIdentity) -> None:
        """Attaches an SSO identity to an existing user."""
        i = identity
        await self._db.run(
            _INSERT_LINK,
            {
                "p_id": i.id,
                "p_user_id": i.user_id,
                "p_provider": i.provider,
                "p_subject": i.subject,
                "p_email": i.email,
                "p_created_at": i.created_at,
            },
        )


class PostgresAuditRepository:
    """Writes use SQLAlchemy's normal execution (it serialises the jsonb
    column); they run in the background, off the request path."""

    __slots__ = ("_db",)

    def __init__(self, db: Database) -> None:
        self._db: Final = db

    async def record(self, e: AuditEvent) -> None:
        """Appends an event."""
        await self._db.execute(
            sa.insert(A).values(
                id=e.id,
                occurred_at=e.occurred_at,
                actor_user_id=e.actor_user_id,
                action=e.action,
                target_type=e.target_type,
                target_id=e.target_id,
                ip=e.ip,
                user_agent=e.user_agent,
                request_id=e.request_id,
                details=dict(e.details),
            )
        )

    async def list(self, f: AuditFilter) -> tuple[AuditEvent, ...]:
        """Events, newest first."""
        stmt = _list_events(by_actor=f.actor_user_id is not None, by_action=bool(f.action))
        params = {"p_actor": f.actor_user_id, "p_action": f.action, "p_limit": f.limit, "p_offset": f.offset}
        return tuple(rows.audit_event(r) for r in await self._db.fetch(stmt, params))
