from datetime import UTC, datetime
from typing import Final
from uuid import UUID

import sqlalchemy as sa

from gate.domain import InvalidTokenError, NotFoundError, RefreshToken, Session
from gate.repository.postgres import rows
from gate.repository.postgres.db import Database, prepare
from gate.repository.postgres.rows import RT, S

_TS = sa.DateTime(timezone=True)

# A refresh token by its hash, with its session, in one query.
_BY_TOKEN_HASH: Final = prepare(
    sa.select(
        RT.c.id.label("t_id"),
        RT.c.token_hash,
        RT.c.expires_at.label("t_expires_at"),
        RT.c.used_at,
        RT.c.created_at.label("t_created_at"),
        *S.c,
    )
    .select_from(RT.join(S, S.c.id == RT.c.session_id))
    .where(RT.c.token_hash == sa.bindparam("p_hash", type_=sa.LargeBinary))
)
_INSERT_SESSION: Final = prepare(
    sa.insert(S).values({c.name: sa.bindparam(f"p_{c.name}", type_=c.type) for c in S.c if c.name != "revoked_at"})
)
_INSERT_TOKEN: Final = prepare(
    sa.insert(RT).values({c.name: sa.bindparam(f"p_{c.name}", type_=c.type) for c in RT.c if c.name != "used_at"})
)
_MARK_USED: Final = prepare(
    sa.update(RT)
    .where(RT.c.id == sa.bindparam("p_id", type_=sa.Uuid), RT.c.used_at.is_(None))
    .values(used_at=sa.bindparam("p_now", type_=_TS))
)
_TOUCH_SESSION: Final = prepare(
    sa.update(S)
    .where(S.c.id == sa.bindparam("p_id", type_=sa.Uuid))
    .values(last_refreshed_at=sa.bindparam("p_now", type_=_TS))
)
_REVOKE: Final = prepare(
    sa.update(S)
    .where(S.c.id == sa.bindparam("p_id", type_=sa.Uuid), S.c.revoked_at.is_(None))
    .values(revoked_at=sa.bindparam("p_now", type_=_TS))
)
_REVOKE_ALL: Final = prepare(
    sa.update(S)
    .where(
        S.c.user_id == sa.bindparam("p_user_id", type_=sa.Uuid),
        S.c.revoked_at.is_(None),
        # keep: the session to leave active, or NULL to revoke them all.
        sa.or_(sa.bindparam("p_keep", type_=sa.Uuid).is_(None), S.c.id != sa.bindparam("p_keep", type_=sa.Uuid)),
    )
    .values(revoked_at=sa.bindparam("p_now", type_=_TS))
)
_PURGE_SESSIONS: Final = prepare(
    sa.delete(S).where(
        sa.or_(
            S.c.expires_at < sa.bindparam("p_before", type_=_TS), S.c.revoked_at < sa.bindparam("p_before", type_=_TS)
        )
    )
)
_PURGE_TOKENS: Final = prepare(sa.delete(RT).where(RT.c.expires_at < sa.bindparam("p_before", type_=_TS)))


def _now() -> datetime:
    return datetime.now(UTC)


def _token_params(rt: RefreshToken) -> dict[str, object]:
    return {
        "p_id": rt.id,
        "p_session_id": rt.session_id,
        "p_token_hash": rt.token_hash,
        "p_expires_at": rt.expires_at,
        "p_created_at": rt.created_at,
    }


class PostgresSessionRepository:
    __slots__ = ("_db",)

    def __init__(self, db: Database) -> None:
        self._db: Final = db

    async def create(self, s: Session, rt: RefreshToken) -> None:
        """Stores a session and its first refresh token atomically."""
        async with self._db.transaction() as tx:
            await self._db.tx_run(
                tx,
                _INSERT_SESSION,
                {
                    "p_id": s.id,
                    "p_user_id": s.user_id,
                    "p_auth_method": s.auth_method,
                    "p_ip": s.ip,
                    "p_user_agent": s.user_agent,
                    "p_created_at": s.created_at,
                    "p_last_refreshed_at": s.last_refreshed_at,
                    "p_expires_at": s.expires_at,
                },
            )
            await self._db.tx_run(tx, _INSERT_TOKEN, _token_params(rt))

    async def get_by_refresh_token(self, token_hash: bytes) -> tuple[RefreshToken, Session]:
        r = await self._db.fetchrow(_BY_TOKEN_HASH, {"p_hash": token_hash})
        if r is None:
            raise NotFoundError
        token = RefreshToken(
            id=rows.uuid(r["t_id"]),
            session_id=rows.uuid(r["id"]),
            token_hash=bytes(r["token_hash"]),
            expires_at=r["t_expires_at"],
            used_at=r["used_at"],
            created_at=r["t_created_at"],
        )
        return token, rows.session(r)

    async def rotate(self, old_token_id: UUID, next_token: RefreshToken) -> None:
        """Marks a refresh token used and stores its successor atomically.
        The conditional update makes concurrent refreshes with the same
        token race-safe: exactly one wins."""
        now = _now()
        async with self._db.transaction() as tx:
            if await self._db.tx_run(tx, _MARK_USED, {"p_id": old_token_id, "p_now": now}) == 0:
                raise InvalidTokenError
            await self._db.tx_run(tx, _INSERT_TOKEN, _token_params(next_token))
            await self._db.tx_run(tx, _TOUCH_SESSION, {"p_id": next_token.session_id, "p_now": now})

    async def revoke(self, session_id: UUID) -> None:
        """Ends a session; its access and refresh tokens stop working."""
        await self._db.run(_REVOKE, {"p_id": session_id, "p_now": _now()})

    async def revoke_all_for_user(self, user_id: UUID, keep: UUID | None = None) -> None:
        """Ends every session of a user, optionally keeping one."""
        await self._db.run(_REVOKE_ALL, {"p_user_id": user_id, "p_keep": keep, "p_now": _now()})

    async def purge(self, before: datetime) -> int:
        """Deletes sessions (cascading to tokens) and refresh tokens that
        expired or were revoked before ``before``."""
        async with self._db.transaction() as tx:
            n = await self._db.tx_run(tx, _PURGE_SESSIONS, {"p_before": before})
            return n + await self._db.tx_run(tx, _PURGE_TOKENS, {"p_before": before})
