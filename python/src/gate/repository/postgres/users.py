import functools
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

from gate.domain import (
    NotFoundError,
    Permission,
    Principal,
    Role,
    User,
    UserDisabledError,
    UserFilter,
    UserKind,
    UserPatch,
)
from gate.repository import CreateUserOptions
from gate.repository.postgres import rows
from gate.repository.postgres import tables as t
from gate.repository.postgres.db import Database, Prepared, prepare
from gate.repository.postgres.rows import RP, UPT, UR, U

_TS = sa.DateTime(timezone=True)

# Static statements, compiled once (see db.prepare).
_BY_ID: Final = prepare(rows.select_users().where(U.c.id == sa.bindparam("p_v", type_=sa.Uuid)))
_BY_EMAIL: Final = prepare(rows.select_users().where(U.c.email == sa.bindparam("p_v", type_=sa.Text)))
_BY_PHONE: Final = prepare(rows.select_users().where(U.c.phone == sa.bindparam("p_v", type_=sa.Text)))
_EFFECTIVE_ROLES: Final = prepare(
    rows.select_roles().where(rows.R.c.id.in_(rows.EFFECTIVE_ROLE_IDS.scalar_subquery())).order_by(rows.R.c.name)
)
# Resolves the request principal in ONE round trip: the user must be active
# and the session unrevoked and unexpired. This runs on every authenticated
# request and is served by primary-key and indexed lookups.
_PRINCIPAL: Final = prepare(
    sa.select(
        U.c.kind,
        U.c.status,
        sa.func.array(
            sa.select(RP.c.permission_code)
            .distinct()
            .where(RP.c.role_id.in_(rows.EFFECTIVE_ROLE_IDS.scalar_subquery()))
            .scalar_subquery()
        ).label("permissions"),
        rows.PUBLIC_TYPES.label("public_types"),
    )
    .select_from(U.join(rows.S, rows.S.c.user_id == U.c.id))
    .where(
        U.c.id == sa.bindparam("user_id", type_=sa.Uuid),
        rows.S.c.id == sa.bindparam("p_session_id", type_=sa.Uuid),
        rows.S.c.revoked_at.is_(None),
        rows.S.c.expires_at > sa.func.now(),
    )
)
_INSERT: Final = prepare(
    sa.insert(U).values({c.name: sa.bindparam(f"p_{c.name}", type_=c.type) for c in U.c if c.name != "last_login_at"})
)
_INSERT_ROLE: Final = prepare(
    sa.insert(UR).values(
        user_id=sa.bindparam("p_user_id", type_=sa.Uuid), role_id=sa.bindparam("p_role_id", type_=sa.Uuid)
    )
)
_INSERT_TYPE: Final = prepare(
    sa.insert(UPT).values(
        user_id=sa.bindparam("p_user_id", type_=sa.Uuid), type_name=sa.bindparam("p_type", type_=sa.Text)
    )
)
_INSERT_IDENTITY: Final = prepare(
    sa.insert(t.user_identities).values(
        {c.name: sa.bindparam(f"p_{c.name}", type_=c.type) for c in t.user_identities.c if c.name != "last_used_at"}
    )
)
_DELETE_ROLES: Final = prepare(sa.delete(UR).where(UR.c.user_id == sa.bindparam("p_user_id", type_=sa.Uuid)))
_DELETE_TYPES: Final = prepare(sa.delete(UPT).where(UPT.c.user_id == sa.bindparam("p_user_id", type_=sa.Uuid)))
_SET_PASSWORD: Final = prepare(
    sa.update(U)
    .where(U.c.id == sa.bindparam("p_id", type_=sa.Uuid))
    .values(password_hash=sa.bindparam("p_hash", type_=sa.Text), updated_at=sa.bindparam("p_now", type_=_TS))
)
_TOUCH_LOGIN: Final = prepare(
    sa.update(U)
    .where(U.c.id == sa.bindparam("p_id", type_=sa.Uuid))
    .values(last_login_at=sa.bindparam("p_now", type_=_TS))
)


@functools.cache
def _list_users(*, by_kind: bool, by_type: bool) -> Prepared:
    """The optional filters give four statement shapes; each is prepared
    once, on first use."""
    stmt = rows.select_users()
    if by_kind:
        stmt = stmt.where(U.c.kind == sa.bindparam("p_kind", type_=sa.Text))
    if by_type:
        stmt = stmt.where(
            U.c.id.in_(sa.select(UPT.c.user_id).where(UPT.c.type_name == sa.bindparam("p_type", type_=sa.Text)))
        )
    return prepare(
        stmt.order_by(U.c.created_at, U.c.id)
        .limit(sa.bindparam("p_limit", type_=sa.Integer))
        .offset(sa.bindparam("p_offset", type_=sa.Integer))
    )


def _now() -> datetime:
    return datetime.now(UTC)


class PostgresUserRepository:
    __slots__ = ("_db",)

    def __init__(self, db: Database) -> None:
        self._db: Final = db

    async def create(self, u: User, opts: CreateUserOptions) -> User:
        """Inserts the user with its roles, public types and SSO identity in
        one transaction."""
        values = {
            "p_id": u.id,
            "p_email": u.email,
            "p_phone": u.phone,
            "p_full_name": u.full_name,
            "p_password_hash": u.password_hash or None,
            "p_kind": str(u.kind),
            "p_status": str(u.status),
            "p_email_verified_at": u.email_verified_at,
            "p_phone_verified_at": u.phone_verified_at,
            "p_created_at": u.created_at,
            "p_updated_at": u.updated_at,
        }
        async with self._db.transaction() as tx:
            await self._db.tx_run(tx, _INSERT, values)
            await _insert_roles(self._db, tx, u.id, opts.role_ids)
            await _insert_public_types(self._db, tx, u.id, opts.public_types)
            if (i := opts.identity) is not None:
                await self._db.tx_run(
                    tx,
                    _INSERT_IDENTITY,
                    {
                        "p_id": i.id,
                        "p_user_id": u.id,
                        "p_provider": i.provider,
                        "p_subject": i.subject,
                        "p_email": i.email,
                        "p_created_at": i.created_at,
                    },
                )
        return await self.get_by_id(u.id)

    async def _one(self, stmt: Prepared, value: object) -> User:
        r = await self._db.fetchrow(stmt, {"p_v": value})
        if r is None:
            raise NotFoundError
        return rows.user(r)

    async def get_by_id(self, id: UUID) -> User:
        return await self._one(_BY_ID, id)

    async def get_by_email(self, email: str) -> User:
        return await self._one(_BY_EMAIL, email)

    async def get_by_phone(self, phone: str) -> User:
        return await self._one(_BY_PHONE, phone)

    async def list(self, f: UserFilter) -> tuple[User, ...]:
        """Users ordered by creation time (index users_kind_created_idx)."""
        stmt = _list_users(by_kind=f.kind is not None, by_type=f.public_type is not None)
        params = {"p_kind": str(f.kind), "p_type": f.public_type, "p_limit": f.limit, "p_offset": f.offset}
        return tuple(rows.user(r) for r in await self._db.fetch(stmt, params))

    async def count(self) -> int:
        rows_ = await self._db.all(sa.select(sa.func.count().label("n")).select_from(U))
        return int(rows_[0]["n"])

    async def update(self, id: UUID, patch: UserPatch) -> User:
        changes: dict[str, object] = {"updated_at": _now()}
        if patch.full_name is not None:
            changes["full_name"] = patch.full_name
        if patch.status is not None:
            changes["status"] = str(patch.status)
        if await self._db.execute(sa.update(U).where(U.c.id == id).values(changes)) == 0:
            raise NotFoundError
        return await self.get_by_id(id)

    async def update_password(self, id: UUID, hash: str) -> None:
        if await self._db.run(_SET_PASSWORD, {"p_id": id, "p_hash": hash, "p_now": _now()}) == 0:
            raise NotFoundError

    async def touch_last_login(self, id: UUID) -> None:
        await self._db.run(_TOUCH_LOGIN, {"p_id": id, "p_now": _now()})

    async def set_roles(self, user_id: UUID, role_ids: Sequence[UUID]) -> None:
        async with self._db.transaction() as tx:
            await self._db.tx_run(tx, _DELETE_ROLES, {"p_user_id": user_id})
            await _insert_roles(self._db, tx, user_id, role_ids)

    async def set_public_types(self, user_id: UUID, types: Sequence[str]) -> None:
        async with self._db.transaction() as tx:
            await self._db.tx_run(tx, _DELETE_TYPES, {"p_user_id": user_id})
            await _insert_public_types(self._db, tx, user_id, types)

    async def effective_roles(self, user_id: UUID) -> tuple[Role, ...]:
        return tuple(rows.role(r) for r in await self._db.fetch(_EFFECTIVE_ROLES, {"user_id": user_id}))

    async def get_principal(self, user_id: UUID, session_id: UUID) -> Principal:
        r = await self._db.fetchrow(_PRINCIPAL, {"user_id": user_id, "p_session_id": session_id})
        if r is None:
            raise NotFoundError
        if r["status"] != "active":
            raise UserDisabledError
        return Principal(
            user_id=user_id,
            session_id=session_id,
            kind=UserKind(r["kind"]),
            public_types=tuple(r["public_types"]),
            permissions=frozenset(Permission(p) for p in r["permissions"]),
        )


async def _insert_roles(db: Database, tx: AsyncConnection, user_id: UUID, role_ids: Sequence[UUID]) -> None:
    if role_ids:
        await db.tx_run_many(tx, _INSERT_ROLE, [{"p_user_id": user_id, "p_role_id": r} for r in role_ids])


async def _insert_public_types(db: Database, tx: AsyncConnection, user_id: UUID, types: Sequence[str]) -> None:
    if types:
        await db.tx_run_many(tx, _INSERT_TYPE, [{"p_user_id": user_id, "p_type": n} for n in types])
