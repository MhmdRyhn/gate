from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from gate.domain import ConflictError, NotFoundError, Permission, PermissionDef, PublicUserType, Role, UserKind
from gate.repository.postgres import rows
from gate.repository.postgres import tables as t
from gate.repository.postgres.db import Database, Prepared, prepare
from gate.repository.postgres.rows import PUT, RP, R

_TS = sa.DateTime(timezone=True)


def _p(name: str, type_: Any) -> sa.BindParameter[Any]:
    """A named parameter; the p_ prefix never collides with a column name."""
    return sa.bindparam(f"p_{name}", type_=type_)


_BY_ID: Final = prepare(rows.select_roles().where(R.c.id == _p("v", sa.Uuid)))
_BY_NAME: Final = prepare(rows.select_roles().where(R.c.name == _p("v", sa.Text)))
# "= ANY(:ids)" keeps one SQL text (and one prepared statement) for any
# number of IDs, unlike an expanding IN (...).
_BY_IDS: Final = prepare(rows.select_roles().where(R.c.id == sa.any_(_p("ids", rows.UUID_ARRAY))).order_by(R.c.name))
_ALL: Final = prepare(rows.select_roles().order_by(R.c.name))

_INSERT: Final = prepare(sa.insert(R).values({c.name: _p(c.name, c.type) for c in R.c}))
_UPDATE: Final = prepare(
    sa.update(R)
    .where(R.c.id == _p("id", sa.Uuid))
    .values(name=_p("name", sa.Text), description=_p("description", sa.Text), updated_at=_p("now", _TS))
)
_DELETE: Final = prepare(sa.delete(R).where(R.c.id == _p("id", sa.Uuid)))
_DELETE_PERMS: Final = prepare(sa.delete(RP).where(RP.c.role_id == _p("role_id", sa.Uuid)))
_INSERT_PERM: Final = prepare(sa.insert(RP).values(role_id=_p("role_id", sa.Uuid), permission_code=_p("code", sa.Text)))

# Seeding: runs once per deploy, so plain readability over speed.
_LOCK_BY_NAME: Final = prepare(sa.select(R.c.id).where(R.c.name == _p("name", sa.Text)).with_for_update())
_RESEED: Final = prepare(
    sa.update(R)
    .where(R.c.id == _p("id", sa.Uuid))
    .values(
        description=_p("description", sa.Text),
        audience=_p("audience", sa.Text),
        is_system=_p("is_system", sa.Boolean),
        updated_at=_p("now", _TS),
    )
)
_PUBLIC_ROLE_ID: Final = prepare(
    sa.select(R.c.id).where(R.c.name == _p("name", sa.Text), R.c.audience == str(UserKind.PUBLIC))
)
_P = t.permissions
_perm_upsert = pg_insert(_P).values(code=_p("code", sa.Text), description=_p("description", sa.Text))
_UPSERT_PERM: Final = prepare(
    _perm_upsert.on_conflict_do_update(
        index_elements=[_P.c.code], set_={"description": _perm_upsert.excluded.description}
    )
)
_DELETE_OBSOLETE_PERMS: Final = prepare(sa.delete(_P).where(_P.c.code != sa.all_(_p("codes", rows.TEXT_ARRAY))))
_type_upsert = pg_insert(PUT).values(
    name=_p("name", sa.Text),
    description=_p("description", sa.Text),
    role_id=_p("role_id", sa.Uuid),
    self_registration=_p("self_registration", sa.Boolean),
)
_UPSERT_TYPE: Final = prepare(
    _type_upsert.on_conflict_do_update(
        index_elements=[PUT.c.name],
        set_={c: _type_upsert.excluded[c] for c in ("description", "role_id", "self_registration")},
    )
)
_DELETE_OBSOLETE_TYPES: Final = prepare(sa.delete(PUT).where(PUT.c.name != sa.all_(_p("names", rows.TEXT_ARRAY))))


def _now() -> datetime:
    return datetime.now(UTC)


def _role_params(r: Role) -> dict[str, object]:
    return {
        "p_id": r.id,
        "p_name": r.name,
        "p_description": r.description,
        "p_audience": str(r.audience),
        "p_is_system": r.is_system,
        "p_created_at": r.created_at,
        "p_updated_at": r.updated_at,
    }


class PostgresRoleRepository:
    __slots__ = ("_db",)

    def __init__(self, db: Database) -> None:
        self._db: Final = db

    async def _one(self, stmt: Prepared, value: object) -> Role:
        r = await self._db.fetchrow(stmt, {"p_v": value})
        if r is None:
            raise NotFoundError
        return rows.role(r)

    async def get_by_id(self, id: UUID) -> Role:
        return await self._one(_BY_ID, id)

    async def get_by_name(self, name: str) -> Role:
        return await self._one(_BY_NAME, name)

    async def get_by_ids(self, ids: Sequence[UUID]) -> tuple[Role, ...]:
        if not ids:
            return ()
        return tuple(rows.role(r) for r in await self._db.fetch(_BY_IDS, {"p_ids": list(ids)}))

    async def list(self) -> tuple[Role, ...]:
        return tuple(rows.role(r) for r in await self._db.fetch(_ALL))

    async def create(self, r: Role) -> Role:
        """Inserts a role and its permissions atomically."""
        async with self._db.transaction() as tx:
            await self._db.tx_run(tx, _INSERT, _role_params(r))
            await _replace_permissions(self._db, tx, r.id, r.permissions)
        return await self.get_by_id(r.id)

    async def update(self, r: Role) -> None:
        """Saves name, description and permissions atomically."""
        async with self._db.transaction() as tx:
            params = {"p_id": r.id, "p_name": r.name, "p_description": r.description, "p_now": _now()}
            if await self._db.tx_run(tx, _UPDATE, params) == 0:
                raise NotFoundError
            await _replace_permissions(self._db, tx, r.id, r.permissions)

    async def delete(self, id: UUID) -> None:
        """Fails with ConflictError while users hold the role."""
        if await self._db.run(_DELETE, {"p_id": id}) == 0:
            raise NotFoundError

    async def sync_permissions(self, defs: Sequence[PermissionDef]) -> None:
        """Upserts defs and deletes permissions no longer defined."""
        if not defs:
            raise ValueError("refusing to sync an empty permission registry")
        async with self._db.transaction() as tx:
            await self._db.tx_run_many(
                tx, _UPSERT_PERM, [{"p_code": str(d.code), "p_description": d.description} for d in defs]
            )
            await self._db.tx_run(tx, _DELETE_OBSOLETE_PERMS, {"p_codes": [str(d.code) for d in defs]})

    async def seed_role(self, r: Role, *, overwrite: bool) -> UUID:
        """Creates the role if missing, or overwrites it when requested."""
        async with self._db.transaction() as tx:
            existing = await self._db.tx_fetchval(tx, _LOCK_BY_NAME, {"p_name": r.name})
            if existing is None:
                role_id = r.id
                await self._db.tx_run(tx, _INSERT, _role_params(r))
            elif not overwrite:
                return rows.uuid(existing)
            else:
                role_id = rows.uuid(existing)
                await self._db.tx_run(
                    tx,
                    _RESEED,
                    {
                        "p_id": role_id,
                        "p_description": r.description,
                        "p_audience": str(r.audience),
                        "p_is_system": r.is_system,
                        "p_now": _now(),
                    },
                )
            await _replace_permissions(self._db, tx, role_id, r.permissions)
            return role_id

    async def sync_public_user_types(self, defs: Sequence[PublicUserType]) -> None:
        """Upserts defs and removes types no longer defined. Removing a type
        still held by users fails."""
        try:
            async with self._db.transaction() as tx:
                for d in defs:
                    role_id = None
                    if d.role:
                        role_id = await self._db.tx_fetchval(tx, _PUBLIC_ROLE_ID, {"p_name": d.role})
                        if role_id is None:
                            raise NotFoundError(f"public type {d.name!r}: public role {d.role!r} not found")
                    await self._db.tx_run(
                        tx,
                        _UPSERT_TYPE,
                        {
                            "p_name": d.name,
                            "p_description": d.description,
                            "p_role_id": role_id,
                            "p_self_registration": d.self_registration,
                        },
                    )
                await self._db.tx_run(tx, _DELETE_OBSOLETE_TYPES, {"p_names": [d.name for d in defs]})
        except ConflictError as e:
            raise RuntimeError("remove obsolete public user types: they are still held by users") from e


async def _replace_permissions(db: Database, tx: AsyncConnection, role_id: UUID, perms: Sequence[Permission]) -> None:
    await db.tx_run(tx, _DELETE_PERMS, {"p_role_id": role_id})
    if perms:
        await db.tx_run_many(tx, _INSERT_PERM, [{"p_role_id": role_id, "p_code": str(p)} for p in perms])
