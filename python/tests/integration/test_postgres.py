"""Repository tests against a real PostgreSQL.

Skipped unless GATE_TEST_DATABASE_URL points at an EMPTY database whose
role may create tables, e.g.:

    docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=pw postgres:17-alpine
    GATE_TEST_DATABASE_URL=postgres://postgres:pw@localhost:55432/postgres make test

The module applies ../migrations before the tests and the down migration
after them.
"""

import os
from collections.abc import AsyncGenerator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg
import pytest
import structlog

from gate import config, rbac
from gate.auth import generate_key
from gate.container import Container
from gate.domain import (
    AuditFilter,
    ConflictError,
    InvalidTokenError,
    NotFoundError,
    Permission,
    Role,
    User,
    UserDisabledError,
    UserFilter,
    UserIdentity,
    UserKind,
    UserPatch,
    UserStatus,
)
from gate.repository import CreateUserOptions
from gate.repository.postgres.identity_audit import PostgresIdentityRepository
from gate.repository.postgres.roles import PostgresRoleRepository
from gate.repository.postgres.sessions import PostgresSessionRepository
from gate.repository.postgres.users import PostgresUserRepository
from gate.service import AuditAction
from gate.service.guard import new_id

URL = os.environ.get("GATE_TEST_DATABASE_URL", "")
MIGRATIONS = Path(__file__).resolve().parents[3] / "migrations"

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not URL, reason="GATE_TEST_DATABASE_URL is not set"),
]


@pytest.fixture(scope="module")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
async def c() -> AsyncGenerator[Container]:
    conn = await asyncpg.connect(URL)
    try:
        for f in sorted(MIGRATIONS.glob("*.up.sql")):
            await conn.execute(f.read_text())
        pem, _ = generate_key()
        cfg = config.decode({"DATABASE_URL": URL, "JWT_ISSUER": "https://auth.test", "JWT_SIGNING_KEY": pem})
        async with Container.build(cfg, structlog.get_logger()).running() as container:
            await container.seeder.sync()
            yield container
    finally:
        for f in sorted(MIGRATIONS.glob("*.down.sql"), reverse=True):
            await conn.execute(f.read_text())
        await conn.close()


def new_user(kind: UserKind = UserKind.PUBLIC, email: str | None = None) -> User:
    now = datetime.now(UTC)
    return User(
        id=new_id(),
        email=email or f"{new_id().hex[:12]}@example.com",
        phone=None,
        full_name="Test",
        password_hash="",
        kind=kind,
        status=UserStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )


async def test_seed_is_idempotent(c: Container) -> None:
    await c.seeder.sync()
    roles = {r.name: r for r in await PostgresRoleRepository(c.db).list()}
    assert set(roles) >= {r.name for r in rbac.DEFAULT_ROLES}
    assert set(roles[rbac.ROLE_ADMIN].permissions) == set(rbac.ALL_PERMISSIONS)


async def test_failed_transaction_rolls_back(c: Container) -> None:
    """The engine runs single statements in autocommit mode; transactions
    must still be atomic. The user row is inserted first, then the public
    type insert fails: nothing may remain."""
    users = PostgresUserRepository(c.db)
    u = new_user()
    with pytest.raises(ConflictError):
        await users.create(u, CreateUserOptions(public_types=("no-such-type",)))
    with pytest.raises(NotFoundError):
        await users.get_by_id(u.id)
    # The connection went back to the pool in autocommit mode: a following
    # single statement is committed immediately.
    ok = await users.create(new_user(), CreateUserOptions(public_types=("customer",)))
    await users.update(ok.id, UserPatch(full_name="Committed"))
    assert (await users.get_by_id(ok.id)).full_name == "Committed"


async def test_user_crud_and_conflicts(c: Container) -> None:
    users = PostgresUserRepository(c.db)
    u = await users.create(new_user(), CreateUserOptions(public_types=("vendor", "customer")))
    assert u.public_types == ("customer", "vendor")  # sorted by the query
    assert (await users.get_by_email(u.email or "")).id == u.id
    with pytest.raises(ConflictError):
        await users.create(replace(new_user(), email=u.email), CreateUserOptions(public_types=("customer",)))
    with pytest.raises(ConflictError):  # unknown public type violates the foreign key
        await users.create(new_user(), CreateUserOptions(public_types=("nope",)))
    updated = await users.update(u.id, UserPatch(full_name="Renamed"))
    assert updated.full_name == "Renamed" and updated.status == UserStatus.ACTIVE
    with pytest.raises(NotFoundError):
        await users.update(new_id(), UserPatch(full_name="x"))
    listed = await users.list(UserFilter(kind=UserKind.PUBLIC, public_type="vendor", limit=200))
    assert u.id in {x.id for x in listed}
    assert u.id not in {x.id for x in await users.list(UserFilter(kind=UserKind.INTERNAL, limit=200))}
    assert len(await users.list(UserFilter(limit=1))) == 1
    assert await users.count() >= 1


async def test_roles_and_principal(c: Container) -> None:
    users, roles = PostgresUserRepository(c.db), PostgresRoleRepository(c.db)
    viewer = await roles.get_by_name(rbac.ROLE_VIEWER)
    auditor = await roles.get_by_name(rbac.ROLE_AUDITOR)
    assert {r.id for r in await roles.get_by_ids([viewer.id, auditor.id, new_id()])} == {viewer.id, auditor.id}

    staff = await users.create(new_user(UserKind.INTERNAL), CreateUserOptions(role_ids=(viewer.id,)))
    await users.set_roles(staff.id, [viewer.id, auditor.id])
    assert {r.name for r in await users.effective_roles(staff.id)} == {rbac.ROLE_VIEWER, rbac.ROLE_AUDITOR}

    pair = await c.auth.start_session(staff, "password")
    p = await c.auth.authenticate(pair.access_token)
    assert p.kind == UserKind.INTERNAL and p.can(rbac.AUDIT_READ) and not p.can(rbac.USERS_CREATE)

    with pytest.raises(ConflictError):  # still assigned
        await roles.delete(auditor.id)
    await users.update(staff.id, UserPatch(status=UserStatus.DISABLED))
    with pytest.raises(UserDisabledError):
        await users.get_principal(staff.id, pair.session_id)


async def test_role_create_update_delete(c: Container) -> None:
    roles = PostgresRoleRepository(c.db)
    now = datetime.now(UTC)
    r = await roles.create(
        Role(
            id=new_id(),
            name=f"r{new_id().hex[:8]}",
            description="",
            audience=UserKind.INTERNAL,
            is_system=False,
            permissions=(rbac.USERS_READ, rbac.ROLES_READ),
            created_at=now,
            updated_at=now,
        )
    )
    assert r.permissions == (rbac.ROLES_READ, rbac.USERS_READ)  # sorted by the query
    await roles.update(replace(r, permissions=(Permission(rbac.USERS_READ),)))
    assert (await roles.get_by_id(r.id)).permissions == (rbac.USERS_READ,)
    with pytest.raises(ConflictError):
        await roles.create(replace(r, id=new_id()))  # duplicate name
    await roles.delete(r.id)
    with pytest.raises(NotFoundError):
        await roles.get_by_id(r.id)


async def test_refresh_rotation_reuse_and_purge(c: Container) -> None:
    users, sessions = PostgresUserRepository(c.db), PostgresSessionRepository(c.db)
    u = await users.create(new_user(), CreateUserOptions(public_types=("customer",)))
    first = await c.auth.start_session(u, "password")
    second = await c.auth.refresh(first.refresh_token)
    assert second.session_id == first.session_id
    with pytest.raises(InvalidTokenError):  # reuse revokes the session
        await c.auth.refresh(first.refresh_token)
    with pytest.raises(InvalidTokenError):
        await c.auth.refresh(second.refresh_token)
    assert await sessions.purge(datetime.now(UTC) + timedelta(seconds=1)) >= 1


async def test_sso_identity_lookup(c: Container) -> None:
    users, identities = PostgresUserRepository(c.db), PostgresIdentityRepository(c.db)
    u = new_user()
    link = UserIdentity(
        id=new_id(),
        user_id=u.id,
        provider="google",
        subject=f"sub-{u.id}",
        email=u.email or "",
        created_at=u.created_at,
    )
    await users.create(u, CreateUserOptions(public_types=("customer",), identity=link))
    assert (await identities.find_user("google", link.subject)).id == u.id
    with pytest.raises(NotFoundError):
        await identities.find_user("google", "unknown")
    with pytest.raises(ConflictError):
        await identities.link(link)


async def test_audit_log(c: Container) -> None:
    actor = new_id()
    await c.auditor.record(AuditAction.LOGOUT, actor=actor, details={"reason": "test", "n": 2})
    await c.auditor.close()  # flush the background write
    events = await c.auditor.list(AuditFilter(actor_user_id=actor))
    assert [e.action for e in events] == ["auth.logout"]
    assert dict(events[0].details) == {"reason": "test", "n": 2}  # jsonb round trip
    assert len(await c.auditor.list(AuditFilter(action="auth.logout", limit=1))) == 1
