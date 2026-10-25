"""The composition root: builds every component once, explicitly, from the
configuration. (The Go service used Google Wire; in Python plain
constructor calls are just as clear.)"""

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from gate.auth import DEFAULT_ARGON2_PARAMS, KeySet, PasswordHasher, TokenIssuer, load_key_set
from gate.auth.sso import Registry
from gate.config import Config
from gate.logs import Logger
from gate.repository.postgres.db import Database
from gate.repository.postgres.identity_audit import PostgresAuditRepository, PostgresIdentityRepository
from gate.repository.postgres.roles import PostgresRoleRepository
from gate.repository.postgres.sessions import PostgresSessionRepository
from gate.repository.postgres.users import PostgresUserRepository
from gate.service import Auditor, AuthService, RoleService, Seeder, SSOService, UserService


def sso_registry(cfg: Config) -> Registry:
    """The enabled SSO providers. None are integrated yet; register them
    here, e.g.:

        google = OIDCProvider(...)  # implements gate.auth.sso.Provider
        return Registry.of(Registration(
            google,
            Policy(kind=UserKind.PUBLIC, allow_signup=True,
                   signup_public_type=rbac.PUBLIC_TYPE_CUSTOMER, link_verified_email=True),
        ))

    See docs/sso.md in the repository root.
    """
    return Registry.of()


@dataclass(frozen=True, slots=True, kw_only=True)
class Container:
    config: Config
    log: Logger
    db: Database
    keys: KeySet
    hasher: PasswordHasher
    sso_registry: Registry
    auditor: Auditor
    auth: AuthService
    users: UserService
    roles: RoleService
    sso: SSOService
    seeder: Seeder

    @classmethod
    def build(cls, cfg: Config, log: Logger) -> Container:
        """Assembles the application. Nothing here does I/O: the database
        pool is opened by ``start()``."""
        db = Database(cfg.database, log)
        user_repo = PostgresUserRepository(db)
        role_repo = PostgresRoleRepository(db)
        session_repo = PostgresSessionRepository(db)
        identity_repo = PostgresIdentityRepository(db)
        audit_repo = PostgresAuditRepository(db)

        keys = load_key_set(cfg.jwt.signing_key.reveal(), cfg.jwt.verification_keys.reveal())
        tokens = TokenIssuer(keys=keys, issuer=cfg.jwt.issuer, audience=cfg.jwt.audience, ttl=cfg.auth.access_token_ttl)
        hasher = PasswordHasher(DEFAULT_ARGON2_PARAMS, threads=cfg.auth.password_hash_threads)
        registry = sso_registry(cfg)

        auditor = Auditor(audit_repo, log)
        auth = AuthService(
            users=user_repo,
            sessions=session_repo,
            hasher=hasher,
            tokens=tokens,
            audit=auditor,
            cfg=cfg.auth,
            log=log,
        )
        return cls(
            config=cfg,
            log=log,
            db=db,
            keys=keys,
            hasher=hasher,
            sso_registry=registry,
            auditor=auditor,
            auth=auth,
            users=UserService(users=user_repo, roles=role_repo, auth=auth, audit=auditor),
            roles=RoleService(roles=role_repo, audit=auditor),
            sso=SSOService(registry=registry, users=user_repo, identities=identity_repo, auth=auth, audit=auditor),
            seeder=Seeder(users=user_repo, roles=role_repo, auth=auth, audit=auditor, log=log),
        )

    async def start(self) -> None:
        await self.db.connect()

    async def stop(self) -> None:
        """Flushes audit writes, then releases the pool and hash threads."""
        await self.auditor.close()
        await self.db.close()
        self.hasher.close()

    @asynccontextmanager
    async def running(self) -> AsyncGenerator[Container]:
        await self.start()
        try:
            yield self
        finally:
            await self.stop()


def cpu_count() -> int:
    return os.process_cpu_count() or 1
