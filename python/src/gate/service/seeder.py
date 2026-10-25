from datetime import UTC, datetime
from typing import Final

from gate import rbac
from gate.domain import NotFoundError, Role, User, UserKind
from gate.logs import Logger
from gate.repository import CreateUserOptions, RoleRepository, UserRepository
from gate.service.audit import AuditAction, Auditor
from gate.service.auth import AuthService, create_user
from gate.service.guard import new_id


class Seeder:
    """Writes the code-defined registry (permissions, default roles, public
    user types) into the database and bootstraps the first admin. All
    operations are idempotent and safe to run concurrently."""

    __slots__ = ("_audit", "_auth", "_log", "_roles", "_users")

    def __init__(
        self, *, users: UserRepository, roles: RoleRepository, auth: AuthService, audit: Auditor, log: Logger
    ) -> None:
        self._users: Final = users
        self._roles: Final = roles
        self._auth: Final = auth
        self._audit: Final = audit
        self._log: Final = log

    async def sync(self) -> None:
        """Makes the database match module rbac."""
        await self._roles.sync_permissions(rbac.PERMISSIONS)
        now = datetime.now(UTC)
        for t in rbac.DEFAULT_ROLES:
            role = Role(
                id=new_id(),
                name=t.name,
                description=t.description,
                audience=t.audience,
                is_system=t.system,
                permissions=t.permissions,
                created_at=now,
                updated_at=now,
            )
            await self._roles.seed_role(role, overwrite=t.system)
        await self._roles.sync_public_user_types(rbac.PUBLIC_USER_TYPES)
        self._log.info(
            "rbac registry synced",
            permissions=len(rbac.PERMISSIONS),
            roles=len(rbac.DEFAULT_ROLES),
            public_types=len(rbac.PUBLIC_USER_TYPES),
        )

    async def create_admin(self, email: str, phone: str, full_name: str, password: str) -> User:
        """Creates an internal user holding the admin role, for the first
        account and break-glass recovery."""
        try:
            admin = await self._roles.get_by_name(rbac.ROLE_ADMIN)
        except NotFoundError:
            raise RuntimeError("admin role not found (run `seed` first)") from None
        u = await self._auth.new_user(email, phone, full_name, password, UserKind.INTERNAL)
        u = await create_user(self._users, u, CreateUserOptions(role_ids=(admin.id,)))
        await self._audit.record(AuditAction.ADMIN_BOOTSTRAPPED, target_type="user", target_id=str(u.id))
        return u
