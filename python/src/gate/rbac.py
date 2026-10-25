"""The single source of truth for the operations the system knows about
(permissions), the roles it ships with, and the types of public user. The
``seed`` command (also run by ``serve --sync-rbac``) writes this registry
into the database.

Adding an internal operation:
  1. Declare a Permission constant and add it to PERMISSIONS.
  2. Protect the route with ``require_permissions(...)``.

Public users: authorization of the public application is a business
decision. Most public routes only need ``require_kind(PUBLIC)`` and, if they
differ per type, ``require_public_type(...)``. If a type does need
fine-grained permissions, add a public role to DEFAULT_ROLES and reference
it from the type's ``role`` field.
"""

from dataclasses import dataclass
from typing import Final

from gate.domain import Permission, PermissionDef, PublicUserType, UserKind

# Internal (staff) operations.
USERS_READ: Final = Permission("users:read")
USERS_CREATE: Final = Permission("users:create")
USERS_UPDATE: Final = Permission("users:update")
USERS_ASSIGN_ROLES: Final = Permission("users:assign_roles")
ROLES_READ: Final = Permission("roles:read")
ROLES_MANAGE: Final = Permission("roles:manage")
AUDIT_READ: Final = Permission("audit:read")

# Registry of every permission the application enforces.
PERMISSIONS: Final[tuple[PermissionDef, ...]] = (
    PermissionDef(code=USERS_READ, description="View users, their roles and public types"),
    PermissionDef(code=USERS_CREATE, description="Create users"),
    PermissionDef(code=USERS_UPDATE, description="Update user profile, status and public types"),
    PermissionDef(code=USERS_ASSIGN_ROLES, description="Assign roles to internal users"),
    PermissionDef(code=ROLES_READ, description="View roles, permissions and public types"),
    PermissionDef(code=ROLES_MANAGE, description="Create, update and delete internal roles"),
    PermissionDef(code=AUDIT_READ, description="Read the security audit log"),
)

ALL_PERMISSIONS: Final[tuple[Permission, ...]] = tuple(p.code for p in PERMISSIONS)
_KNOWN: Final = frozenset(ALL_PERMISSIONS)

# Internal roles.
ROLE_ADMIN: Final = "admin"
ROLE_MANAGER: Final = "manager"
ROLE_VIEWER: Final = "viewer"
ROLE_AUDITOR: Final = "auditor"


@dataclass(frozen=True, slots=True, kw_only=True)
class RoleTemplate:
    """A role seeded into the database.

    System roles are owned by the code: permissions are re-synced on every
    seed and the API cannot change them. Non-system templates are created
    once and can then be customised by admins.
    """

    name: str
    description: str
    audience: UserKind
    permissions: tuple[Permission, ...]
    system: bool = False


# Seeded on every ``seed``.
DEFAULT_ROLES: Final[tuple[RoleTemplate, ...]] = (
    RoleTemplate(
        name=ROLE_ADMIN,
        description="Full access to every operation",
        audience=UserKind.INTERNAL,
        system=True,
        permissions=ALL_PERMISSIONS,
    ),
    RoleTemplate(
        name=ROLE_MANAGER,
        description="Manages users and their access",
        audience=UserKind.INTERNAL,
        permissions=(USERS_READ, USERS_CREATE, USERS_UPDATE, USERS_ASSIGN_ROLES, ROLES_READ),
    ),
    RoleTemplate(
        name=ROLE_VIEWER,
        description="Read-only access to users and roles",
        audience=UserKind.INTERNAL,
        permissions=(USERS_READ, ROLES_READ),
    ),
    RoleTemplate(
        name=ROLE_AUDITOR,
        description="Reads the audit log",
        audience=UserKind.INTERNAL,
        permissions=(USERS_READ, ROLES_READ, AUDIT_READ),
    ),
    # Optional public role example, for a type that needs permissions:
    # RoleTemplate(name="vendor", audience=UserKind.PUBLIC, system=True,
    #              description="...", permissions=(PRODUCTS_MANAGE,)),
)

# Public user types. Rename or extend to fit the application; a user may
# hold several (e.g. both customer and vendor).
PUBLIC_TYPE_CUSTOMER: Final = "customer"
PUBLIC_TYPE_VENDOR: Final = "vendor"

# Used when a sign-up does not choose a type.
DEFAULT_PUBLIC_TYPE: Final = PUBLIC_TYPE_CUSTOMER

PUBLIC_USER_TYPES: Final[tuple[PublicUserType, ...]] = (
    PublicUserType(name=PUBLIC_TYPE_CUSTOMER, description="Regular user of the application", self_registration=True),
    PublicUserType(
        name=PUBLIC_TYPE_VENDOR, description="Business partner, onboarded by staff", self_registration=False
    ),
)

_PUBLIC_TYPES_BY_NAME: Final = frozendict({t.name: t for t in PUBLIC_USER_TYPES})


def is_known(p: str) -> bool:
    """Reports whether p is in the registry."""
    return p in _KNOWN


def lookup_public_type(name: str) -> PublicUserType | None:
    """Returns the public user type with the given name."""
    return _PUBLIC_TYPES_BY_NAME.get(name)
