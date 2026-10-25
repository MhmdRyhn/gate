"""Use cases (sign-in, registration, SSO, user and role management) on top
of the repository protocols. Authorization decisions that depend on data
live here; the HTTP layer only checks route-level access."""

from gate.service.audit import AuditAction, Auditor
from gate.service.auth import AuthService, RegisterInput, TokenPair
from gate.service.roles import RoleInput, RoleService
from gate.service.seeder import Seeder
from gate.service.sso import SSOService
from gate.service.users import CreateUserInput, UserDetails, UserService

__all__ = [
    "AuditAction",
    "Auditor",
    "AuthService",
    "CreateUserInput",
    "RegisterInput",
    "RoleInput",
    "RoleService",
    "SSOService",
    "Seeder",
    "TokenPair",
    "UserDetails",
    "UserService",
]
