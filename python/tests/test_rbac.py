import dataclasses
import re

import pytest

from gate import rbac
from gate.domain import UserKind

# Must match the CHECK constraint on permissions.code in the schema.
CODE_FORMAT = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")


def test_permission_registry() -> None:
    codes = [p.code for p in rbac.PERMISSIONS]
    assert len(codes) == len(set(codes)), "duplicate permission"
    for code in codes:
        assert CODE_FORMAT.match(code), f"{code} does not match <resource>:<action>"


def test_default_roles() -> None:
    names = [r.name for r in rbac.DEFAULT_ROLES]
    assert len(names) == len(set(names)), "duplicate role"
    for r in rbac.DEFAULT_ROLES:
        if r.audience == UserKind.PUBLIC:
            assert r.system, f"public role {r.name} must be a system role"
        for p in r.permissions:
            assert rbac.is_known(p), f"role {r.name} references unknown permission {p}"


def test_public_user_types() -> None:
    roles = {r.name: r for r in rbac.DEFAULT_ROLES}
    names = [t.name for t in rbac.PUBLIC_USER_TYPES]
    assert len(names) == len(set(names)), "duplicate public type"
    for t in rbac.PUBLIC_USER_TYPES:
        if t.role:
            assert t.role in roles and roles[t.role].audience == UserKind.PUBLIC
    default = rbac.lookup_public_type(rbac.DEFAULT_PUBLIC_TYPE)
    assert default is not None and default.self_registration


def test_registry_is_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        rbac.DEFAULT_ROLES[0].name = "root"  # type: ignore[misc]
    with pytest.raises(TypeError):
        rbac._PUBLIC_TYPES_BY_NAME["x"] = rbac.PUBLIC_USER_TYPES[0]  # type: ignore[index]
