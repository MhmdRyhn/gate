import uuid

import pytest

from gate import rbac
from gate.domain import ForbiddenError, Permission, Principal, UserKind, ValidationError
from gate.service.guard import clean_permissions, contact_input, ensure_holds, normalize_email, normalize_phone


def test_ensure_holds() -> None:
    manager = Principal(
        user_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        kind=UserKind.INTERNAL,
        permissions=frozenset({rbac.USERS_READ, rbac.USERS_ASSIGN_ROLES}),
    )
    ensure_holds(manager, [rbac.USERS_READ])
    with pytest.raises(ForbiddenError):
        ensure_holds(manager, [rbac.USERS_READ, rbac.ROLES_MANAGE])


def test_clean_permissions() -> None:
    assert clean_permissions([rbac.USERS_READ, rbac.ROLES_READ, rbac.USERS_READ]) == (rbac.ROLES_READ, rbac.USERS_READ)
    with pytest.raises(ValidationError):
        clean_permissions([Permission("made:up")])


def test_normalize_email() -> None:
    assert normalize_email("  Alice@Example.COM ") == "alice@example.com"
    for bad in ["", "nope", "Alice <alice@example.com>"]:
        with pytest.raises(ValidationError):
            normalize_email(bad)


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("+8801712345678", "+8801712345678"),
        ("+880 1712-345678", "+8801712345678"),
        ("00880 1712 345678", "+8801712345678"),
        ("+1 (415) 555-0100", "+14155550100"),
    ],
)
def test_normalize_phone(raw: str, want: str) -> None:
    assert normalize_phone(raw) == want


@pytest.mark.parametrize("bad", ["", "01712345678", "+0123456789", "+12", "+1234567890123456", "+88017abc"])
def test_normalize_phone_rejects(bad: str) -> None:
    with pytest.raises(ValidationError):
        normalize_phone(bad)


def test_contact_input() -> None:
    with pytest.raises(ValidationError):
        contact_input("", " ")
    assert contact_input("A@B.io", "+8801712345678") == ("a@b.io", "+8801712345678")
