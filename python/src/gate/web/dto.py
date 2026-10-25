"""Request and response bodies. DTOs decouple the public API contract from
domain and storage models: internal fields (password hashes, token hashes)
cannot leak because they have no DTO field. Size limits bound the work an
attacker can cause per request; unknown fields are rejected. Every model is
frozen."""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from gate.domain import AuditEvent, Principal, Role, User
from gate.service import TokenPair, UserDetails


def _limit(max_length: int, *, required: bool = False) -> object:
    return StringConstraints(min_length=1 if required else 0, max_length=max_length)


class Request(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Response(BaseModel):
    model_config = ConfigDict(frozen=True)


class LoginRequest(Request):
    identifier: Annotated[str, _limit(320, required=True)]  # email or phone
    password: Annotated[str, _limit(512, required=True)]


class RegisterRequest(Request):
    email: Annotated[str, _limit(254)] = ""
    phone: Annotated[str, _limit(32)] = ""
    full_name: Annotated[str, _limit(200)] = ""
    password: Annotated[str, _limit(512, required=True)]
    type: Annotated[str, _limit(50)] = ""


class RefreshRequest(Request):
    refresh_token: Annotated[str, _limit(256, required=True)]


class ChangePasswordRequest(Request):
    current_password: Annotated[str, _limit(512, required=True)]
    new_password: Annotated[str, _limit(512, required=True)]


type PublicTypeName = Annotated[str, _limit(50, required=True)]


class CreateUserRequest(Request):
    email: Annotated[str, _limit(254)] = ""
    phone: Annotated[str, _limit(32)] = ""
    full_name: Annotated[str, _limit(200)] = ""
    password: Annotated[str, _limit(512, required=True)]
    kind: Literal["", "internal", "public"] = ""
    role_ids: Annotated[tuple[UUID, ...], Field(max_length=50)] = ()
    public_types: Annotated[tuple[PublicTypeName, ...], Field(max_length=10)] = ()


class UpdateUserRequest(Request):
    full_name: Annotated[str, _limit(200)] | None = None
    status: Literal["active", "disabled"] | None = None


class SetRolesRequest(Request):
    role_ids: Annotated[tuple[UUID, ...], Field(max_length=50)]


class SetPublicTypesRequest(Request):
    public_types: Annotated[tuple[PublicTypeName, ...], Field(min_length=1, max_length=10)]


class RoleRequest(Request):
    name: Annotated[str, _limit(50)] | None = None
    description: Annotated[str, _limit(500)] | None = None
    permissions: Annotated[tuple[Annotated[str, _limit(100)], ...], Field(max_length=200)] | None = None


class TokenResponse(Response):
    """The OAuth 2.0 token response shape (RFC 6749 §5.1)."""

    token_type: str = "Bearer"
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int

    @classmethod
    def of(cls, p: TokenPair) -> TokenResponse:
        now = datetime.now(UTC)
        return cls(
            access_token=p.access_token,
            expires_in=int((p.access_token_expires_at - now).total_seconds()),
            refresh_token=p.refresh_token,
            refresh_expires_in=int((p.refresh_token_expires_at - now).total_seconds()),
        )


class RoleResponse(Response):
    id: UUID
    name: str
    description: str
    audience: str
    is_system: bool
    permissions: tuple[str, ...]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def of(cls, r: Role) -> RoleResponse:
        return cls(
            id=r.id,
            name=r.name,
            description=r.description,
            audience=r.audience,
            is_system=r.is_system,
            permissions=r.permissions,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )


class UserResponse(Response):
    id: UUID
    email: str | None = None
    phone: str | None = None
    full_name: str
    kind: str
    status: str
    public_types: tuple[str, ...] | None = None
    has_password: bool
    email_verified_at: datetime | None = None
    phone_verified_at: datetime | None = None
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    roles: tuple[RoleResponse, ...] | None = None

    @staticmethod
    def fields(u: User, roles: tuple[Role, ...] | None) -> dict[str, object]:
        return {
            "id": u.id,
            "email": u.email,
            "phone": u.phone,
            "full_name": u.full_name,
            "kind": u.kind,
            "status": u.status,
            "public_types": u.public_types or None,
            "has_password": u.has_password,
            "email_verified_at": u.email_verified_at,
            "phone_verified_at": u.phone_verified_at,
            "last_login_at": u.last_login_at,
            "created_at": u.created_at,
            "updated_at": u.updated_at,
            "roles": None if roles is None else tuple(RoleResponse.of(r) for r in roles),
        }

    @classmethod
    def of(cls, u: User) -> UserResponse:
        return cls.model_validate(cls.fields(u, None))

    @classmethod
    def details(cls, d: UserDetails) -> UserResponse:
        return cls.model_validate(cls.fields(d.user, d.roles))


class MeResponse(UserResponse):
    session_id: UUID
    permissions: tuple[str, ...]

    @classmethod
    def build(cls, d: UserDetails, p: Principal) -> MeResponse:
        return cls.model_validate(
            cls.fields(d.user, d.roles) | {"session_id": p.session_id, "permissions": tuple(sorted(p.permissions))}
        )


class AuditEventResponse(Response):
    id: UUID
    occurred_at: datetime
    actor_user_id: UUID | None = None
    action: str
    target_type: str | None = None
    target_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    details: dict[str, object] | None = None

    @classmethod
    def of(cls, e: AuditEvent) -> AuditEventResponse:
        return cls(
            id=e.id,
            occurred_at=e.occurred_at,
            actor_user_id=e.actor_user_id,
            action=e.action,
            target_type=e.target_type or None,
            target_id=e.target_id or None,
            ip=e.ip or None,
            user_agent=e.user_agent or None,
            request_id=e.request_id or None,
            details=dict(e.details) or None,
        )


class ListResponse[T](Response):
    items: tuple[T, ...]
    limit: int | None = None
    offset: int | None = None
