"""The internal (staff) API under /v1/admin. Every route is restricted to
internal users and gated by a permission."""

from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from starlette.responses import JSONResponse, Response

from gate import rbac
from gate.domain import AuditFilter, Permission, Principal, UserFilter, UserKind, UserPatch, UserStatus, ValidationError
from gate.service import Auditor, CreateUserInput, RoleInput, RoleService, UserService
from gate.web.deps import Authenticate, require_kind, require_permissions
from gate.web.dto import (
    AuditEventResponse,
    CreateUserRequest,
    ListResponse,
    RoleRequest,
    RoleResponse,
    SetPublicTypesRequest,
    SetRolesRequest,
    UpdateUserRequest,
    UserResponse,
)


@dataclass(frozen=True, slots=True)
class Page:
    limit: int
    offset: int


async def page(limit: Annotated[str, Query()] = "50", offset: Annotated[str, Query()] = "0") -> Page:
    """limit 1-200 (default 50) and offset 0-100000. Deep offsets are capped;
    see docs/security.md on pagination."""
    try:
        p = Page(int(limit), int(offset))
    except ValueError:
        p = Page(0, -1)
    if not (1 <= p.limit <= 200 and 0 <= p.offset <= 100_000):
        raise ValidationError("limit must be 1-200 and offset 0-100000")
    return p


def admin_routes(*, authn: Authenticate, users: UserService, roles: RoleService, audit: Auditor) -> APIRouter:
    router = APIRouter(
        prefix="/v1/admin", dependencies=[Depends(authn), Depends(require_kind(authn, UserKind.INTERNAL))]
    )
    Actor = Annotated[Principal, Depends(authn)]
    Paging = Annotated[Page, Depends(page)]

    def needs(*perms: Permission) -> list[Any]:
        return [Depends(require_permissions(authn, *perms))]

    # --- registry ---------------------------------------------------------------

    permissions_body = {"items": [{"code": p.code, "description": p.description} for p in rbac.PERMISSIONS]}
    public_types_body = {
        "items": [
            {"name": t.name, "description": t.description, "self_registration": t.self_registration}
            | ({"role": t.role} if t.role else {})
            for t in rbac.PUBLIC_USER_TYPES
        ]
    }

    @router.get("/permissions", dependencies=needs(rbac.ROLES_READ))
    async def list_permissions() -> JSONResponse:
        return JSONResponse(permissions_body)

    @router.get("/public-types", dependencies=needs(rbac.ROLES_READ))
    async def list_public_types() -> JSONResponse:
        return JSONResponse(public_types_body)

    # --- users ------------------------------------------------------------------

    @router.get("/users", dependencies=needs(rbac.USERS_READ), response_model_exclude_none=True)
    async def list_users(pg: Paging, kind: str = "", public_type: str = "") -> ListResponse[UserResponse]:
        if kind and kind not in UserKind:
            raise ValidationError('kind must be "internal" or "public"')
        f = UserFilter(
            kind=UserKind(kind) if kind else None,
            public_type=public_type or None,
            limit=pg.limit,
            offset=pg.offset,
        )
        items = tuple(UserResponse.of(u) for u in await users.list(f))
        return ListResponse[UserResponse](items=items, limit=pg.limit, offset=pg.offset or None)

    @router.post("/users", status_code=201, dependencies=needs(rbac.USERS_CREATE), response_model_exclude_none=True)
    async def create_user(req: CreateUserRequest, actor: Actor) -> UserResponse:
        d = await users.create(
            actor,
            CreateUserInput(
                email=req.email,
                phone=req.phone,
                full_name=req.full_name,
                password=req.password,
                kind=UserKind(req.kind) if req.kind else UserKind.INTERNAL,
                role_ids=req.role_ids,
                public_types=req.public_types,
            ),
        )
        return UserResponse.details(d)

    @router.get("/users/{id}", dependencies=needs(rbac.USERS_READ), response_model_exclude_none=True)
    async def get_user(id: UUID) -> UserResponse:
        return UserResponse.details(await users.get(id))

    @router.patch("/users/{id}", dependencies=needs(rbac.USERS_UPDATE), response_model_exclude_none=True)
    async def update_user(id: UUID, req: UpdateUserRequest, actor: Actor) -> UserResponse:
        patch = UserPatch(full_name=req.full_name, status=UserStatus(req.status) if req.status else None)
        return UserResponse.details(await users.update(actor, id, patch))

    @router.put("/users/{id}/roles", dependencies=needs(rbac.USERS_ASSIGN_ROLES), response_model_exclude_none=True)
    async def set_user_roles(id: UUID, req: SetRolesRequest, actor: Actor) -> UserResponse:
        return UserResponse.details(await users.set_roles(actor, id, req.role_ids))

    @router.put("/users/{id}/public-types", dependencies=needs(rbac.USERS_UPDATE), response_model_exclude_none=True)
    async def set_user_public_types(id: UUID, req: SetPublicTypesRequest, actor: Actor) -> UserResponse:
        return UserResponse.details(await users.set_public_types(actor, id, req.public_types))

    # --- roles ------------------------------------------------------------------

    @router.get("/roles", dependencies=needs(rbac.ROLES_READ), response_model_exclude_none=True)
    async def list_roles() -> ListResponse[RoleResponse]:
        return ListResponse[RoleResponse](items=tuple(RoleResponse.of(r) for r in await roles.list()))

    @router.post("/roles", status_code=201, dependencies=needs(rbac.ROLES_MANAGE))
    async def create_role(req: RoleRequest, actor: Actor) -> RoleResponse:
        if req.name is None:
            raise ValidationError("name is required")
        return RoleResponse.of(await roles.create(actor, _role_input(req)))

    @router.get("/roles/{id}", dependencies=needs(rbac.ROLES_READ))
    async def get_role(id: UUID) -> RoleResponse:
        return RoleResponse.of(await roles.get(id))

    @router.patch("/roles/{id}", dependencies=needs(rbac.ROLES_MANAGE))
    async def update_role(id: UUID, req: RoleRequest, actor: Actor) -> RoleResponse:
        return RoleResponse.of(await roles.update(actor, id, _role_input(req)))

    @router.delete("/roles/{id}", status_code=204, dependencies=needs(rbac.ROLES_MANAGE))
    async def delete_role(id: UUID, actor: Actor) -> Response:
        await roles.delete(actor, id)
        return Response(status_code=204)

    # --- audit ------------------------------------------------------------------

    @router.get("/audit-events", dependencies=needs(rbac.AUDIT_READ), response_model_exclude_none=True)
    async def list_audit(pg: Paging, action: str = "", actor_user_id: str = "") -> ListResponse[AuditEventResponse]:
        try:
            actor_id = UUID(actor_user_id) if actor_user_id else None
        except ValueError:
            raise ValidationError("actor_user_id must be a UUID") from None
        events = await audit.list(AuditFilter(actor_user_id=actor_id, action=action, limit=pg.limit, offset=pg.offset))
        items = tuple(AuditEventResponse.of(e) for e in events)
        return ListResponse[AuditEventResponse](items=items, limit=pg.limit, offset=pg.offset or None)

    return router


def _role_input(req: RoleRequest) -> RoleInput:
    return RoleInput(name=req.name, description=req.description, permissions=req.permissions)
