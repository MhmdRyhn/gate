"""Sign-in, registration, token refresh, logout, JWKS and the signed-in
user's own endpoints (/v1/me)."""

from typing import Annotated

from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse, Response

from gate import rbac
from gate.auth import KeySet
from gate.domain import Principal
from gate.service import AuthService, RegisterInput, UserService
from gate.web.deps import Authenticate, Check
from gate.web.dto import ChangePasswordRequest, LoginRequest, MeResponse, RefreshRequest, RegisterRequest, TokenResponse


def jwks_route(keys: KeySet) -> APIRouter:
    router = APIRouter()
    body = keys.jwks()  # immutable for the life of the process

    @router.get("/.well-known/jwks.json")
    async def jwks() -> JSONResponse:
        """Public keys for token verification."""
        return JSONResponse(body, headers={"Cache-Control": "public, max-age=300"})

    return router


def auth_routes(
    *,
    auth: AuthService,
    limiter: Check,
    registration_enabled: bool,
) -> APIRouter:
    """Unauthenticated endpoints under /v1/auth."""
    router = APIRouter(prefix="/v1/auth")
    limited = [Depends(limiter)]

    @router.post("/login", dependencies=limited)
    async def login(req: LoginRequest) -> TokenResponse:
        """Email or phone + password."""
        return TokenResponse.of(await auth.login(req.identifier, req.password))

    @router.post("/refresh", dependencies=limited)
    async def refresh(req: RefreshRequest) -> TokenResponse:
        """Rotates the refresh token."""
        return TokenResponse.of(await auth.refresh(req.refresh_token))

    @router.post("/logout", status_code=204)
    async def logout(req: RefreshRequest) -> Response:
        """Revokes the refresh token's session."""
        await auth.logout(req.refresh_token)
        return Response(status_code=204)

    if registration_enabled:

        @router.post("/register", status_code=201, dependencies=limited)
        async def register(req: RegisterRequest) -> TokenResponse:
            """Public self-registration."""
            pair = await auth.register(
                RegisterInput(
                    email=req.email, phone=req.phone, full_name=req.full_name, password=req.password, type=req.type
                )
            )
            return TokenResponse.of(pair)

        types_body = {
            "items": [
                {"name": t.name, "description": t.description} for t in rbac.PUBLIC_USER_TYPES if t.self_registration
            ],
            "default": rbac.DEFAULT_PUBLIC_TYPE,
        }

        @router.get("/register/types")
        async def registration_types() -> JSONResponse:
            """Types open for sign-up."""
            return JSONResponse(types_body)

    return router


def me_routes(*, authn: Authenticate, auth: AuthService, users: UserService) -> APIRouter:
    """Any signed-in user."""
    router = APIRouter(prefix="/v1/me", dependencies=[Depends(authn)])
    CurrentPrincipal = Annotated[Principal, Depends(authn)]

    @router.get("", response_model_exclude_none=True)
    async def me(p: CurrentPrincipal) -> MeResponse:
        """The signed-in user, roles and effective permissions."""
        return MeResponse.build(await users.get(p.user_id), p)

    @router.post("/password", status_code=204)
    async def change_password(req: ChangePasswordRequest, p: CurrentPrincipal) -> Response:
        """Other sessions are signed out."""
        await auth.change_password(p, req.current_password, req.new_password)
        return Response(status_code=204)

    @router.post("/logout-all", status_code=204)
    async def logout_all(p: CurrentPrincipal) -> Response:
        """Revokes every session of the user."""
        await auth.logout_all(p)
        return Response(status_code=204)

    return router
