"""The browser side of the OAuth 2.0 / OIDC authorization code flow with
state, nonce and PKCE:

    GET /v1/auth/sso/{provider}/start     -> 302 to the provider
    GET /v1/auth/sso/{provider}/callback  -> verifies, signs in, returns tokens

No routes are registered when no provider is configured.
"""

import asyncio
import hmac
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Final, Protocol

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse, Response

from gate.auth.sso import (
    FLOW_TTL,
    Identity,
    InvalidStateError,
    Registry,
    StateCodec,
    UnknownProviderError,
    new_flow_state,
)
from gate.domain import DomainError
from gate.logs import Logger
from gate.service import TokenPair
from gate.web.deps import Check
from gate.web.dto import TokenResponse
from gate.web.problem import from_domain_error, problem

SSO_COOKIE: Final = "__Host-sso_state"
_EXCHANGE_TIMEOUT: Final = 15.0


class SSOSignIn(Protocol):
    """Completes a sign-in from a verified identity (SSOService)."""

    async def sign_in(self, provider_name: str, identity: Identity) -> TokenPair: ...


def _now() -> datetime:
    return datetime.now(UTC)


def sso_routes(
    *,
    registry: Registry,
    state_key: bytes,
    sign_in: SSOSignIn,
    limiter: Check,
    log: Logger,
    now: Callable[[], datetime] = _now,
) -> APIRouter | None:
    """None when no provider is registered. Otherwise SSO_STATE_KEY is
    required (ValueError if shorter than 32 bytes)."""
    if registry.empty:
        return None
    codec = StateCodec(state_key)
    router = APIRouter(prefix="/v1/auth/sso", dependencies=[Depends(limiter)])

    @router.get("/{provider}/start")
    async def start(provider: str) -> Response:
        try:
            reg = registry.get(provider)
        except UnknownProviderError:
            return problem(404, "not_found", "unknown SSO provider")
        flow = new_flow_state(reg.provider.name, now())
        resp = RedirectResponse(reg.provider.auth_code_url(flow.state, flow.nonce, flow.code_challenge()), 302)
        # __Host- prefix: Secure, Path=/, no Domain, so subdomains cannot set
        # it. SameSite=Lax lets it survive the top-level redirect back.
        resp.set_cookie(
            SSO_COOKIE,
            codec.seal(flow),
            max_age=int(FLOW_TTL.total_seconds()),
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return resp

    @router.get("/{provider}/callback")
    async def callback(provider: str, request: Request) -> Response:
        resp = await _callback(provider, request)
        # The state cookie is single-use: clear it whatever the outcome.
        resp.delete_cookie(SSO_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        return resp

    async def _callback(provider_name: str, request: Request) -> Response:
        try:
            reg = registry.get(provider_name)
        except UnknownProviderError:
            return problem(404, "not_found", "unknown SSO provider")
        q = request.query_params
        if q.get("error"):
            return problem(401, "sso_denied", "the identity provider denied the sign-in")
        raw = request.cookies.get(SSO_COOKIE)
        if not raw:
            return problem(400, "invalid_state", "missing SSO state; restart the sign-in")
        try:
            flow = codec.open(raw, now())
        except InvalidStateError:
            return problem(400, "invalid_state", "invalid SSO state; restart the sign-in")
        if flow.provider != provider_name or not hmac.compare_digest(flow.state, q.get("state", "")):
            return problem(400, "invalid_state", "invalid SSO state; restart the sign-in")
        code = q.get("code", "")
        if not code or len(code) > 2048:
            return problem(400, "invalid_request", "missing authorization code")
        try:
            async with asyncio.timeout(_EXCHANGE_TIMEOUT):
                identity = await reg.provider.exchange(code, flow.code_verifier, flow.nonce)
        except Exception as e:
            log.warning("SSO code exchange failed", provider=provider_name, error=repr(e))
            return problem(401, "sso_failed", "could not verify the identity provider response")
        identity = Identity(
            provider=provider_name,
            subject=identity.subject,
            email=identity.email,
            email_verified=identity.email_verified,
            name=identity.name,
        )
        try:
            pair = await sign_in.sign_in(provider_name, identity)
        except DomainError as e:
            return from_domain_error(e)
        return Response(TokenResponse.of(pair).model_dump_json(), media_type="application/json")

    return router
