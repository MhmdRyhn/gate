"""The ASGI application. ``create_app`` is the authorization map of the API:
each router and route declares who may call it."""

import asyncio
import concurrent.futures
import contextlib
import json
import os
import random
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Final

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, Response

from gate import config, logs
from gate.container import Container
from gate.domain import DomainError, UserKind
from gate.web.deps import make_authenticate, rate_limit, require_kind
from gate.web.middleware import GateMiddleware
from gate.web.problem import ProblemError, describe_validation, from_domain_error, from_problem_error, problem
from gate.web.ratelimit import IPRateLimiter
from gate.web.routes_admin import admin_routes
from gate.web.routes_auth import auth_routes, jwks_route, me_routes
from gate.web.routes_sso import sso_routes

# Environment variable through which `serve` hands its --config-source list
# to worker processes; each worker loads the configuration itself.
CONFIG_SOURCES_ENV: Final = "GATE_CONFIG_SOURCES"
PURGE_INTERVAL_ENV: Final = "GATE_PURGE_INTERVAL"
_PURGE_GRACE: Final = timedelta(hours=24)


def install_error_handlers(app: FastAPI) -> None:
    """Every error leaves as application/problem+json."""

    async def on_domain_error(_: Request, e: Exception) -> Response:
        assert isinstance(e, DomainError)
        return from_domain_error(e)

    async def on_problem(_: Request, e: Exception) -> Response:
        assert isinstance(e, ProblemError)
        return from_problem_error(e)

    async def on_validation(_: Request, e: Exception) -> Response:
        assert isinstance(e, RequestValidationError)
        return problem(400, "invalid_request", describe_validation(e.errors()))

    async def on_http(_: Request, e: Exception) -> Response:
        assert isinstance(e, HTTPException)
        match e.status_code:
            case 404:
                return problem(404, "not_found", "route not found")
            case 405:
                return problem(405, "method_not_allowed", "method not allowed", e.headers)
            case 413:
                return problem(413, "invalid_request", "invalid JSON body: body too large")
            case 400:
                return problem(400, "invalid_request", "invalid JSON body")
            case status:
                return problem(status, "http_error", str(e.detail))

    app.add_exception_handler(DomainError, on_domain_error)
    app.add_exception_handler(ProblemError, on_problem)
    app.add_exception_handler(RequestValidationError, on_validation)
    app.add_exception_handler(HTTPException, on_http)


async def _purge_loop(c: Container, every: timedelta) -> None:
    """Deletes sessions that ended more than a day ago. Idempotent, so safe
    on every worker; a random start offset spreads workers apart. At scale,
    prefer ``maintenance purge-sessions`` on a schedule."""
    await asyncio.sleep(random.uniform(0, every.total_seconds()))
    while True:
        try:
            n = await c.auth.purge_sessions(datetime.now(UTC) - _PURGE_GRACE)
            if n:
                c.log.info("purged ended sessions", rows=n)
        except Exception as e:
            c.log.warning("purge sessions failed", error=repr(e))
        await asyncio.sleep(every.total_seconds())


def create_app(c: Container, *, purge_every: timedelta | None = timedelta(hours=1)) -> FastAPI:
    cfg = c.config

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
        await c.start()
        purger = asyncio.create_task(_purge_loop(c, purge_every)) if purge_every else None
        c.log.info("worker ready", pid=os.getpid())
        try:
            yield
        finally:
            if purger:
                purger.cancel()
            await c.stop()

    middleware = [
        Middleware(
            GateMiddleware,
            log=c.log,
            max_body_bytes=cfg.http.max_body_bytes,
            trusted=cfg.http.trusted_networks,
        )
    ]
    if cfg.http.cors_allowed_origins:
        middleware.append(
            Middleware(
                CORSMiddleware,
                allow_origins=list(cfg.http.cors_allowed_origins),
                allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
                expose_headers=["X-Request-ID", "Retry-After"],
                max_age=12 * 3600,
                # Bearer tokens, not cookies: credentials mode is not needed.
                allow_credentials=False,
            )
        )
    dev = cfg.app.env == "development"
    app = FastAPI(
        title="rbac-service",
        lifespan=lifespan,
        middleware=middleware,
        # API docs only in development; production exposes no schema.
        docs_url="/docs" if dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if dev else None,
    )
    install_error_handlers(app)

    # Operational endpoints.
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> Response:
        try:
            await c.db.ping()
        except Exception:
            return problem(503, "not_ready", "database unavailable")
        return JSONResponse({"status": "ok"})

    authn = make_authenticate(c.auth)
    limiter = rate_limit(IPRateLimiter(cfg.auth.rate_limit_per_minute, cfg.auth.rate_limit_burst))

    app.include_router(jwks_route(c.keys))
    # Unauthenticated.
    app.include_router(
        auth_routes(auth=c.auth, limiter=limiter, registration_enabled=cfg.auth.public_registration_enabled)
    )
    sso = sso_routes(
        registry=c.sso_registry,
        state_key=cfg.auth.sso_state_key.reveal().encode(),
        sign_in=c.sso,
        limiter=limiter,
        log=c.log,
    )
    if sso is not None:
        app.include_router(sso)
    # Any signed-in user.
    app.include_router(me_routes(authn=authn, auth=c.auth, users=c.users))
    # Public application API: only public users. Add the application's
    # routes to this router; restrict by type with require_public_type(authn,
    # "vendor") and, if the business needs it, by permission.
    public_app = APIRouter(
        prefix="/v1/app", dependencies=[Depends(authn), Depends(require_kind(authn, UserKind.PUBLIC))]
    )
    app.include_router(public_app)
    # Internal (staff) API: only internal users, each route permission-gated.
    app.include_router(admin_routes(authn=authn, users=c.users, roles=c.roles, audit=c.auditor))
    return app


def from_environment() -> FastAPI:
    """Uvicorn application factory for worker processes. Each worker loads
    the configuration from the sources ``serve`` was given."""
    specs = json.loads(os.environ.get(CONFIG_SOURCES_ENV, '["env"]'))
    sources = [config.parse_source(s) for s in specs]
    # The factory is called inside uvicorn's running event loop, so the async
    # loader runs on a helper thread with its own loop.
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        cfg = pool.submit(asyncio.run, config.load(sources)).result()
    log = logs.configure(cfg.log)
    purge = config.parse_duration(os.environ.get(PURGE_INTERVAL_ENV, "1h"))
    return create_app(Container.build(cfg, log), purge_every=purge if purge > timedelta(0) else None)
